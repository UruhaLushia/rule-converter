use std::path::Path;

use anyhow::{Result, bail};

use super::fast_path::{
    convert_single_mrs_file_fast_path, estimate_file_input_bytes, estimate_rule_bytes,
    estimate_rule_count,
};
use super::input_plan::{
    apply_input_options, converter_for_options, detect_configured_file_inputs,
    effective_input_behavior, merge_input_behavior, merge_input_target, should_build_rule_sets,
    should_keep_domain_set_lines, should_keep_ip_set_lines, should_keep_mixed_rules,
};
use super::options::{normalize_options, options_with_output_behavior, resolve_output_behavior};
use super::stream::{can_stream_text_to_path, stream_text_to_path};
use super::types::{ConvertOptions, ConvertResult, FileInput, SkippedRule};
use crate::input::{InputSource, detect_payload, for_each_rule};
use crate::output::{OutputFile, RuleSetOutput};
use crate::rules::{BehaviorMode, Converter, RuleTextStore};

pub fn convert_payload(
    payload: impl AsRef<[u8]>,
    options: ConvertOptions,
) -> Result<ConvertResult> {
    let options = normalize_options(options);
    let payload = payload.as_ref();
    let detected = apply_input_options(detect_payload(payload)?, options);
    let input_behavior = effective_input_behavior(detected);
    let output_behavior = resolve_output_behavior(options, input_behavior)?;
    let options = options_with_output_behavior(options, output_behavior);
    let converter = converter_for_options(input_behavior, detected.target, options);
    let mut builder = converter.builder_with_options(
        should_keep_mixed_rules(options, input_behavior),
        should_build_rule_sets(options, input_behavior),
        should_keep_domain_set_lines(options),
        should_keep_ip_set_lines(options),
    );
    builder.reserve(
        estimate_rule_count(payload.len()),
        estimate_rule_bytes(payload.len()),
    );
    let count = for_each_rule(
        InputSource::Payload(payload),
        detected.target,
        detected.format,
        |rule| builder.push(rule),
    )?;
    if count == 0 {
        bail!("input does not contain any rules in `rules` or `payload`");
    }
    let mut result = builder.finish()?;
    result.output_behavior = output_behavior;
    if result.is_empty() {
        bail!("no supported rules found for the requested conversion");
    }
    Ok(result)
}

pub fn convert_file(path: impl AsRef<Path>, options: ConvertOptions) -> Result<ConvertResult> {
    convert_files([path], options)
}

pub fn convert_files<P, I>(paths: I, options: ConvertOptions) -> Result<ConvertResult>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = P>,
{
    let inputs = paths
        .into_iter()
        .map(|path| FileInput::path(path.as_ref()))
        .collect::<Vec<_>>();
    convert_file_inputs(inputs, options)
}

pub fn convert_file_inputs<I>(inputs: I, options: ConvertOptions) -> Result<ConvertResult>
where
    I: IntoIterator<Item = FileInput>,
{
    let options = normalize_options(options);
    let (paths, detected) = detect_configured_file_inputs(inputs, options)?;
    if let Some(result) = convert_single_mrs_file_fast_path(&paths, &detected, options)? {
        return Ok(result);
    }
    let input_behavior = merge_input_behavior(detected.iter().copied());
    let output_behavior = resolve_output_behavior(options, input_behavior)?;
    let options = options_with_output_behavior(options, output_behavior);
    let input_target = merge_input_target(detected.iter().copied());
    let converter = converter_for_options(input_behavior, input_target, options);
    let mut builder = converter.builder_with_options(
        should_keep_mixed_rules(options, input_behavior),
        should_build_rule_sets(options, input_behavior),
        should_keep_domain_set_lines(options),
        should_keep_ip_set_lines(options),
    );
    let input_bytes = estimate_file_input_bytes(&paths);
    builder.reserve(
        estimate_rule_count(input_bytes),
        estimate_rule_bytes(input_bytes),
    );
    let mut count = 0usize;
    for (path, detected) in paths.iter().zip(detected.iter().copied()) {
        count += for_each_rule(
            InputSource::FilePath(path),
            detected.target,
            detected.format,
            |rule| builder.push(rule),
        )?;
    }
    if count == 0 {
        bail!("input does not contain any rules in `rules` or `payload`");
    }
    let mut result = builder.finish()?;
    result.output_behavior = output_behavior;
    if result.is_empty() {
        bail!("no supported rules found for the requested conversion");
    }
    Ok(result)
}

pub fn convert_files_to_path_streaming<P, I>(
    paths: I,
    output: impl AsRef<Path>,
    options: ConvertOptions,
) -> Result<Option<(Vec<OutputFile>, Vec<SkippedRule>)>>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = P>,
{
    let inputs = paths
        .into_iter()
        .map(|path| FileInput::path(path.as_ref()))
        .collect::<Vec<_>>();
    convert_file_inputs_to_path_streaming(inputs, output, options)
}

pub fn convert_file_inputs_to_path_streaming<I>(
    inputs: I,
    output: impl AsRef<Path>,
    options: ConvertOptions,
) -> Result<Option<(Vec<OutputFile>, Vec<SkippedRule>)>>
where
    I: IntoIterator<Item = FileInput>,
{
    let options = normalize_options(options);
    let (paths, detected) = detect_configured_file_inputs(inputs, options)?;
    let input_behavior = merge_input_behavior(detected.iter().copied());
    let output_behavior = resolve_output_behavior(options, input_behavior)?;
    let options = options_with_output_behavior(options, output_behavior);

    if !can_stream_text_to_path(options) {
        return Ok(None);
    }

    stream_text_to_path(&paths, &detected, output.as_ref(), options).map(Some)
}

pub fn convert_rules(rules: &[String], behavior: BehaviorMode) -> Result<ConvertResult> {
    if rules.is_empty() {
        bail!("input does not contain any rules in `rules` or `payload`");
    }

    let result = Converter::new(behavior).convert(rules)?;
    if result.is_empty() {
        bail!("no supported rules found for the requested conversion");
    }
    Ok(result)
}

pub fn convert_rule_set_output(
    rule_set: RuleSetOutput,
    output_behavior: BehaviorMode,
) -> ConvertResult {
    ConvertResult {
        outputs: vec![rule_set],
        mixed_rules: RuleTextStore::default(),
        sing_box_rules: None,
        output_behavior,
        no_resolve: false,
        skipped: Vec::new(),
    }
}
