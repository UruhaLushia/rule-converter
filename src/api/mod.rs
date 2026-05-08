use std::path::Path;

use anyhow::{Result, bail};

use crate::RuleTarget;
use crate::codec::sing_box::RuleStore;
use crate::input::{
    DetectedInput, InputFormat, InputSource, detect_path, detect_payload, expand_file_paths,
    for_each_rule,
};
use crate::output::{
    MemoryOutput, OutputFile, OutputFormat, OutputTarget, RuleSetOutput,
    write_owned_sing_box_rule_set, write_owned_sing_box_rule_set_to_memory, write_rule_sets,
    write_rule_sets_to_memory,
};
use crate::rules::{BehaviorMode, Converter, InputBehaviorMode, RuleTextStore};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConvertOptions {
    pub input_target: Option<RuleTarget>,
    pub input_format: Option<InputFormat>,
    pub input_behavior: InputBehaviorMode,
    pub output_target: RuleTarget,
    pub output_format: OutputFormat,
    pub output_behavior: BehaviorMode,
}

impl Default for ConvertOptions {
    fn default() -> Self {
        Self {
            input_target: None,
            input_format: None,
            input_behavior: InputBehaviorMode::Auto,
            output_target: RuleTarget::Mihomo,
            output_format: OutputFormat::Mrs,
            output_behavior: BehaviorMode::Domain,
        }
    }
}

pub struct ConvertResult {
    pub outputs: Vec<RuleSetOutput>,
    pub mixed_rules: RuleTextStore,
    pub sing_box_rules: Option<RuleStore>,
    pub output_behavior: BehaviorMode,
    pub no_resolve: bool,
    pub skipped: Vec<SkippedRule>,
}

impl ConvertResult {
    pub fn is_empty(&self) -> bool {
        self.outputs.is_empty()
            && self.mixed_rules.is_empty()
            && self.sing_box_rules.as_ref().is_none_or(RuleStore::is_empty)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkippedRule {
    pub rule: String,
    pub reason: String,
}

impl SkippedRule {
    pub fn new(rule: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            rule: rule.into(),
            reason: reason.into(),
        }
    }
}

pub fn convert_payload(
    payload: impl AsRef<[u8]>,
    options: ConvertOptions,
) -> Result<ConvertResult> {
    let payload = payload.as_ref();
    let detected = apply_input_options(detect_payload(payload)?, options);
    let output_behavior = options.output_behavior;
    let converter =
        converter_for_options(effective_input_behavior(detected), detected.target, options);
    let mut builder = converter.builder_with_options(
        should_keep_mixed_rules(options, effective_input_behavior(detected)),
        should_build_rule_sets(options, effective_input_behavior(detected)),
        should_keep_domain_set_lines(options),
        should_keep_ip_set_lines(options),
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
    let paths = expand_file_paths(paths)?;
    let detected = detect_file_inputs(&paths, options)?;
    let output_behavior = options.output_behavior;
    let input_behavior = merge_input_behavior(detected.iter().copied());
    let input_target = merge_input_target(detected.iter().copied());
    let converter = converter_for_options(input_behavior, input_target, options);
    let mut builder = converter.builder_with_options(
        should_keep_mixed_rules(options, input_behavior),
        should_build_rule_sets(options, input_behavior),
        should_keep_domain_set_lines(options),
        should_keep_ip_set_lines(options),
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

fn detect_file_inputs(
    paths: &[std::path::PathBuf],
    options: ConvertOptions,
) -> Result<Vec<DetectedInput>> {
    if let (Some(target), Some(format)) = (options.input_target, options.input_format) {
        let behavior = input_behavior_to_output_mode(options.input_behavior);
        return Ok(vec![
            DetectedInput {
                target,
                format,
                behavior,
            };
            paths.len()
        ]);
    }

    paths
        .iter()
        .map(|path| detect_path(path).map(|detected| apply_input_options(detected, options)))
        .collect::<Result<Vec<_>>>()
}

fn apply_input_options(mut detected: DetectedInput, options: ConvertOptions) -> DetectedInput {
    if let Some(target) = options.input_target {
        detected.target = target;
    }
    if let Some(format) = options.input_format {
        detected.format = format;
    }
    if options.input_behavior != InputBehaviorMode::Auto {
        detected.behavior = input_behavior_to_output_mode(options.input_behavior);
    }
    detected
}

fn merge_input_behavior(detected: impl IntoIterator<Item = DetectedInput>) -> InputBehaviorMode {
    let mut behavior = InputBehaviorMode::Auto;
    for item in detected {
        let item_behavior = effective_input_behavior(item);
        if item_behavior == InputBehaviorMode::Auto {
            return InputBehaviorMode::Auto;
        }
        if behavior == InputBehaviorMode::Auto {
            behavior = item_behavior;
        } else if behavior != item_behavior {
            return InputBehaviorMode::Auto;
        }
    }
    behavior
}

fn merge_input_target(detected: impl IntoIterator<Item = DetectedInput>) -> RuleTarget {
    let mut target = None;
    for item in detected {
        match target {
            None => target = Some(item.target),
            Some(current) if current == item.target => {}
            Some(_) => return RuleTarget::General,
        }
    }
    target.unwrap_or(RuleTarget::Mihomo)
}

fn effective_input_behavior(detected: DetectedInput) -> InputBehaviorMode {
    match detected.behavior {
        BehaviorMode::Auto => InputBehaviorMode::Auto,
        BehaviorMode::Domain => InputBehaviorMode::Domain,
        BehaviorMode::Ipcidr => InputBehaviorMode::Ipcidr,
        BehaviorMode::Classical => InputBehaviorMode::Classical,
    }
}

fn input_behavior_to_output_mode(behavior: InputBehaviorMode) -> BehaviorMode {
    match behavior {
        InputBehaviorMode::Auto => BehaviorMode::Auto,
        InputBehaviorMode::Domain => BehaviorMode::Domain,
        InputBehaviorMode::Ipcidr => BehaviorMode::Ipcidr,
        InputBehaviorMode::Classical => BehaviorMode::Classical,
    }
}

fn should_build_rule_sets(options: ConvertOptions, _input_behavior: InputBehaviorMode) -> bool {
    match (options.output_target, options.output_format) {
        (
            RuleTarget::General,
            OutputFormat::DomainSet | OutputFormat::RuleSet | OutputFormat::IpSet,
        ) => false,
        (RuleTarget::Mihomo, OutputFormat::Text | OutputFormat::Yaml) => {
            options.output_behavior != BehaviorMode::Classical
        }
        _ => true,
    }
}

fn should_keep_domain_set_lines(options: ConvertOptions) -> bool {
    options.output_target == RuleTarget::General && options.output_format == OutputFormat::DomainSet
}

fn should_keep_ip_set_lines(options: ConvertOptions) -> bool {
    options.output_target == RuleTarget::General && options.output_format == OutputFormat::IpSet
}

fn should_keep_mixed_rules(options: ConvertOptions, input_behavior: InputBehaviorMode) -> bool {
    match (options.output_target, options.output_format) {
        (RuleTarget::Mihomo, OutputFormat::Text | OutputFormat::Yaml) => {
            options.output_behavior == BehaviorMode::Classical
        }
        (RuleTarget::General, OutputFormat::RuleSet) => true,
        (RuleTarget::General, OutputFormat::DomainSet | OutputFormat::IpSet) => true,
        _ => {
            options.output_behavior == BehaviorMode::Classical
                && input_behavior == InputBehaviorMode::Classical
        }
    }
}

fn converter_for_options(
    input_behavior: InputBehaviorMode,
    input_target: RuleTarget,
    options: ConvertOptions,
) -> Converter {
    if options.output_target == RuleTarget::SingBox
        && matches!(
            options.output_format,
            OutputFormat::Json | OutputFormat::Srs
        )
    {
        return Converter::for_sing_box_output(
            input_behavior,
            input_target,
            options.output_behavior,
        );
    }

    Converter::with_input_context(input_behavior, input_target, options.output_behavior)
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

pub fn write_outputs(result: &ConvertResult, output: impl AsRef<Path>) -> Result<Vec<OutputFile>> {
    write_outputs_as(result, output, RuleTarget::Mihomo, OutputFormat::Mrs)
}

pub fn write_outputs_owned(
    result: ConvertResult,
    output: impl AsRef<Path>,
) -> Result<(Vec<OutputFile>, Vec<SkippedRule>)> {
    write_outputs_as_owned(result, output, RuleTarget::Mihomo, OutputFormat::Mrs)
}

pub fn write_outputs_as(
    result: &ConvertResult,
    output: impl AsRef<Path>,
    target: RuleTarget,
    format: OutputFormat,
) -> Result<Vec<OutputFile>> {
    write_rule_sets(
        &result.outputs,
        &result.mixed_rules,
        result.sing_box_rules.as_ref(),
        OutputTarget::FilePath(output.as_ref()),
        target,
        format,
        result.output_behavior,
        result.no_resolve,
    )
}

pub fn write_outputs_as_owned(
    result: ConvertResult,
    output: impl AsRef<Path>,
    target: RuleTarget,
    format: OutputFormat,
) -> Result<(Vec<OutputFile>, Vec<SkippedRule>)> {
    let skipped = result.skipped;
    let no_resolve = result.no_resolve;
    let output_behavior = result.output_behavior;
    if target == RuleTarget::SingBox
        && matches!(format, OutputFormat::Json | OutputFormat::Srs)
        && let Some(sing_box_rules) = result.sing_box_rules
    {
        let files = write_owned_sing_box_rule_set(
            sing_box_rules,
            OutputTarget::FilePath(output.as_ref()),
            format,
            output_behavior,
        )?;
        return Ok((files, skipped));
    }

    let files = write_rule_sets(
        &result.outputs,
        &result.mixed_rules,
        result.sing_box_rules.as_ref(),
        OutputTarget::FilePath(output.as_ref()),
        target,
        format,
        output_behavior,
        no_resolve,
    )?;
    Ok((files, skipped))
}

pub fn write_outputs_to_memory(
    result: &ConvertResult,
    target: RuleTarget,
    format: OutputFormat,
) -> Result<Vec<MemoryOutput>> {
    write_rule_sets_to_memory(
        &result.outputs,
        &result.mixed_rules,
        result.sing_box_rules.as_ref(),
        target,
        format,
        result.output_behavior,
        result.no_resolve,
    )
}

pub fn write_outputs_to_memory_owned(
    result: ConvertResult,
) -> Result<(Vec<MemoryOutput>, Vec<SkippedRule>)> {
    write_outputs_as_to_memory_owned(result, RuleTarget::Mihomo, OutputFormat::Mrs)
}

pub fn write_outputs_as_to_memory_owned(
    result: ConvertResult,
    target: RuleTarget,
    format: OutputFormat,
) -> Result<(Vec<MemoryOutput>, Vec<SkippedRule>)> {
    let skipped = result.skipped;
    let no_resolve = result.no_resolve;
    let output_behavior = result.output_behavior;
    if target == RuleTarget::SingBox
        && matches!(format, OutputFormat::Json | OutputFormat::Srs)
        && let Some(sing_box_rules) = result.sing_box_rules
    {
        let outputs =
            write_owned_sing_box_rule_set_to_memory(sing_box_rules, format, output_behavior)?;
        return Ok((outputs, skipped));
    }

    let outputs = write_rule_sets_to_memory(
        &result.outputs,
        &result.mixed_rules,
        result.sing_box_rules.as_ref(),
        target,
        format,
        output_behavior,
        no_resolve,
    )?;
    Ok((outputs, skipped))
}
