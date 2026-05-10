use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use anyhow::Result;

use crate::codec::mihomo::mrs::read_mrs_stream;
use crate::input::{InputSource, detect_payload, expand_file_paths, for_each_rule};
use crate::rules::InputBehaviorMode;
use crate::{FileInput, RuleTarget};

mod config;
mod db;
mod options;
mod provider;
mod rule;
mod state;
mod types;

pub use types::{
    MatchInputFormat, MatchInputTarget, MatchOptions, MatchQueryKind, MatchResult, MatchedRule,
};

use config::{match_mihomo_config_path, match_mihomo_config_payload};
use db::{match_db_file, match_db_payload};
use options::{apply_match_options, detect_match_file_input, rule_input_format, rule_input_target};
use state::MatchState;

pub fn match_payload(
    payload: impl AsRef<[u8]>,
    query: &str,
    options: MatchOptions,
) -> Result<MatchResult> {
    let payload = payload.as_ref();
    if let Some(result) = match_db_payload(payload, query, options)? {
        return Ok(result);
    }
    let detected = apply_match_options(detect_payload(payload)?, options);
    if detected.target == RuleTarget::Mihomo
        && detected.format == crate::InputFormat::Yaml
        && let Some(result) = match_mihomo_config_payload(payload, query)?
    {
        return Ok(result);
    }
    let mut state = MatchState::new(query);
    if detected.target == RuleTarget::Mihomo && detected.format == crate::InputFormat::Mrs {
        let rule_set = crate::codec::mihomo::mrs::read_mrs(payload)?;
        let count = state.push_mrs_rule_set(&rule_set);
        ensure_has_rules(count)?;
        return Ok(state.finish());
    }
    let count = for_each_rule(
        InputSource::Payload(payload),
        detected.target,
        detected.format,
        |rule| state.push_rule(rule, detected),
    )?;
    ensure_has_rules(count)?;
    Ok(state.finish())
}

pub fn match_file(
    path: impl AsRef<Path>,
    query: &str,
    options: MatchOptions,
) -> Result<MatchResult> {
    match_file_inputs(
        [FileInput {
            path: path.as_ref().to_path_buf(),
            target: rule_input_target(options.input_target),
            format: rule_input_format(options.input_format),
            behavior: options.input_behavior,
        }],
        query,
        options,
    )
}

pub fn match_files<P, I>(paths: I, query: &str, options: MatchOptions) -> Result<MatchResult>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = P>,
{
    let inputs = paths
        .into_iter()
        .map(|path| FileInput {
            path: path.as_ref().to_path_buf(),
            target: rule_input_target(options.input_target),
            format: rule_input_format(options.input_format),
            behavior: options.input_behavior,
        })
        .collect::<Vec<_>>();
    match_file_inputs(inputs, query, options)
}

pub fn match_file_inputs<I>(inputs: I, query: &str, options: MatchOptions) -> Result<MatchResult>
where
    I: IntoIterator<Item = FileInput>,
{
    let mut state = MatchState::new(query);
    let mut total = 0usize;
    for input in inputs {
        let item_options = input_options(&input, options);
        let expanded = expand_file_paths([input.path])?;
        for path in expanded {
            total += match_file_input(&path, item_options, &mut state)?;
        }
    }
    ensure_has_rules(total)?;
    Ok(state.finish())
}

fn input_options(input: &FileInput, options: MatchOptions) -> MatchOptions {
    MatchOptions {
        input_target: input
            .target
            .map(MatchInputTarget::from)
            .or(options.input_target),
        input_format: input
            .format
            .map(MatchInputFormat::from)
            .or(options.input_format),
        input_behavior: if input.behavior == InputBehaviorMode::Auto {
            options.input_behavior
        } else {
            input.behavior
        },
    }
}

fn match_file_input(path: &Path, options: MatchOptions, state: &mut MatchState) -> Result<usize> {
    if let Some(count) = match_db_file(path, options, state)? {
        return Ok(count);
    }
    let detected = detect_match_file_input(path, options)?;
    if detected.target == RuleTarget::Mihomo
        && detected.format == crate::InputFormat::Yaml
        && let Some(count) = match_mihomo_config_path(path, state)?
    {
        return Ok(count);
    }
    if detected.target == RuleTarget::Mihomo && detected.format == crate::InputFormat::Mrs {
        let file = File::open(path)
            .map(BufReader::new)
            .map_err(|err| anyhow::anyhow!("failed to read input {}: {err}", path.display()))?;
        let rule_set = read_mrs_stream(file)?;
        return Ok(state.push_mrs_rule_set(&rule_set));
    }
    for_each_rule(
        InputSource::FilePath(path),
        detected.target,
        detected.format,
        |rule| state.push_rule(rule, detected),
    )
}

fn ensure_has_rules(count: usize) -> Result<()> {
    if count == 0 {
        anyhow::bail!("input does not contain any rules in `rules` or `payload`");
    }
    Ok(())
}
