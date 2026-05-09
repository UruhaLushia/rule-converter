use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use crate::codec::mihomo::mrs::{Behavior, read_mrs_stream};
use crate::input::{
    DetectedInput, InputSource, detect_path, detect_payload, expand_file_paths, for_each_rule,
};
use crate::rules::{BehaviorMode, InputBehaviorMode};
use crate::{FileInput, InputFormat, RuleTarget};

mod config;
mod provider;
mod rule;
mod state;

use config::{match_mihomo_config_path, match_mihomo_config_payload};
use state::MatchState;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchOptions {
    pub input_target: Option<RuleTarget>,
    pub input_format: Option<InputFormat>,
    pub input_behavior: InputBehaviorMode,
}

impl Default for MatchOptions {
    fn default() -> Self {
        Self {
            input_target: None,
            input_format: None,
            input_behavior: InputBehaviorMode::Auto,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchQueryKind {
    Domain,
    Ip,
}

impl MatchQueryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Ip => "ip",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MatchedRule {
    #[serde(serialize_with = "serialize_behavior")]
    pub behavior: Behavior,
    pub rule: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MatchResult {
    pub matched: bool,
    pub query: String,
    pub kind: MatchQueryKind,
    pub rules: Vec<MatchedRule>,
}

pub fn match_payload(
    payload: impl AsRef<[u8]>,
    query: &str,
    options: MatchOptions,
) -> Result<MatchResult> {
    let payload = payload.as_ref();
    let detected = apply_match_options(detect_payload(payload)?, options);
    if detected.target == RuleTarget::Mihomo
        && detected.format == InputFormat::Yaml
        && let Some(result) = match_mihomo_config_payload(payload, query)?
    {
        return Ok(result);
    }
    let mut state = MatchState::new(query);
    if detected.target == RuleTarget::Mihomo && detected.format == InputFormat::Mrs {
        let rule_set = crate::codec::mihomo::mrs::read_mrs(payload)?;
        let count = state.push_mrs_rule_set(&rule_set);
        if count == 0 {
            anyhow::bail!("input does not contain any rules in `rules` or `payload`");
        }
        return Ok(state.finish());
    }
    let count = for_each_rule(
        InputSource::Payload(payload),
        detected.target,
        detected.format,
        |rule| state.push_rule(rule, detected),
    )?;
    if count == 0 {
        anyhow::bail!("input does not contain any rules in `rules` or `payload`");
    }
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
            target: options.input_target,
            format: options.input_format,
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
            target: options.input_target,
            format: options.input_format,
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
        let expanded = expand_file_paths([input.path])?;
        for path in expanded {
            let item_options = MatchOptions {
                input_target: input.target.or(options.input_target),
                input_format: input.format.or(options.input_format),
                input_behavior: if input.behavior == InputBehaviorMode::Auto {
                    options.input_behavior
                } else {
                    input.behavior
                },
            };
            let detected = detect_match_file_input(&path, item_options)?;
            if detected.target == RuleTarget::Mihomo
                && detected.format == InputFormat::Yaml
                && let Some(result) = match_mihomo_config_path(&path, &mut state)?
            {
                total += result;
                continue;
            }
            if detected.target == RuleTarget::Mihomo && detected.format == InputFormat::Mrs {
                let file = File::open(&path).map(BufReader::new).map_err(|err| {
                    anyhow::anyhow!("failed to read input {}: {err}", path.display())
                })?;
                let rule_set = read_mrs_stream(file)?;
                total += state.push_mrs_rule_set(&rule_set);
                continue;
            }
            total += for_each_rule(
                InputSource::FilePath(&path),
                detected.target,
                detected.format,
                |rule| state.push_rule(rule, detected),
            )?;
        }
    }
    if total == 0 {
        anyhow::bail!("input does not contain any rules in `rules` or `payload`");
    }
    Ok(state.finish())
}

fn detect_match_file_input(path: &Path, options: MatchOptions) -> Result<DetectedInput> {
    if let (Some(target), Some(format)) = (options.input_target, options.input_format) {
        return Ok(DetectedInput {
            target,
            format,
            behavior: input_behavior_to_output_mode(options.input_behavior),
        });
    }
    detect_path(path).map(|detected| apply_match_options(detected, options))
}

fn apply_match_options(mut detected: DetectedInput, options: MatchOptions) -> DetectedInput {
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

fn input_behavior_to_output_mode(behavior: InputBehaviorMode) -> BehaviorMode {
    match behavior {
        InputBehaviorMode::Auto => BehaviorMode::Auto,
        InputBehaviorMode::Domain => BehaviorMode::Domain,
        InputBehaviorMode::Ipcidr => BehaviorMode::Ipcidr,
        InputBehaviorMode::Classical => BehaviorMode::Classical,
    }
}

fn serialize_behavior<S>(behavior: &Behavior, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(behavior.as_str())
}
