use std::path::Path;

use anyhow::Result;

use super::{MatchInputFormat, MatchInputTarget, MatchOptions};
use crate::input::{DetectedInput, detect_path};
use crate::rules::{BehaviorMode, InputBehaviorMode};
use crate::{InputFormat, RuleTarget};

pub(super) fn detect_match_file_input(path: &Path, options: MatchOptions) -> Result<DetectedInput> {
    if let (Some(target), Some(format)) = (
        rule_input_target(options.input_target),
        rule_input_format(options.input_format),
    ) {
        return Ok(DetectedInput {
            target,
            format,
            behavior: input_behavior_to_output_mode(options.input_behavior),
        });
    }
    detect_path(path).map(|detected| apply_match_options(detected, options))
}

pub(super) fn apply_match_options(
    mut detected: DetectedInput,
    options: MatchOptions,
) -> DetectedInput {
    if let Some(target) = rule_input_target(options.input_target) {
        detected.target = target;
    }
    if let Some(format) = rule_input_format(options.input_format) {
        detected.format = format;
    }
    if options.input_behavior != InputBehaviorMode::Auto {
        detected.behavior = input_behavior_to_output_mode(options.input_behavior);
    }
    detected
}

pub(super) fn rule_input_target(target: Option<MatchInputTarget>) -> Option<RuleTarget> {
    match target {
        Some(MatchInputTarget::Rule(target)) => target,
        _ => None,
    }
}

pub(super) fn rule_input_format(format: Option<MatchInputFormat>) -> Option<InputFormat> {
    match format {
        Some(MatchInputFormat::Rule(format)) => format,
        _ => None,
    }
}

pub(super) fn input_behavior_to_output_mode(behavior: InputBehaviorMode) -> BehaviorMode {
    match behavior {
        InputBehaviorMode::Auto => BehaviorMode::Auto,
        InputBehaviorMode::Domain => BehaviorMode::Domain,
        InputBehaviorMode::Ipcidr => BehaviorMode::Ipcidr,
        InputBehaviorMode::Classical => BehaviorMode::Classical,
    }
}
