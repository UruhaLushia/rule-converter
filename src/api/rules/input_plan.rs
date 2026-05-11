use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use super::types::{ConvertOptions, FileInput};
use crate::RuleTarget;
use crate::input::{DetectedInput, InputFormat, detect_path, expand_file_paths};
use crate::output::OutputFormat;
use crate::rules::{BehaviorMode, Converter, InputBehaviorMode};

pub(super) fn detect_configured_file_inputs<I>(
    inputs: I,
    options: ConvertOptions,
) -> Result<(Vec<PathBuf>, Vec<DetectedInput>)>
where
    I: IntoIterator<Item = FileInput>,
{
    let mut paths = Vec::new();
    let mut detected = Vec::new();

    for input in inputs {
        let expanded = expand_file_paths([input.path])?;
        for path in expanded {
            let input_options = ConvertOptions {
                input_target: input.target.or(options.input_target),
                input_format: input.format.or(options.input_format),
                input_behavior: if input.behavior == InputBehaviorMode::Auto {
                    options.input_behavior
                } else {
                    input.behavior
                },
                ..options
            };
            let item_detected = detect_file_input(&path, input_options)?;
            paths.push(path);
            detected.push(item_detected);
        }
    }

    if paths.is_empty() {
        bail!("input path expansion did not match any files");
    }
    Ok((paths, detected))
}

pub(super) fn detect_file_input(path: &Path, options: ConvertOptions) -> Result<DetectedInput> {
    if let (Some(target), Some(format)) = (options.input_target, options.input_format) {
        let behavior = input_behavior_to_output_mode(options.input_behavior);
        if target == RuleTarget::Mihomo
            && format == InputFormat::Mrs
            && behavior == BehaviorMode::Auto
        {
            return detect_path(path).map(|detected| DetectedInput {
                target,
                format,
                behavior: detected.behavior,
            });
        }
        return Ok(DetectedInput {
            target,
            format,
            behavior,
        });
    }

    detect_path(path).map(|detected| apply_input_options(detected, options))
}

pub(super) fn apply_input_options(
    mut detected: DetectedInput,
    options: ConvertOptions,
) -> DetectedInput {
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

pub(super) fn merge_input_behavior(
    detected: impl IntoIterator<Item = DetectedInput>,
) -> InputBehaviorMode {
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

pub(super) fn merge_input_target(detected: impl IntoIterator<Item = DetectedInput>) -> RuleTarget {
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

pub(super) fn effective_input_behavior(detected: DetectedInput) -> InputBehaviorMode {
    match detected.behavior {
        BehaviorMode::Auto => InputBehaviorMode::Auto,
        BehaviorMode::Domain => InputBehaviorMode::Domain,
        BehaviorMode::Ipcidr => InputBehaviorMode::Ipcidr,
        BehaviorMode::Classical => InputBehaviorMode::Classical,
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

pub(super) fn should_build_rule_sets(
    options: ConvertOptions,
    _input_behavior: InputBehaviorMode,
) -> bool {
    match (options.output_target, options.output_format) {
        (RuleTarget::SingBox, OutputFormat::Json | OutputFormat::Srs) => false,
        (
            RuleTarget::General,
            OutputFormat::DomainSet | OutputFormat::Adguard | OutputFormat::IpSet,
        ) => true,
        (RuleTarget::General, OutputFormat::RuleSet) => false,
        (RuleTarget::Mihomo, OutputFormat::Text | OutputFormat::Yaml) => {
            options.output_behavior != BehaviorMode::Classical
        }
        _ => true,
    }
}

pub(super) fn should_keep_domain_set_lines(options: ConvertOptions) -> bool {
    options.output_target == RuleTarget::General
        && matches!(
            options.output_format,
            OutputFormat::DomainSet | OutputFormat::Adguard
        )
}

pub(super) fn should_keep_ip_set_lines(options: ConvertOptions) -> bool {
    options.output_target == RuleTarget::General && options.output_format == OutputFormat::IpSet
}

pub(super) fn should_keep_mixed_rules(
    options: ConvertOptions,
    input_behavior: InputBehaviorMode,
) -> bool {
    match (options.output_target, options.output_format) {
        (RuleTarget::Mihomo, OutputFormat::Text | OutputFormat::Yaml) => {
            options.output_behavior == BehaviorMode::Classical
        }
        (RuleTarget::General, OutputFormat::RuleSet) => true,
        (
            RuleTarget::General,
            OutputFormat::DomainSet | OutputFormat::Adguard | OutputFormat::IpSet,
        ) => false,
        (RuleTarget::Egern, OutputFormat::RuleSet) => false,
        _ => {
            options.output_behavior == BehaviorMode::Classical
                && input_behavior == InputBehaviorMode::Classical
        }
    }
}

pub(super) fn converter_for_options(
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
