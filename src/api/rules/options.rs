use anyhow::{Result, bail};

use super::types::ConvertOptions;
use crate::RuleTarget;
use crate::output::OutputFormat;
use crate::rules::{BehaviorMode, InputBehaviorMode};

pub fn default_output_behavior(
    output_target: RuleTarget,
    output_format: OutputFormat,
) -> BehaviorMode {
    match (output_target, output_format) {
        (RuleTarget::General, OutputFormat::IpSet) => BehaviorMode::Ipcidr,
        (RuleTarget::General, OutputFormat::DomainSet | OutputFormat::Adguard) => {
            BehaviorMode::Domain
        }
        (RuleTarget::Mihomo, OutputFormat::Mrs) => BehaviorMode::Auto,
        _ => BehaviorMode::Classical,
    }
}

pub(super) fn normalize_options(mut options: ConvertOptions) -> ConvertOptions {
    options.output_behavior = normalize_output_behavior(
        options.output_target,
        options.output_format,
        options.output_behavior,
    );
    options
}

pub(super) fn normalize_output_behavior(
    output_target: RuleTarget,
    output_format: OutputFormat,
    output_behavior: BehaviorMode,
) -> BehaviorMode {
    match (output_target, output_format) {
        (RuleTarget::General, OutputFormat::DomainSet | OutputFormat::Adguard) => {
            BehaviorMode::Domain
        }
        (RuleTarget::General, OutputFormat::IpSet) => BehaviorMode::Ipcidr,
        _ => output_behavior,
    }
}

pub(super) fn resolve_output_behavior(
    options: ConvertOptions,
    input_behavior: InputBehaviorMode,
) -> Result<BehaviorMode> {
    let behavior = normalize_output_behavior(
        options.output_target,
        options.output_format,
        options.output_behavior,
    );
    if behavior != BehaviorMode::Auto {
        return Ok(behavior);
    }

    match (options.output_target, options.output_format, input_behavior) {
        (
            RuleTarget::Mihomo,
            OutputFormat::Mrs | OutputFormat::Text | OutputFormat::Yaml,
            InputBehaviorMode::Domain,
        ) => Ok(BehaviorMode::Domain),
        (
            RuleTarget::Mihomo,
            OutputFormat::Mrs | OutputFormat::Text | OutputFormat::Yaml,
            InputBehaviorMode::Ipcidr,
        ) => Ok(BehaviorMode::Ipcidr),
        (RuleTarget::Mihomo, OutputFormat::Mrs, _) => bail!(
            "mihomo MRS output needs explicit output behavior for mixed/classical input; use domain or ip"
        ),
        _ => Ok(default_output_behavior(
            options.output_target,
            options.output_format,
        )),
    }
}

pub(super) fn options_with_output_behavior(
    mut options: ConvertOptions,
    output_behavior: BehaviorMode,
) -> ConvertOptions {
    options.output_behavior = output_behavior;
    options
}
