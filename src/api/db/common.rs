use anyhow::Result;

use super::super::{convert_rule_set_output, write_outputs_as_to_memory_owned};
use super::types::{DbMemoryOutput, DbStringOutput};
use crate::codec::mihomo::mrs::Behavior;
use crate::output::OutputFormat;
use crate::rules::BehaviorMode;
use crate::{ConvertResult, RuleSetOutput, RuleTarget};

pub(super) fn db_convert_result_to_memory(
    name: impl Into<String>,
    mut result: ConvertResult,
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<Vec<DbMemoryOutput>> {
    result.output_behavior = behavior;
    let (outputs, _) = write_outputs_as_to_memory_owned(result, target, format)?;
    let name = name.into();
    Ok(outputs
        .into_iter()
        .map(|output| DbMemoryOutput {
            name: name.clone(),
            behavior: output.behavior,
            format: output.format,
            count: output.count,
            bytes: output.bytes,
        })
        .collect())
}

pub(super) fn db_rule_set_to_memory(
    name: impl Into<String>,
    rule_set: RuleSetOutput,
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<Vec<DbMemoryOutput>> {
    let result = convert_rule_set_output(rule_set, behavior);
    let (outputs, _) = write_outputs_as_to_memory_owned(result, target, format)?;
    let name = name.into();
    Ok(outputs
        .into_iter()
        .map(|output| DbMemoryOutput {
            name: name.clone(),
            behavior: output.behavior,
            format: output.format,
            count: output.count,
            bytes: output.bytes,
        })
        .collect())
}

pub(super) fn normalize_db_output_behavior(
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> BehaviorMode {
    match (target, format, behavior) {
        (RuleTarget::General, OutputFormat::IpSet, _) => BehaviorMode::Ipcidr,
        (RuleTarget::General, OutputFormat::DomainSet, _) => BehaviorMode::Domain,
        (_, _, BehaviorMode::Auto) => BehaviorMode::Ipcidr,
        _ => behavior,
    }
}

pub(super) fn can_stream_ipset(
    split: bool,
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> bool {
    !split
        && target == RuleTarget::General
        && format == OutputFormat::IpSet
        && behavior == BehaviorMode::Ipcidr
}

pub(super) fn db_ipset_string_output(name: &str, count: usize, text: String) -> DbStringOutput {
    DbStringOutput {
        name: name.to_string(),
        behavior: Behavior::Ipcidr,
        format: OutputFormat::IpSet,
        count,
        text,
    }
}
