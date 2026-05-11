use anyhow::Result;

use crate::codec::generic;
use crate::codec::mihomo::mrs::{Behavior, RuleSetOutput};
use crate::output::OutputFormat;
use crate::rules::BehaviorMode;

use super::common::{MemoryOutput, estimate_rule_sets_bytes, memory_output};

pub(super) fn write_general_rule_sets_to_memory(
    outputs: &[RuleSetOutput],
    behavior: BehaviorMode,
    format: OutputFormat,
) -> Result<Vec<MemoryOutput>> {
    let mut bytes = Vec::with_capacity(estimate_rule_sets_bytes(outputs, format));
    let mut count = 0usize;
    for rule_set in outputs {
        if should_write_general_rule_set(rule_set, behavior, format) {
            write_general_rule_set(&mut bytes, rule_set, format)?;
            count += rule_set.count();
        }
    }
    if count == 0 {
        anyhow::bail!("no supported rules found for the requested conversion");
    }
    Ok(vec![memory_output(
        behavior_to_output_behavior(behavior),
        format,
        count,
        bytes,
    )])
}

fn behavior_to_output_behavior(behavior: BehaviorMode) -> Behavior {
    match behavior {
        BehaviorMode::Ipcidr => Behavior::Ipcidr,
        BehaviorMode::Auto | BehaviorMode::Domain | BehaviorMode::Classical => Behavior::Domain,
    }
}

fn write_general_rule_set(
    bytes: &mut Vec<u8>,
    rule_set: &RuleSetOutput,
    format: OutputFormat,
) -> Result<()> {
    if matches!(format, OutputFormat::DomainSet | OutputFormat::Adguard)
        && matches!(rule_set, RuleSetOutput::Domain(_))
    {
        let writer = if format == OutputFormat::Adguard {
            generic::text::write_adguard_domain_rule
        } else {
            generic::text::write_domain_set_rule
        };
        return rule_set
            .for_each_rule(|rule| writer(bytes, rule))
            .map_err(Into::into);
    }

    if format == OutputFormat::IpSet && matches!(rule_set, RuleSetOutput::Ipcidr(_)) {
        return rule_set
            .for_each_rule(|rule| generic::text::write_plain_rule(bytes, rule))
            .map_err(Into::into);
    }

    rule_set
        .for_each_rule(|rule| generic::text::write_typed_rule(bytes, rule_set.behavior(), rule))
        .map_err(Into::into)
}

fn should_write_general_rule_set(
    rule_set: &RuleSetOutput,
    behavior: BehaviorMode,
    format: OutputFormat,
) -> bool {
    match format {
        OutputFormat::DomainSet | OutputFormat::Adguard => {
            matches!(rule_set, RuleSetOutput::Domain(_))
        }
        OutputFormat::IpSet => matches!(rule_set, RuleSetOutput::Ipcidr(_)),
        OutputFormat::RuleSet => match behavior {
            BehaviorMode::Domain => matches!(rule_set, RuleSetOutput::Domain(_)),
            BehaviorMode::Ipcidr => matches!(rule_set, RuleSetOutput::Ipcidr(_)),
            BehaviorMode::Auto | BehaviorMode::Classical => true,
        },
        _ => true,
    }
}
