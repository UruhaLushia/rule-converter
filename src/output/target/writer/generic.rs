use std::fs;
use std::io::BufWriter;
use std::path::Path;

use anyhow::{Result, bail};

use crate::BehaviorMode;
use crate::RuleTarget;
use crate::codec::generic;
use crate::codec::mihomo::mrs::{Behavior, RuleSetOutput};
use crate::output::OutputFormat;
use crate::output::target::resolve_output_path_for_target;

use super::common::{OutputFile, create_output_writer, output_file};

pub(super) fn write_generic_text_to_path(
    outputs: &[RuleSetOutput],
    base: &Path,
    behavior: BehaviorMode,
    format: OutputFormat,
) -> Result<Vec<OutputFile>> {
    let output_behavior = behavior_to_output_behavior(behavior);
    let path =
        resolve_output_path_for_target(base, output_behavior, false, format, RuleTarget::General);

    let count = outputs
        .iter()
        .filter(|rule_set| should_write_general_rule_set(rule_set, behavior, format))
        .map(RuleSetOutput::count)
        .sum::<usize>();
    if count == 0 {
        bail!("no supported rules found for the requested conversion");
    }

    let mut file = create_output_writer(&path)?;
    for rule_set in outputs {
        if should_write_general_rule_set(rule_set, behavior, format) {
            write_generic_text(&mut file, rule_set, format)?;
        }
    }

    Ok(outputs
        .iter()
        .filter(|rule_set| should_write_general_rule_set(rule_set, behavior, format))
        .map(|rule_set| output_file(rule_set.behavior(), format, rule_set.count(), path.clone()))
        .collect())
}

fn behavior_to_output_behavior(behavior: BehaviorMode) -> Behavior {
    match behavior {
        BehaviorMode::Ipcidr => Behavior::Ipcidr,
        BehaviorMode::Auto | BehaviorMode::Domain | BehaviorMode::Classical => Behavior::Domain,
    }
}

pub(super) fn write_generic_text(
    file: &mut BufWriter<fs::File>,
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
            .for_each_rule(|rule| writer(file, rule))
            .map_err(Into::into);
    }

    if format == OutputFormat::IpSet && matches!(rule_set, RuleSetOutput::Ipcidr(_)) {
        return rule_set
            .for_each_rule(|rule| generic::text::write_plain_rule(file, rule))
            .map_err(Into::into);
    }

    rule_set
        .for_each_rule(|rule| generic::text::write_typed_rule(file, rule_set.behavior(), rule))
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
