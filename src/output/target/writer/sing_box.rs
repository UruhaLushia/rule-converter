use std::path::Path;

use anyhow::{Result, bail};

use crate::codec::mihomo::mrs::{Behavior, RuleSetOutput};
use crate::codec::sing_box::RuleStore;
use crate::codec::{sing_box, sing_box::RuleSet};
use crate::output::OutputFormat;
use crate::rules::RuleTextStore;
use crate::{BehaviorMode, RuleTarget};

use super::common::{OutputFile, create_output_writer, output_file};
use crate::output::target::resolve_output_path_for_target;

pub(super) fn write_sing_box_to_path(
    outputs: &[RuleSetOutput],
    mixed_rules: &RuleTextStore,
    sing_box_rules: Option<&RuleStore>,
    base: &Path,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<Vec<OutputFile>> {
    let rule_set = sing_box_rules
        .map(|store| store.to_rule_set_with_behavior(behavior))
        .unwrap_or_else(|| RuleSet::from_outputs(outputs, mixed_rules, behavior));
    let output_behavior = rule_set_output_behavior(&rule_set, behavior);
    if rule_set.count() == 0 {
        bail!("no supported rules found for the requested conversion");
    }
    let path =
        resolve_output_path_for_target(base, output_behavior, false, format, RuleTarget::SingBox);
    let mut file = create_output_writer(&path)?;
    let count = match format {
        OutputFormat::Json => {
            let count = rule_set.count();
            sing_box::json::write_json(&mut file, &rule_set)?;
            count
        }
        OutputFormat::Srs => {
            let count = rule_set.count();
            sing_box::srs::write_srs(&mut file, &rule_set)?;
            count
        }
        _ => unreachable!("sing-box writer only handles JSON and SRS"),
    };

    if count == 0 {
        bail!("no supported rules found for the requested conversion");
    }

    Ok(vec![output_file(output_behavior, format, count, path)])
}

pub(super) fn write_owned_sing_box_to_path(
    sing_box_rules: RuleStore,
    base: &Path,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<Vec<OutputFile>> {
    if !matches!(format, OutputFormat::Json | OutputFormat::Srs) {
        bail!("sing-box owned writer only supports `json` and `srs` formats");
    }

    let output_behavior = rule_store_output_behavior(&sing_box_rules, behavior);
    let count = sing_box_rules.count();
    if count == 0 {
        bail!("no supported rules found for the requested conversion");
    }
    let path =
        resolve_output_path_for_target(base, output_behavior, false, format, RuleTarget::SingBox);
    let mut file = create_output_writer(&path)?;
    match format {
        OutputFormat::Json => sing_box::json::write_store_json(&mut file, &sing_box_rules)?,
        OutputFormat::Srs => {
            sing_box::srs::write_owned_store_srs(&mut file, sing_box_rules)?;
        }
        _ => unreachable!("format checked above"),
    };

    Ok(vec![output_file(output_behavior, format, count, path)])
}

fn rule_set_output_behavior(rule_set: &RuleSet, behavior: BehaviorMode) -> Behavior {
    match behavior {
        BehaviorMode::Ipcidr => Behavior::Ipcidr,
        BehaviorMode::Domain => Behavior::Domain,
        BehaviorMode::Auto | BehaviorMode::Classical => {
            if rule_set.has_ip_rules() && !rule_set.has_domain_rules() {
                Behavior::Ipcidr
            } else {
                Behavior::Domain
            }
        }
    }
}

fn rule_store_output_behavior(rule_store: &RuleStore, behavior: BehaviorMode) -> Behavior {
    match behavior {
        BehaviorMode::Ipcidr => Behavior::Ipcidr,
        BehaviorMode::Domain => Behavior::Domain,
        BehaviorMode::Auto | BehaviorMode::Classical => {
            if rule_store.has_ip_rules() && !rule_store.has_domain_rules() {
                Behavior::Ipcidr
            } else {
                Behavior::Domain
            }
        }
    }
}
