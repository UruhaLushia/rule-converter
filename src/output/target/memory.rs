use anyhow::{Result, bail};

use crate::codec::mihomo::mrs::{Behavior, RuleSetOutput};
use crate::codec::sing_box::RuleStore;
use crate::codec::{egern, generic, mihomo, sing_box};
use crate::rules::{BehaviorMode, RuleTextStore};
use crate::{OutputFormat, RuleTarget};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryOutput {
    pub behavior: Behavior,
    pub format: OutputFormat,
    pub count: usize,
    pub bytes: Vec<u8>,
}

pub fn write_rule_sets_to_memory(
    outputs: &[RuleSetOutput],
    mixed_rules: &RuleTextStore,
    sing_box_rules: Option<&RuleStore>,
    rule_target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
    no_resolve: bool,
) -> Result<Vec<MemoryOutput>> {
    validate_memory_output(rule_target, format, behavior)?;

    if rule_target == RuleTarget::SingBox {
        return write_sing_box_to_memory(outputs, mixed_rules, sing_box_rules, format, behavior);
    }

    if !mixed_rules.is_empty()
        && ((rule_target == RuleTarget::Mihomo
            && matches!(format, OutputFormat::Text | OutputFormat::Yaml)
            && behavior == BehaviorMode::Classical)
            || (rule_target == RuleTarget::General
                && matches!(
                    format,
                    OutputFormat::DomainSet | OutputFormat::RuleSet | OutputFormat::IpSet
                )))
    {
        return write_mixed_rules_to_memory(mixed_rules, format);
    }

    if rule_target == RuleTarget::General {
        let mut bytes = Vec::new();
        let mut count = 0usize;
        for rule_set in outputs {
            if should_write_general_rule_set(rule_set, behavior, format) {
                write_general_rule_set(&mut bytes, rule_set, format)?;
                count += rule_set.count();
            }
        }
        return Ok(vec![MemoryOutput {
            behavior: Behavior::Domain,
            format,
            count,
            bytes,
        }]);
    }

    let mut out = Vec::new();
    for rule_set in outputs {
        let mut bytes = Vec::new();
        write_rule_set_to_memory(&mut bytes, rule_set, rule_target, format, no_resolve)?;
        out.push(MemoryOutput {
            behavior: rule_set.behavior(),
            format,
            count: rule_set.count(),
            bytes,
        });
    }
    Ok(out)
}

pub fn write_owned_sing_box_rule_set_to_memory(
    sing_box_rules: RuleStore,
    format: OutputFormat,
) -> Result<Vec<MemoryOutput>> {
    if !matches!(format, OutputFormat::Json | OutputFormat::Srs) {
        bail!("sing-box owned writer only supports `json` and `srs` formats");
    }

    let mut bytes = Vec::new();
    let count = match format {
        OutputFormat::Json => {
            let count = sing_box_rules.count();
            sing_box::json::write_store_json(&mut bytes, &sing_box_rules)?;
            count
        }
        OutputFormat::Srs => sing_box::srs::write_owned_store_srs(&mut bytes, sing_box_rules)?,
        _ => unreachable!("format checked above"),
    };

    Ok(vec![MemoryOutput {
        behavior: Behavior::Domain,
        format,
        count,
        bytes,
    }])
}

fn validate_memory_output(
    rule_target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<()> {
    if rule_target == RuleTarget::SingBox {
        if matches!(format, OutputFormat::Json | OutputFormat::Srs) {
            return Ok(());
        }
        bail!("sing-box output only supports `json` and `srs` formats");
    }
    if matches!(format, OutputFormat::Json | OutputFormat::Srs) {
        bail!("JSON and SRS output are only supported for `sing-box` target");
    }

    match rule_target {
        RuleTarget::Mihomo
            if !matches!(
                format,
                OutputFormat::Mrs | OutputFormat::Text | OutputFormat::Yaml
            ) =>
        {
            bail!("mihomo output only supports `mrs`, `text`, and `yaml` formats");
        }
        RuleTarget::General
            if !matches!(
                format,
                OutputFormat::DomainSet | OutputFormat::RuleSet | OutputFormat::IpSet
            ) =>
        {
            bail!("general output only supports `domainset`, `ruleset`, and `ipset` formats");
        }
        RuleTarget::Egern if format != OutputFormat::RuleSet => {
            bail!("egern output only supports `ruleset` format");
        }
        _ => {}
    }
    if format == OutputFormat::Mrs && behavior == BehaviorMode::Classical {
        bail!("mihomo MRS output does not support classical behavior; use domain or ip");
    }
    Ok(())
}

fn write_mixed_rules_to_memory(
    rules: &RuleTextStore,
    format: OutputFormat,
) -> Result<Vec<MemoryOutput>> {
    let mut bytes = Vec::new();
    match format {
        OutputFormat::Text => generic::text::write_plain_rules(&mut bytes, rules.iter())?,
        OutputFormat::Yaml => mihomo::write_payload_yaml(&mut bytes, rules.iter())?,
        OutputFormat::RuleSet | OutputFormat::DomainSet | OutputFormat::IpSet => {
            generic::text::write_plain_rules(&mut bytes, rules.iter())?
        }
        OutputFormat::Mrs | OutputFormat::Json | OutputFormat::Srs => unreachable!(),
    }
    Ok(vec![MemoryOutput {
        behavior: Behavior::Domain,
        format,
        count: rules.len(),
        bytes,
    }])
}

fn write_rule_set_to_memory(
    bytes: &mut Vec<u8>,
    rule_set: &RuleSetOutput,
    target: RuleTarget,
    format: OutputFormat,
    no_resolve: bool,
) -> Result<()> {
    match format {
        OutputFormat::Mrs => rule_set.write_mrs(bytes),
        OutputFormat::Text if target == RuleTarget::Mihomo => match rule_set {
            RuleSetOutput::Domain(_) => rule_set
                .for_each_rule(|rule| mihomo::write_text_domain_rule(bytes, rule))
                .map_err(Into::into),
            RuleSetOutput::Ipcidr(_) => rule_set
                .for_each_rule(|rule| generic::text::write_plain_rule(bytes, rule))
                .map_err(Into::into),
        },
        OutputFormat::Text => rule_set
            .for_each_rule(|rule| generic::text::write_typed_rule(bytes, rule_set.behavior(), rule))
            .map_err(Into::into),
        OutputFormat::Yaml => {
            if target == RuleTarget::Egern {
                egern::write_ruleset_yaml_with_options(bytes, rule_set, no_resolve)
                    .map_err(Into::into)
            } else if target == RuleTarget::Mihomo {
                mihomo::write_payload_yaml_start(bytes)?;
                match rule_set {
                    RuleSetOutput::Domain(_) => rule_set
                        .for_each_rule(|rule| mihomo::write_payload_yaml_domain_rule(bytes, rule))
                        .map_err(Into::into),
                    RuleSetOutput::Ipcidr(_) => rule_set
                        .for_each_rule(|rule| mihomo::write_payload_yaml_rule(bytes, rule))
                        .map_err(Into::into),
                }
            } else {
                mihomo::write_payload_yaml_start(bytes)?;
                rule_set
                    .for_each_rule(|rule| {
                        mihomo::write_payload_yaml_typed_rule(bytes, rule_set.behavior(), rule)
                    })
                    .map_err(Into::into)
            }
        }
        OutputFormat::RuleSet if target == RuleTarget::Egern => {
            egern::write_ruleset_yaml_with_options(bytes, rule_set, no_resolve).map_err(Into::into)
        }
        _ => unreachable!("format was validated before memory writing"),
    }
}

fn write_sing_box_to_memory(
    outputs: &[RuleSetOutput],
    mixed_rules: &RuleTextStore,
    sing_box_rules: Option<&RuleStore>,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<Vec<MemoryOutput>> {
    let mut bytes = Vec::new();
    let count = match format {
        OutputFormat::Json => {
            if let Some(store) = sing_box_rules {
                let count = store.count();
                sing_box::json::write_store_json(&mut bytes, store)?;
                count
            } else {
                let rule_set = sing_box::RuleSet::from_outputs(outputs, mixed_rules, behavior);
                let count = rule_set.count();
                sing_box::json::write_json(&mut bytes, &rule_set)?;
                count
            }
        }
        OutputFormat::Srs => {
            if let Some(store) = sing_box_rules {
                sing_box::srs::write_store_srs(&mut bytes, store)?
            } else if !mixed_rules.is_empty() {
                sing_box::srs::write_classical_srs(&mut bytes, mixed_rules)?
            } else {
                let rule_set = sing_box::RuleSet::from_outputs(outputs, mixed_rules, behavior);
                let count = rule_set.count();
                sing_box::srs::write_srs(&mut bytes, &rule_set)?;
                count
            }
        }
        _ => unreachable!("sing-box format was validated before memory writing"),
    };

    Ok(vec![MemoryOutput {
        behavior: Behavior::Domain,
        format,
        count,
        bytes,
    }])
}

fn write_general_rule_set(
    bytes: &mut Vec<u8>,
    rule_set: &RuleSetOutput,
    format: OutputFormat,
) -> Result<()> {
    if format == OutputFormat::DomainSet && matches!(rule_set, RuleSetOutput::Domain(_)) {
        return rule_set
            .for_each_rule(|rule| generic::text::write_domain_set_rule(bytes, rule))
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
        OutputFormat::DomainSet => matches!(rule_set, RuleSetOutput::Domain(_)),
        OutputFormat::IpSet => matches!(rule_set, RuleSetOutput::Ipcidr(_)),
        OutputFormat::RuleSet => match behavior {
            BehaviorMode::Domain => matches!(rule_set, RuleSetOutput::Domain(_)),
            BehaviorMode::Ipcidr => matches!(rule_set, RuleSetOutput::Ipcidr(_)),
            BehaviorMode::Auto | BehaviorMode::Classical => true,
        },
        _ => true,
    }
}
