mod common;
mod generic;
mod rule_set;
mod sing_box;
mod special;

use anyhow::{Result, bail};

use crate::codec::mihomo::mrs::RuleSetOutput;
use crate::codec::sing_box::RuleStore;
use crate::rules::{BehaviorMode, RuleTextStore};
use crate::{OutputFormat, RuleTarget};

pub use self::common::MemoryOutput;
use self::common::{estimate_rule_set_bytes, memory_output};
use self::generic::write_general_rule_sets_to_memory;
use self::rule_set::write_rule_set_to_memory;
pub use self::sing_box::write_owned_sing_box_rule_set_to_memory;
use self::sing_box::write_sing_box_to_memory;
use self::special::{write_egern_classical_to_memory, write_mixed_rules_to_memory};

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
            || (rule_target == RuleTarget::General && format == OutputFormat::RuleSet))
    {
        return write_mixed_rules_to_memory(mixed_rules, format);
    }

    if rule_target == RuleTarget::Egern && behavior == BehaviorMode::Classical {
        return write_egern_classical_to_memory(outputs, format, no_resolve);
    }

    if rule_target == RuleTarget::General {
        return write_general_rule_sets_to_memory(outputs, behavior, format);
    }

    let mut out = Vec::new();
    for rule_set in outputs {
        let mut bytes = Vec::with_capacity(estimate_rule_set_bytes(rule_set, format));
        write_rule_set_to_memory(&mut bytes, rule_set, rule_target, format, no_resolve)?;
        out.push(memory_output(
            rule_set.behavior(),
            format,
            rule_set.count(),
            bytes,
        ));
    }
    Ok(out)
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
    if format == OutputFormat::Mrs {
        match behavior {
            BehaviorMode::Domain | BehaviorMode::Ipcidr => {}
            BehaviorMode::Auto => bail!(
                "mihomo MRS output needs explicit output behavior for mixed/classical input; use domain or ip"
            ),
            BehaviorMode::Classical => {
                bail!("mihomo MRS output does not support classical behavior; use domain or ip")
            }
        }
    }
    Ok(())
}
