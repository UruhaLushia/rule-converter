mod common;
mod generic;
mod rule_set;
mod sing_box;
mod special;

use anyhow::{Result, bail};
use std::path::Path;

use crate::codec::mihomo::mrs::RuleSetOutput;
use crate::codec::sing_box::RuleStore;
use crate::output::OutputFormat;
use crate::rules::RuleTextStore;
use crate::{BehaviorMode, RuleTarget};

pub use self::common::{OutputFile, OutputTarget};
use self::common::{create_output_writer, output_file};
use self::generic::write_generic_text_to_path;
use self::rule_set::write_rule_set;
use self::sing_box::{write_owned_sing_box_to_path, write_sing_box_to_path};
use self::special::{write_egern_classical_to_path, write_mixed_rules_to_path};
use super::resolve_output_path_for_target;

#[derive(Clone, Copy)]
struct WritePathOptions {
    rule_target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
    no_resolve: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn write_rule_sets(
    outputs: &[RuleSetOutput],
    mixed_rules: &RuleTextStore,
    sing_box_rules: Option<&RuleStore>,
    target: OutputTarget<'_>,
    rule_target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
    no_resolve: bool,
) -> Result<Vec<OutputFile>> {
    let options = WritePathOptions {
        rule_target,
        format,
        behavior,
        no_resolve,
    };
    match target {
        OutputTarget::FilePath(base) => {
            write_to_path(outputs, mixed_rules, sing_box_rules, base, options)
        }
    }
}

fn write_to_path(
    outputs: &[RuleSetOutput],
    mixed_rules: &RuleTextStore,
    sing_box_rules: Option<&RuleStore>,
    base: &Path,
    options: WritePathOptions,
) -> Result<Vec<OutputFile>> {
    let WritePathOptions {
        rule_target,
        format,
        behavior,
        no_resolve,
    } = options;
    validate_output_request(rule_target, format, behavior)?;

    if rule_target == RuleTarget::SingBox {
        return write_sing_box_to_path(
            outputs,
            mixed_rules,
            sing_box_rules,
            base,
            format,
            behavior,
        );
    }

    if !mixed_rules.is_empty()
        && ((rule_target == RuleTarget::Mihomo
            && matches!(format, OutputFormat::Text | OutputFormat::Yaml)
            && behavior == BehaviorMode::Classical)
            || (rule_target == RuleTarget::General && format == OutputFormat::RuleSet))
    {
        return write_mixed_rules_to_path(mixed_rules, base, rule_target, format);
    }

    if rule_target == RuleTarget::General {
        return write_generic_text_to_path(outputs, base, behavior, format);
    }

    if rule_target == RuleTarget::Egern && behavior == BehaviorMode::Classical {
        return write_egern_classical_to_path(outputs, base, format, no_resolve);
    }

    write_split_rule_sets(outputs, mixed_rules, base, options)
}

fn validate_output_request(
    rule_target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<()> {
    if rule_target == RuleTarget::SingBox
        && matches!(format, OutputFormat::Json | OutputFormat::Srs)
    {
        return Ok(());
    }
    if rule_target == RuleTarget::SingBox {
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
                OutputFormat::DomainSet
                    | OutputFormat::Adguard
                    | OutputFormat::RuleSet
                    | OutputFormat::IpSet
            ) =>
        {
            bail!(
                "general output only supports `domainset`, `adguard`, `ruleset`, and `ipset` formats"
            );
        }
        RuleTarget::Egern if !matches!(format, OutputFormat::Yaml | OutputFormat::RuleSet) => {
            bail!("egern output only supports `yaml` format");
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

fn write_split_rule_sets(
    outputs: &[RuleSetOutput],
    mixed_rules: &RuleTextStore,
    base: &Path,
    options: WritePathOptions,
) -> Result<Vec<OutputFile>> {
    let split = outputs.len() > 1;
    let mut files = Vec::with_capacity(outputs.len());

    for rule_set in outputs {
        let path = resolve_output_path_for_target(
            base,
            rule_set.behavior(),
            split,
            options.format,
            options.rule_target,
        );
        let file = create_output_writer(&path)?;
        write_rule_set(
            file,
            rule_set,
            mixed_rules,
            options.rule_target,
            options.format,
            options.no_resolve,
        )?;
        files.push(output_file(
            rule_set.behavior(),
            options.format,
            rule_set.count(),
            path,
        ));
    }

    Ok(files)
}

pub fn write_owned_sing_box_rule_set(
    sing_box_rules: RuleStore,
    target: OutputTarget<'_>,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<Vec<OutputFile>> {
    match target {
        OutputTarget::FilePath(base) => {
            write_owned_sing_box_to_path(sing_box_rules, base, format, behavior)
        }
    }
}
