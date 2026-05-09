use std::fs;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::codec::mihomo::mrs::{Behavior, RuleSetOutput};
use crate::codec::sing_box::RuleStore;
use crate::codec::{egern, generic, mihomo, sing_box};
use crate::output::OutputFormat;
use crate::rules::RuleTextStore;
use crate::{BehaviorMode, RuleTarget};

use super::resolve_output_path_for_target;

const FILE_BUFFER_SIZE: usize = 64 * 1024;

pub enum OutputTarget<'a> {
    FilePath(&'a Path),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputFile {
    pub behavior: Behavior,
    pub format: OutputFormat,
    pub count: usize,
    pub path: PathBuf,
}

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
    match target {
        OutputTarget::FilePath(base) => write_to_path(
            outputs,
            mixed_rules,
            sing_box_rules,
            base,
            rule_target,
            format,
            behavior,
            no_resolve,
        ),
    }
}

fn write_to_path(
    outputs: &[RuleSetOutput],
    mixed_rules: &RuleTextStore,
    sing_box_rules: Option<&RuleStore>,
    base: &Path,
    rule_target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
    no_resolve: bool,
) -> Result<Vec<OutputFile>> {
    if rule_target == RuleTarget::SingBox
        && matches!(format, OutputFormat::Json | OutputFormat::Srs)
    {
        return write_sing_box_to_path(
            outputs,
            mixed_rules,
            sing_box_rules,
            base,
            format,
            behavior,
        );
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

    let split = outputs.len() > 1;
    let mut files = Vec::with_capacity(outputs.len());

    for rule_set in outputs {
        let path =
            resolve_output_path_for_target(base, rule_set.behavior(), split, format, rule_target);
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create output directory {}", parent.display())
            })?;
        }
        let file = fs::File::create(&path)
            .with_context(|| format!("failed to create output {}", path.display()))?;
        write_rule_set(
            BufWriter::with_capacity(FILE_BUFFER_SIZE, file),
            rule_set,
            mixed_rules,
            rule_target,
            format,
            no_resolve,
        )?;
        files.push(OutputFile {
            behavior: rule_set.behavior(),
            format,
            count: rule_set.count(),
            path,
        });
    }

    Ok(files)
}

fn write_mixed_rules_to_path(
    rules: &RuleTextStore,
    base: &Path,
    target: RuleTarget,
    format: OutputFormat,
) -> Result<Vec<OutputFile>> {
    let path = resolve_output_path_for_target(base, Behavior::Domain, false, format, target);
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    }

    let file = fs::File::create(&path)
        .with_context(|| format!("failed to create output {}", path.display()))?;
    let mut file = BufWriter::with_capacity(FILE_BUFFER_SIZE, file);
    match format {
        OutputFormat::Text => generic::text::write_plain_rules(&mut file, rules.iter())?,
        OutputFormat::Yaml => mihomo::write_payload_yaml(&mut file, rules.iter())?,
        OutputFormat::RuleSet | OutputFormat::DomainSet | OutputFormat::IpSet => {
            generic::text::write_plain_rules(&mut file, rules.iter())?
        }
        OutputFormat::Mrs => unreachable!("mixed rule text writer does not handle MRS"),
        OutputFormat::Json | OutputFormat::Srs => {
            unreachable!("mixed rule text writer does not handle sing-box formats")
        }
    }

    Ok(vec![OutputFile {
        behavior: Behavior::Domain,
        format,
        count: rules.len(),
        path,
    }])
}

fn write_egern_classical_to_path(
    outputs: &[RuleSetOutput],
    base: &Path,
    format: OutputFormat,
    no_resolve: bool,
) -> Result<Vec<OutputFile>> {
    let count = outputs.iter().map(RuleSetOutput::count).sum::<usize>();
    if count == 0 {
        bail!("no supported rules found for the requested conversion");
    }

    let path =
        resolve_output_path_for_target(base, Behavior::Domain, false, format, RuleTarget::Egern);
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    }
    let file = fs::File::create(&path)
        .with_context(|| format!("failed to create output {}", path.display()))?;
    egern::write_rulesets_yaml_with_options(
        BufWriter::with_capacity(FILE_BUFFER_SIZE, file),
        outputs,
        no_resolve,
    )?;

    Ok(vec![OutputFile {
        behavior: Behavior::Domain,
        format,
        count,
        path,
    }])
}

fn write_rule_set(
    file: BufWriter<fs::File>,
    rule_set: &RuleSetOutput,
    _mixed_rules: &RuleTextStore,
    target: RuleTarget,
    format: OutputFormat,
    no_resolve: bool,
) -> Result<()> {
    let mut file = file;
    match format {
        OutputFormat::Mrs => rule_set.write_mrs(file),
        OutputFormat::Json | OutputFormat::Srs => {
            unreachable!("sing-box formats are handled before split rule-set writing")
        }
        OutputFormat::DomainSet | OutputFormat::IpSet | OutputFormat::RuleSet
            if target == RuleTarget::General =>
        {
            write_generic_text(&mut file, rule_set, format)
        }
        OutputFormat::Text if target == RuleTarget::General => {
            write_generic_text(&mut file, rule_set, OutputFormat::RuleSet)
        }
        OutputFormat::Text if target == RuleTarget::Mihomo => match rule_set {
            RuleSetOutput::Domain(_) => rule_set
                .for_each_rule(|rule| mihomo::write_text_domain_rule(&mut file, rule))
                .map_err(Into::into),
            RuleSetOutput::Ipcidr(_) => rule_set
                .for_each_rule(|rule| generic::text::write_plain_rule(&mut file, rule))
                .map_err(Into::into),
        },
        OutputFormat::Text => rule_set
            .for_each_rule(|rule| {
                generic::text::write_typed_rule(&mut file, rule_set.behavior(), rule)
            })
            .map_err(Into::into),
        OutputFormat::Yaml => {
            if target == RuleTarget::Egern {
                egern::write_ruleset_yaml_with_options(file, rule_set, no_resolve)
                    .map_err(Into::into)
            } else if target == RuleTarget::Mihomo {
                mihomo::write_payload_yaml_start(&mut file)?;
                match rule_set {
                    RuleSetOutput::Domain(_) => rule_set
                        .for_each_rule(|rule| {
                            mihomo::write_payload_yaml_domain_rule(&mut file, rule)
                        })
                        .map_err(Into::into),
                    RuleSetOutput::Ipcidr(_) => rule_set
                        .for_each_rule(|rule| mihomo::write_payload_yaml_rule(&mut file, rule))
                        .map_err(Into::into),
                }
            } else {
                mihomo::write_payload_yaml_start(&mut file)?;
                rule_set
                    .for_each_rule(|rule| {
                        mihomo::write_payload_yaml_typed_rule(&mut file, rule_set.behavior(), rule)
                    })
                    .map_err(Into::into)
            }
        }
        OutputFormat::RuleSet if target == RuleTarget::Egern => {
            egern::write_ruleset_yaml_with_options(file, rule_set, no_resolve).map_err(Into::into)
        }
        OutputFormat::DomainSet | OutputFormat::IpSet | OutputFormat::RuleSet => unreachable!(),
    }
}

fn write_sing_box_to_path(
    outputs: &[RuleSetOutput],
    mixed_rules: &RuleTextStore,
    sing_box_rules: Option<&RuleStore>,
    base: &Path,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<Vec<OutputFile>> {
    let rule_set = sing_box_rules
        .map(|store| store.to_rule_set_with_behavior(behavior))
        .unwrap_or_else(|| sing_box::RuleSet::from_outputs(outputs, mixed_rules, behavior));
    let output_behavior = rule_set_output_behavior(&rule_set, behavior);
    if rule_set.count() == 0 {
        bail!("no supported rules found for the requested conversion");
    }
    let path =
        resolve_output_path_for_target(base, output_behavior, false, format, RuleTarget::SingBox);
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    }

    let file = fs::File::create(&path)
        .with_context(|| format!("failed to create output {}", path.display()))?;
    let mut file = BufWriter::with_capacity(FILE_BUFFER_SIZE, file);
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

    Ok(vec![OutputFile {
        behavior: output_behavior,
        format,
        count,
        path,
    }])
}

fn write_generic_text_to_path(
    outputs: &[RuleSetOutput],
    base: &Path,
    behavior: BehaviorMode,
    format: OutputFormat,
) -> Result<Vec<OutputFile>> {
    let output_behavior = behavior_to_output_behavior(behavior);
    let path =
        resolve_output_path_for_target(base, output_behavior, false, format, RuleTarget::General);
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    }

    let count = outputs
        .iter()
        .filter(|rule_set| should_write_general_rule_set(rule_set, behavior, format))
        .map(RuleSetOutput::count)
        .sum::<usize>();
    if count == 0 {
        bail!("no supported rules found for the requested conversion");
    }

    let file = fs::File::create(&path)
        .with_context(|| format!("failed to create output {}", path.display()))?;
    let mut file = BufWriter::with_capacity(FILE_BUFFER_SIZE, file);

    for rule_set in outputs {
        if should_write_general_rule_set(rule_set, behavior, format) {
            write_generic_text(&mut file, rule_set, format)?;
        }
    }

    Ok(outputs
        .iter()
        .filter(|rule_set| should_write_general_rule_set(rule_set, behavior, format))
        .map(|rule_set| OutputFile {
            behavior: rule_set.behavior(),
            format,
            count: rule_set.count(),
            path: path.clone(),
        })
        .collect())
}

fn behavior_to_output_behavior(behavior: BehaviorMode) -> Behavior {
    match behavior {
        BehaviorMode::Ipcidr => Behavior::Ipcidr,
        BehaviorMode::Auto | BehaviorMode::Domain | BehaviorMode::Classical => Behavior::Domain,
    }
}

fn rule_set_output_behavior(rule_set: &sing_box::RuleSet, behavior: BehaviorMode) -> Behavior {
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

fn write_generic_text(
    file: &mut BufWriter<fs::File>,
    rule_set: &RuleSetOutput,
    format: OutputFormat,
) -> Result<()> {
    if format == OutputFormat::DomainSet && matches!(rule_set, RuleSetOutput::Domain(_)) {
        return rule_set
            .for_each_rule(|rule| generic::text::write_domain_set_rule(file, rule))
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

fn write_owned_sing_box_to_path(
    sing_box_rules: RuleStore,
    base: &Path,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<Vec<OutputFile>> {
    if !matches!(format, OutputFormat::Json | OutputFormat::Srs) {
        bail!("sing-box owned writer only supports `json` and `srs` formats");
    }

    let rule_set = sing_box_rules.to_rule_set_with_behavior(behavior);
    let output_behavior = rule_set_output_behavior(&rule_set, behavior);
    if rule_set.count() == 0 {
        bail!("no supported rules found for the requested conversion");
    }
    let path =
        resolve_output_path_for_target(base, output_behavior, false, format, RuleTarget::SingBox);
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    }

    let file = fs::File::create(&path)
        .with_context(|| format!("failed to create output {}", path.display()))?;
    let mut file = BufWriter::with_capacity(FILE_BUFFER_SIZE, file);
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
        _ => unreachable!("format checked above"),
    };

    Ok(vec![OutputFile {
        behavior: output_behavior,
        format,
        count,
        path,
    }])
}
