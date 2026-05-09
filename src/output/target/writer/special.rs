use std::path::Path;

use anyhow::{Result, bail};

use crate::RuleTarget;
use crate::codec::mihomo::mrs::{Behavior, RuleSetOutput};
use crate::codec::{egern, generic, mihomo};
use crate::output::OutputFormat;
use crate::rules::RuleTextStore;

use super::common::{OutputFile, create_output_writer, output_file};
use crate::output::target::resolve_output_path_for_target;

pub(super) fn write_mixed_rules_to_path(
    rules: &RuleTextStore,
    base: &Path,
    target: RuleTarget,
    format: OutputFormat,
) -> Result<Vec<OutputFile>> {
    let path = resolve_output_path_for_target(base, Behavior::Domain, false, format, target);
    let mut file = create_output_writer(&path)?;
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

    Ok(vec![output_file(
        Behavior::Domain,
        format,
        rules.len(),
        path,
    )])
}

pub(super) fn write_egern_classical_to_path(
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
    let file = create_output_writer(&path)?;
    egern::write_rulesets_yaml_with_options(file, outputs, no_resolve)?;

    Ok(vec![output_file(Behavior::Domain, format, count, path)])
}
