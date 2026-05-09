use anyhow::{Result, bail};

use crate::codec::mihomo::mrs::{Behavior, RuleSetOutput};
use crate::codec::{egern, generic, mihomo};
use crate::output::OutputFormat;
use crate::rules::RuleTextStore;

use super::common::{
    MemoryOutput, estimate_rule_sets_bytes, estimate_text_rules_bytes, memory_output,
};

pub(super) fn write_mixed_rules_to_memory(
    rules: &RuleTextStore,
    format: OutputFormat,
) -> Result<Vec<MemoryOutput>> {
    let mut bytes = Vec::with_capacity(estimate_text_rules_bytes(rules.len(), format));
    match format {
        OutputFormat::Text => generic::text::write_plain_rules(&mut bytes, rules.iter())?,
        OutputFormat::Yaml => mihomo::write_payload_yaml(&mut bytes, rules.iter())?,
        OutputFormat::RuleSet | OutputFormat::DomainSet | OutputFormat::IpSet => {
            generic::text::write_plain_rules(&mut bytes, rules.iter())?
        }
        OutputFormat::Mrs | OutputFormat::Json | OutputFormat::Srs => unreachable!(),
    }
    Ok(vec![memory_output(
        Behavior::Domain,
        format,
        rules.len(),
        bytes,
    )])
}

pub(super) fn write_egern_classical_to_memory(
    outputs: &[RuleSetOutput],
    format: OutputFormat,
    no_resolve: bool,
) -> Result<Vec<MemoryOutput>> {
    let count = outputs.iter().map(RuleSetOutput::count).sum::<usize>();
    if count == 0 {
        bail!("no supported rules found for the requested conversion");
    }
    let mut bytes = Vec::with_capacity(estimate_rule_sets_bytes(outputs, format));
    egern::write_rulesets_yaml_with_options(&mut bytes, outputs, no_resolve)?;
    Ok(vec![memory_output(Behavior::Domain, format, count, bytes)])
}
