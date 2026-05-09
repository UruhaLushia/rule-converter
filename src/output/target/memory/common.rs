use crate::codec::mihomo::mrs::{Behavior, RuleSetOutput};
use crate::output::OutputFormat;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryOutput {
    pub behavior: Behavior,
    pub format: OutputFormat,
    pub count: usize,
    pub bytes: Vec<u8>,
}

pub(super) fn memory_output(
    behavior: Behavior,
    format: OutputFormat,
    count: usize,
    bytes: Vec<u8>,
) -> MemoryOutput {
    MemoryOutput {
        behavior,
        format,
        count,
        bytes,
    }
}

pub(super) fn estimate_rule_sets_bytes(outputs: &[RuleSetOutput], format: OutputFormat) -> usize {
    outputs
        .iter()
        .map(|rule_set| estimate_rule_set_bytes(rule_set, format))
        .sum()
}

pub(super) fn estimate_rule_set_bytes(rule_set: &RuleSetOutput, format: OutputFormat) -> usize {
    estimate_text_rules_bytes(rule_set.count(), format)
}

pub(super) fn estimate_text_rules_bytes(count: usize, format: OutputFormat) -> usize {
    match format {
        OutputFormat::Yaml | OutputFormat::RuleSet => 16 + count.saturating_mul(24),
        OutputFormat::Text | OutputFormat::DomainSet | OutputFormat::IpSet => {
            count.saturating_mul(20)
        }
        OutputFormat::Mrs | OutputFormat::Json | OutputFormat::Srs => 0,
    }
}
