use anyhow::Result;

use crate::RuleTarget;
use crate::codec::mihomo::mrs::RuleSetOutput;
use crate::codec::{egern, generic, mihomo};
use crate::output::OutputFormat;

pub(super) fn write_rule_set_to_memory(
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
        OutputFormat::Adguard if target == RuleTarget::General => rule_set
            .for_each_rule(|rule| generic::text::write_adguard_domain_rule(bytes, rule))
            .map_err(Into::into),
        _ => unreachable!("format was validated before memory writing"),
    }
}
