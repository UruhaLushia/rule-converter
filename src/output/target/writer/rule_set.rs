use std::fs;
use std::io::BufWriter;

use anyhow::Result;

use crate::codec::mihomo::mrs::RuleSetOutput;
use crate::codec::{egern, generic, mihomo};
use crate::output::OutputFormat;
use crate::{RuleTarget, rules::RuleTextStore};

use super::generic::write_generic_text;

pub(super) fn write_rule_set(
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
