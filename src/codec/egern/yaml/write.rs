use std::io::Write;

use crate::codec::mihomo::mrs::{Behavior, RuleSetOutput};

pub fn write_ruleset_yaml<W: Write>(
    mut writer: W,
    rule_set: &RuleSetOutput,
) -> std::io::Result<()> {
    write_ruleset_yaml_with_options(&mut writer, rule_set, false)
}

pub fn write_ruleset_yaml_with_options<W: Write>(
    mut writer: W,
    rule_set: &RuleSetOutput,
    no_resolve: bool,
) -> std::io::Result<()> {
    match rule_set.behavior() {
        Behavior::Domain => write_domain_ruleset(&mut writer, rule_set),
        Behavior::Ipcidr => write_ipcidr_ruleset(&mut writer, rule_set, no_resolve),
    }
}

pub fn write_rulesets_yaml_with_options<W: Write>(
    mut writer: W,
    rule_sets: &[RuleSetOutput],
    no_resolve: bool,
) -> std::io::Result<()> {
    let mut wrote_no_resolve = false;
    for rule_set in rule_sets {
        match rule_set.behavior() {
            Behavior::Domain => write_domain_ruleset(&mut writer, rule_set)?,
            Behavior::Ipcidr => {
                write_ipcidr_ruleset(&mut writer, rule_set, no_resolve && !wrote_no_resolve)?;
                wrote_no_resolve |= no_resolve;
            }
        }
    }
    Ok(())
}

fn write_domain_ruleset<W: Write>(writer: &mut W, rule_set: &RuleSetOutput) -> std::io::Result<()> {
    let RuleSetOutput::Domain(domain) = rule_set else {
        return Ok(());
    };

    let mut wrote_exact_header = false;
    domain.for_each_exact_rule(|rule| {
        if !wrote_exact_header {
            writeln!(writer, "domain_set:")?;
            wrote_exact_header = true;
        }
        writeln!(writer, "  - {rule:?}")
    })?;

    let mut wrote_suffix_header = false;
    domain.for_each_suffix_rule(|rule| {
        if !wrote_suffix_header {
            writeln!(writer, "domain_suffix_set:")?;
            wrote_suffix_header = true;
        }
        writeln!(writer, "  - {rule:?}")
    })
}

fn write_ipcidr_ruleset<W: Write>(
    writer: &mut W,
    rule_set: &RuleSetOutput,
    no_resolve: bool,
) -> std::io::Result<()> {
    let mut wrote_v4_header = false;
    let mut wrote_v6_header = false;

    if no_resolve {
        writeln!(writer, "no_resolve: true")?;
    }

    rule_set.for_each_rule(|rule| {
        if rule.contains(':') {
            if !wrote_v6_header {
                writeln!(writer, "ip_cidr6_set:")?;
                wrote_v6_header = true;
            }
        } else {
            if !wrote_v4_header {
                writeln!(writer, "ip_cidr_set:")?;
                wrote_v4_header = true;
            }
        }
        writeln!(writer, "  - {rule:?}")
    })
}
