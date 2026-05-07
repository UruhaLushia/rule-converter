use std::io::Write;

use anyhow::Result;

use crate::rules::{ClassicalKind, ClassicalRule, RuleTextStore};

use super::binary::write_uvarint;
use super::constants::*;
use super::domain::{DomainMatcherKeys, write_domain_matcher_keys};
use super::ip_set::write_ip_set_item_from_rules;

#[derive(Clone, Copy, Default)]
pub(super) struct GroupedClassicalRuleCounts {
    domains: usize,
    domain_suffix: usize,
    domain_keyword: usize,
    domain_regex: usize,
    source_ip_cidr: usize,
    ip_cidr: usize,
    network: usize,
    source_port_range: usize,
    port_range: usize,
    process_name: usize,
    process_path: usize,
    process_path_regex: usize,
}

impl GroupedClassicalRuleCounts {
    pub(super) fn from_rules(rules: &RuleTextStore) -> Self {
        let mut counts = Self::default();
        for rule in rules.iter() {
            let Ok(parsed) = ClassicalRule::parse(rule) else {
                continue;
            };
            counts.increment(parsed.kind);
        }
        counts
    }

    pub(super) fn rule_count(self) -> usize {
        usize::from(self.domains != 0 || self.domain_suffix != 0)
            + usize::from(self.domain_keyword != 0)
            + usize::from(self.domain_regex != 0)
            + usize::from(self.source_ip_cidr != 0)
            + usize::from(self.ip_cidr != 0)
            + usize::from(self.network != 0)
            + usize::from(self.source_port_range != 0)
            + usize::from(self.port_range != 0)
            + usize::from(self.process_name != 0)
            + usize::from(self.process_path != 0)
            + usize::from(self.process_path_regex != 0)
    }

    pub(super) fn item_count(self) -> usize {
        self.domains
            + self.domain_suffix
            + self.domain_keyword
            + self.domain_regex
            + self.source_ip_cidr
            + self.ip_cidr
            + self.network
            + self.source_port_range
            + self.port_range
            + self.process_name
            + self.process_path
            + self.process_path_regex
    }

    pub(super) fn write<W: Write>(self, writer: &mut W, rules: &RuleTextStore) -> Result<()> {
        if self.domains != 0 || self.domain_suffix != 0 {
            writer.write_all(&[RULE_DEFAULT, ITEM_DOMAIN])?;
            write_domain_rule(writer, rules, self.domains + self.domain_suffix)?;
            writer.write_all(&[ITEM_FINAL, 0])?;
        }
        write_string_rule(
            writer,
            rules,
            ITEM_DOMAIN_KEYWORD,
            self.domain_keyword,
            |kind| kind == ClassicalKind::DomainKeyword,
        )?;
        write_string_rule(
            writer,
            rules,
            ITEM_DOMAIN_REGEX,
            self.domain_regex,
            |kind| kind == ClassicalKind::DomainRegex,
        )?;
        write_ip_rule(
            writer,
            rules,
            ITEM_SOURCE_IP_CIDR,
            self.source_ip_cidr,
            |kind| matches!(kind, ClassicalKind::SrcIpcidr | ClassicalKind::SrcIp),
        )?;
        write_ip_rule(writer, rules, ITEM_IP_CIDR, self.ip_cidr, |kind| {
            kind == ClassicalKind::Ipcidr
        })?;
        write_string_rule(writer, rules, ITEM_NETWORK, self.network, |kind| {
            kind == ClassicalKind::Network
        })?;
        write_string_rule(
            writer,
            rules,
            ITEM_SOURCE_PORT_RANGE,
            self.source_port_range,
            |kind| kind == ClassicalKind::SrcPort,
        )?;
        write_string_rule(writer, rules, ITEM_PORT_RANGE, self.port_range, |kind| {
            kind == ClassicalKind::DstPort
        })?;
        write_string_rule(
            writer,
            rules,
            ITEM_PROCESS_NAME,
            self.process_name,
            |kind| kind == ClassicalKind::ProcessName,
        )?;
        write_string_rule(
            writer,
            rules,
            ITEM_PROCESS_PATH,
            self.process_path,
            |kind| kind == ClassicalKind::ProcessPath,
        )?;
        write_string_rule(
            writer,
            rules,
            ITEM_PROCESS_PATH_REGEX,
            self.process_path_regex,
            |kind| kind == ClassicalKind::ProcessPathRegex,
        )?;
        Ok(())
    }

    fn increment(&mut self, kind: ClassicalKind) {
        match kind {
            ClassicalKind::Domain => self.domains += 1,
            ClassicalKind::DomainSuffix => self.domain_suffix += 1,
            ClassicalKind::DomainKeyword => self.domain_keyword += 1,
            ClassicalKind::DomainRegex => self.domain_regex += 1,
            ClassicalKind::Ipcidr => self.ip_cidr += 1,
            ClassicalKind::SrcIpcidr | ClassicalKind::SrcIp => self.source_ip_cidr += 1,
            ClassicalKind::Network => self.network += 1,
            ClassicalKind::DstPort => self.port_range += 1,
            ClassicalKind::SrcPort => self.source_port_range += 1,
            ClassicalKind::ProcessName => self.process_name += 1,
            ClassicalKind::ProcessPath => self.process_path += 1,
            ClassicalKind::ProcessPathRegex => self.process_path_regex += 1,
            _ => {}
        }
    }
}

fn write_domain_rule<W: Write>(writer: &mut W, rules: &RuleTextStore, count: usize) -> Result<()> {
    let mut keys = DomainMatcherKeys::with_capacity(count);
    for rule in rules.iter() {
        let Ok(parsed) = ClassicalRule::parse(rule) else {
            continue;
        };
        let payload = parsed.payload.unwrap_or_default();
        match parsed.kind {
            ClassicalKind::Domain => keys.push_exact(payload)?,
            ClassicalKind::DomainSuffix => keys.push_suffix(payload)?,
            _ => {}
        }
    }
    write_domain_matcher_keys(writer, &mut keys)
}

fn write_string_rule<W, F>(
    writer: &mut W,
    rules: &RuleTextStore,
    item: u8,
    count: usize,
    matches_kind: F,
) -> Result<()>
where
    W: Write,
    F: Fn(ClassicalKind) -> bool,
{
    if count == 0 {
        return Ok(());
    }
    writer.write_all(&[RULE_DEFAULT, item])?;
    write_uvarint(writer, count as u64)?;
    for rule in rules.iter() {
        let Ok(parsed) = ClassicalRule::parse(rule) else {
            continue;
        };
        if !matches_kind(parsed.kind) {
            continue;
        }
        let payload = parsed.payload.unwrap_or_default();
        write_uvarint(writer, payload.len() as u64)?;
        writer.write_all(payload.as_bytes())?;
    }
    writer.write_all(&[ITEM_FINAL, 0])?;
    Ok(())
}

fn write_ip_rule<W, F>(
    writer: &mut W,
    rules: &RuleTextStore,
    item: u8,
    count: usize,
    matches_kind: F,
) -> Result<()>
where
    W: Write,
    F: Fn(ClassicalKind) -> bool,
{
    if count == 0 {
        return Ok(());
    }
    writer.write_all(&[RULE_DEFAULT])?;
    write_ip_set_item_from_rules(writer, item, rules, count, matches_kind)?;
    writer.write_all(&[ITEM_FINAL, 0])?;
    Ok(())
}
