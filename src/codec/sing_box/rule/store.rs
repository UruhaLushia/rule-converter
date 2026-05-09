use crate::rules::{BehaviorMode, ClassicalKind, ClassicalRule};

use super::rule_item::push_rule;
use super::{RuleSet, RuleStore, VERSION_CURRENT};

impl RuleStore {
    pub fn reserve_domain(&mut self, items: usize, bytes: usize) {
        self.domain.reserve(items, bytes);
        self.domain_suffix.reserve(items / 8, bytes / 8);
        self.domain_keyword.reserve(items / 32, bytes / 32);
        self.domain_regex.reserve(items / 64, bytes / 64);
    }

    pub fn reserve_ip_cidr(&mut self, items: usize, bytes: usize) {
        self.ip_cidr.reserve(items, bytes);
        self.source_ip_cidr.reserve(items / 16, bytes / 16);
    }

    pub fn reserve_mixed(&mut self, items: usize, bytes: usize) {
        let item_hint = (items / 8).max(1);
        let byte_hint = (bytes / 8).max(1);
        self.domain.reserve(item_hint, byte_hint);
        self.domain_suffix.reserve(item_hint, byte_hint);
        self.domain_keyword.reserve(item_hint / 4, byte_hint / 4);
        self.domain_regex.reserve(item_hint / 8, byte_hint / 8);
        self.source_ip_cidr.reserve(item_hint / 8, byte_hint / 8);
        self.ip_cidr.reserve(item_hint / 8, byte_hint / 8);
        self.network.reserve(item_hint / 16, byte_hint / 16);
        self.source_port_range
            .reserve(item_hint / 16, byte_hint / 16);
        self.port_range.reserve(item_hint / 16, byte_hint / 16);
        self.process_name.reserve(item_hint / 16, byte_hint / 16);
        self.process_path.reserve(item_hint / 16, byte_hint / 16);
        self.process_path_regex
            .reserve(item_hint / 16, byte_hint / 16);
    }

    pub fn push_classical(&mut self, rule: &str) -> bool {
        if self.push_fast_classical(rule) {
            return true;
        }

        let Some(parsed) = ClassicalRule::parse(rule).ok() else {
            return false;
        };
        let payload = parsed.payload.unwrap_or_default();
        match parsed.kind {
            ClassicalKind::Domain => self.domain.push(payload),
            ClassicalKind::DomainSuffix => self.domain_suffix.push(payload),
            ClassicalKind::DomainKeyword => self.domain_keyword.push(payload),
            ClassicalKind::DomainRegex => self.domain_regex.push(payload),
            ClassicalKind::Ipcidr => self.ip_cidr.push(payload),
            ClassicalKind::SrcIpcidr | ClassicalKind::SrcIp => self.source_ip_cidr.push(payload),
            ClassicalKind::Network => self.network.push(payload),
            ClassicalKind::DstPort => self.port_range.push(payload),
            ClassicalKind::SrcPort => self.source_port_range.push(payload),
            ClassicalKind::ProcessName => self.process_name.push(payload),
            ClassicalKind::ProcessPath => self.process_path.push(payload),
            ClassicalKind::ProcessPathRegex => self.process_path_regex.push(payload),
            _ => return false,
        }
        true
    }

    fn push_fast_classical(&mut self, rule: &str) -> bool {
        let Some((kind, rest)) = rule.split_once(',') else {
            return false;
        };
        let payload = rest
            .split_once(',')
            .map_or(rest, |(payload, _)| payload)
            .trim();
        if payload.is_empty() {
            return false;
        }

        if kind.eq_ignore_ascii_case("DOMAIN") {
            self.domain.push(payload);
        } else if kind.eq_ignore_ascii_case("DOMAIN-SUFFIX") {
            self.domain_suffix.push(payload);
        } else if kind.eq_ignore_ascii_case("DOMAIN-KEYWORD") {
            self.domain_keyword.push(payload);
        } else if kind.eq_ignore_ascii_case("DOMAIN-REGEX") {
            self.domain_regex.push(payload);
        } else if kind.eq_ignore_ascii_case("IP-CIDR") || kind.eq_ignore_ascii_case("IP-CIDR6") {
            self.ip_cidr.push(payload);
        } else if kind.eq_ignore_ascii_case("SRC-IP-CIDR") || kind.eq_ignore_ascii_case("SRC-IP") {
            self.source_ip_cidr.push(payload);
        } else if kind.eq_ignore_ascii_case("NETWORK") {
            self.network.push(payload);
        } else if kind.eq_ignore_ascii_case("DST-PORT") || kind.eq_ignore_ascii_case("DEST-PORT") {
            self.port_range.push(payload);
        } else if kind.eq_ignore_ascii_case("SRC-PORT") {
            self.source_port_range.push(payload);
        } else if kind.eq_ignore_ascii_case("PROCESS-NAME") {
            self.process_name.push(payload);
        } else if kind.eq_ignore_ascii_case("PROCESS-PATH") {
            self.process_path.push(payload);
        } else if kind.eq_ignore_ascii_case("PROCESS-PATH-REGEX") {
            self.process_path_regex.push(payload);
        } else {
            return false;
        }
        true
    }

    pub fn push_domain(&mut self, value: impl AsRef<str>) {
        self.domain.push(value.as_ref());
    }

    pub fn push_domain_suffix(&mut self, value: impl AsRef<str>) {
        self.domain_suffix.push(value.as_ref());
    }

    pub fn push_ip_cidr(&mut self, value: impl AsRef<str>) {
        self.ip_cidr.push(value.as_ref());
    }

    pub fn has_domain_rules(&self) -> bool {
        !self.domain.is_empty()
            || !self.domain_suffix.is_empty()
            || !self.domain_keyword.is_empty()
            || !self.domain_regex.is_empty()
    }

    pub fn has_ip_rules(&self) -> bool {
        !self.source_ip_cidr.is_empty() || !self.ip_cidr.is_empty()
    }

    pub fn keep_domain_rules(&mut self) {
        self.source_ip_cidr.clear();
        self.ip_cidr.clear();
        self.network.clear();
        self.source_port_range.clear();
        self.port_range.clear();
        self.process_name.clear();
        self.process_path.clear();
        self.process_path_regex.clear();
    }

    pub fn keep_ip_rules(&mut self) {
        self.domain.clear();
        self.domain_suffix.clear();
        self.domain_keyword.clear();
        self.domain_regex.clear();
        self.network.clear();
        self.source_port_range.clear();
        self.port_range.clear();
        self.process_name.clear();
        self.process_path.clear();
        self.process_path_regex.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.count() == 0
    }

    pub fn count(&self) -> usize {
        self.domain.len()
            + self.domain_suffix.len()
            + self.domain_keyword.len()
            + self.domain_regex.len()
            + self.source_ip_cidr.len()
            + self.ip_cidr.len()
            + self.network.len()
            + self.source_port_range.len()
            + self.port_range.len()
            + self.process_name.len()
            + self.process_path.len()
            + self.process_path_regex.len()
    }

    pub fn rule_count(&self) -> usize {
        usize::from(!self.domain.is_empty() || !self.domain_suffix.is_empty())
            + usize::from(!self.domain_keyword.is_empty())
            + usize::from(!self.domain_regex.is_empty())
            + usize::from(!self.source_ip_cidr.is_empty())
            + usize::from(!self.ip_cidr.is_empty())
            + usize::from(!self.network.is_empty())
            + usize::from(!self.source_port_range.is_empty())
            + usize::from(!self.port_range.is_empty())
            + usize::from(!self.process_name.is_empty())
            + usize::from(!self.process_path.is_empty())
            + usize::from(!self.process_path_regex.is_empty())
    }

    pub fn to_rule_set_with_behavior(&self, behavior: BehaviorMode) -> RuleSet {
        let mut rule_set = self.to_rule_set();
        rule_set.keep_behavior(behavior);
        rule_set
    }

    pub fn to_rule_set(&self) -> RuleSet {
        let mut rules = Vec::with_capacity(self.rule_count());
        push_rule(&mut rules, |rule| {
            rule.domain = self.domain.to_strings();
            rule.domain_suffix = self.domain_suffix.to_strings();
        });
        push_rule(&mut rules, |rule| {
            rule.domain_keyword = self.domain_keyword.to_strings()
        });
        push_rule(&mut rules, |rule| {
            rule.domain_regex = self.domain_regex.to_strings()
        });
        push_rule(&mut rules, |rule| {
            rule.source_ip_cidr = self.source_ip_cidr.to_strings()
        });
        push_rule(&mut rules, |rule| rule.ip_cidr = self.ip_cidr.to_strings());
        push_rule(&mut rules, |rule| rule.network = self.network.to_strings());
        push_rule(&mut rules, |rule| {
            rule.source_port_range = self.source_port_range.to_strings()
        });
        push_rule(&mut rules, |rule| {
            rule.port_range = self.port_range.to_strings()
        });
        push_rule(&mut rules, |rule| {
            rule.process_name = self.process_name.to_strings()
        });
        push_rule(&mut rules, |rule| {
            rule.process_path = self.process_path.to_strings()
        });
        push_rule(&mut rules, |rule| {
            rule.process_path_regex = self.process_path_regex.to_strings()
        });

        RuleSet {
            version: VERSION_CURRENT,
            rules,
        }
    }
}
