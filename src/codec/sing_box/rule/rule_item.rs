use crate::codec::mihomo::mrs::RuleSetOutput;
use crate::rules::{BehaviorMode, ClassicalKind, ClassicalRule};

use super::Rule;

pub(super) fn push_rule(rules: &mut Vec<Rule>, f: impl FnOnce(&mut Rule)) {
    let mut rule = Rule::default();
    f(&mut rule);
    if !rule.is_empty() {
        rules.push(rule);
    }
}

impl Rule {
    pub fn from_classical(rule: &str) -> Option<Self> {
        Self::from_classical_with_behavior(rule, BehaviorMode::Classical)
    }

    pub fn from_classical_with_behavior(rule: &str, behavior: BehaviorMode) -> Option<Self> {
        let parsed = ClassicalRule::parse(rule).ok()?;
        let payload = parsed.payload.unwrap_or_default();
        let mut out = Rule::default();
        match parsed.kind {
            ClassicalKind::Domain => out.domain.push(payload.into()),
            ClassicalKind::DomainSuffix => out.domain_suffix.push(payload.into()),
            ClassicalKind::DomainKeyword => out.domain_keyword.push(payload.into()),
            ClassicalKind::DomainRegex => out.domain_regex.push(payload.into()),
            ClassicalKind::Ipcidr => out.ip_cidr.push(payload.into()),
            ClassicalKind::SrcIpcidr | ClassicalKind::SrcIp => {
                out.source_ip_cidr.push(payload.into())
            }
            ClassicalKind::Network => out.network.push(payload.into()),
            ClassicalKind::DstPort => out.port_range.push(payload.into()),
            ClassicalKind::SrcPort => out.source_port_range.push(payload.into()),
            ClassicalKind::ProcessName => out.process_name.push(payload.into()),
            ClassicalKind::ProcessPath => out.process_path.push(payload.into()),
            ClassicalKind::ProcessPathRegex => out.process_path_regex.push(payload.into()),
            _ => return None,
        }
        if out.matches_behavior(behavior) {
            Some(out)
        } else {
            None
        }
    }

    pub fn matches_behavior(&self, behavior: BehaviorMode) -> bool {
        match behavior {
            BehaviorMode::Domain => self.has_domain_items(),
            BehaviorMode::Ipcidr => self.has_ip_items(),
            BehaviorMode::Auto | BehaviorMode::Classical => true,
        }
    }

    pub(super) fn has_domain_items(&self) -> bool {
        !self.domain.is_empty()
            || !self.domain_suffix.is_empty()
            || !self.domain_keyword.is_empty()
            || !self.domain_regex.is_empty()
    }

    pub(super) fn has_ip_items(&self) -> bool {
        !self.source_ip_cidr.is_empty() || !self.ip_cidr.is_empty()
    }

    pub fn is_empty(&self) -> bool {
        self.item_count() == 0
    }

    pub fn item_count(&self) -> usize {
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
            + self.package_name.len()
            + self.package_name_regex.len()
    }

    pub(super) fn push_classical_rules(&self, out: &mut Vec<String>) {
        extend_prefixed(out, "DOMAIN", &self.domain);
        extend_prefixed(out, "DOMAIN-SUFFIX", &self.domain_suffix);
        extend_prefixed(out, "DOMAIN-KEYWORD", &self.domain_keyword);
        extend_prefixed(out, "DOMAIN-REGEX", &self.domain_regex);
        extend_prefixed(out, "SRC-IP-CIDR", &self.source_ip_cidr);
        extend_prefixed(out, "IP-CIDR", &self.ip_cidr);
        extend_prefixed(out, "NETWORK", &self.network);
        extend_prefixed(out, "SRC-PORT", &self.source_port_range);
        extend_prefixed(out, "DST-PORT", &self.port_range);
        extend_prefixed(out, "PROCESS-NAME", &self.process_name);
        extend_prefixed(out, "PROCESS-PATH", &self.process_path);
        extend_prefixed(out, "PROCESS-PATH-REGEX", &self.process_path_regex);
        extend_prefixed(out, "PROCESS-NAME", &self.package_name);
        extend_prefixed(out, "PROCESS-NAME-REGEX", &self.package_name_regex);
    }

    pub(super) fn for_each_classical_rule(
        &self,
        f: &mut impl FnMut(&str) -> anyhow::Result<()>,
    ) -> anyhow::Result<usize> {
        let mut count = 0usize;
        extend_prefixed_each(&mut count, f, "DOMAIN", &self.domain)?;
        extend_prefixed_each(&mut count, f, "DOMAIN-SUFFIX", &self.domain_suffix)?;
        extend_prefixed_each(&mut count, f, "DOMAIN-KEYWORD", &self.domain_keyword)?;
        extend_prefixed_each(&mut count, f, "DOMAIN-REGEX", &self.domain_regex)?;
        extend_prefixed_each(&mut count, f, "SRC-IP-CIDR", &self.source_ip_cidr)?;
        extend_prefixed_each(&mut count, f, "IP-CIDR", &self.ip_cidr)?;
        extend_prefixed_each(&mut count, f, "NETWORK", &self.network)?;
        extend_prefixed_each(&mut count, f, "SRC-PORT", &self.source_port_range)?;
        extend_prefixed_each(&mut count, f, "DST-PORT", &self.port_range)?;
        extend_prefixed_each(&mut count, f, "PROCESS-NAME", &self.process_name)?;
        extend_prefixed_each(&mut count, f, "PROCESS-PATH", &self.process_path)?;
        extend_prefixed_each(
            &mut count,
            f,
            "PROCESS-PATH-REGEX",
            &self.process_path_regex,
        )?;
        extend_prefixed_each(&mut count, f, "PROCESS-NAME", &self.package_name)?;
        extend_prefixed_each(
            &mut count,
            f,
            "PROCESS-NAME-REGEX",
            &self.package_name_regex,
        )?;
        Ok(count)
    }

    pub(crate) fn into_each_classical_rule(
        self,
        f: &mut impl FnMut(&str) -> anyhow::Result<()>,
    ) -> anyhow::Result<usize> {
        let Rule {
            rule_type: _,
            domain,
            domain_suffix,
            domain_keyword,
            domain_regex,
            source_ip_cidr,
            ip_cidr,
            network,
            source_port_range,
            port_range,
            process_name,
            process_path,
            process_path_regex,
            package_name,
            package_name_regex,
            invert: _,
        } = self;

        let mut count = 0usize;
        extend_prefixed_into_each(&mut count, f, "DOMAIN", domain)?;
        extend_prefixed_into_each(&mut count, f, "DOMAIN-SUFFIX", domain_suffix)?;
        extend_prefixed_into_each(&mut count, f, "DOMAIN-KEYWORD", domain_keyword)?;
        extend_prefixed_into_each(&mut count, f, "DOMAIN-REGEX", domain_regex)?;
        extend_prefixed_into_each(&mut count, f, "SRC-IP-CIDR", source_ip_cidr)?;
        extend_prefixed_into_each(&mut count, f, "IP-CIDR", ip_cidr)?;
        extend_prefixed_into_each(&mut count, f, "NETWORK", network)?;
        extend_prefixed_into_each(&mut count, f, "SRC-PORT", source_port_range)?;
        extend_prefixed_into_each(&mut count, f, "DST-PORT", port_range)?;
        extend_prefixed_into_each(&mut count, f, "PROCESS-NAME", process_name)?;
        extend_prefixed_into_each(&mut count, f, "PROCESS-PATH", process_path)?;
        extend_prefixed_into_each(&mut count, f, "PROCESS-PATH-REGEX", process_path_regex)?;
        extend_prefixed_into_each(&mut count, f, "PROCESS-NAME", package_name)?;
        extend_prefixed_into_each(&mut count, f, "PROCESS-NAME-REGEX", package_name_regex)?;
        Ok(count)
    }
}

pub(super) fn rule_set_output_matches_behavior(
    output: &RuleSetOutput,
    behavior: BehaviorMode,
) -> bool {
    match behavior {
        BehaviorMode::Domain => matches!(output, RuleSetOutput::Domain(_)),
        BehaviorMode::Ipcidr => matches!(output, RuleSetOutput::Ipcidr(_)),
        BehaviorMode::Auto | BehaviorMode::Classical => true,
    }
}

pub(super) fn sing_box_domain_suffix(rule: &str) -> String {
    if let Some(suffix) = rule.strip_prefix("+.") {
        suffix.to_string()
    } else {
        rule.to_string()
    }
}

fn extend_prefixed(out: &mut Vec<String>, kind: &str, values: &[String]) {
    out.extend(values.iter().map(|value| format!("{kind},{value}")));
}

fn extend_prefixed_each(
    count: &mut usize,
    f: &mut impl FnMut(&str) -> anyhow::Result<()>,
    kind: &str,
    values: &[String],
) -> anyhow::Result<()> {
    for value in values {
        let mut rule = String::with_capacity(kind.len() + 1 + value.len());
        rule.push_str(kind);
        rule.push(',');
        rule.push_str(value);
        f(&rule)?;
        *count += 1;
    }
    Ok(())
}

fn extend_prefixed_into_each(
    count: &mut usize,
    f: &mut impl FnMut(&str) -> anyhow::Result<()>,
    kind: &str,
    values: Vec<String>,
) -> anyhow::Result<()> {
    for value in values {
        let mut rule = String::with_capacity(kind.len() + 1 + value.len());
        rule.push_str(kind);
        rule.push(',');
        rule.push_str(&value);
        f(&rule)?;
        *count += 1;
    }
    Ok(())
}
