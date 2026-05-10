use std::borrow::Cow;
use std::net::IpAddr;

use anyhow::Result;
use regex::Regex;

use crate::RuleTarget;
use crate::codec::mihomo::mrs::prefix_contains_ip;
use crate::input::DetectedInput;
use crate::rules::{BehaviorMode, ClassicalKind};

pub(super) fn rule_matches_domain(
    rule: &str,
    domain: &str,
    detected: DetectedInput,
) -> Result<bool> {
    if let Some(parsed) = parse_match_rule(rule) {
        return parsed_rule_matches_domain(parsed, domain);
    }
    if has_classical_marker(rule)
        || matches!(detected.behavior, BehaviorMode::Ipcidr)
        || prefix_contains_ip_query(rule).is_some()
    {
        return Ok(false);
    }
    Ok(plain_domain_rule_matches(rule, domain, detected.target))
}

pub(super) fn rule_matches_ip(rule: &str, ip: IpAddr) -> Result<bool> {
    if let Some(parsed) = parse_match_rule(rule) {
        return parsed_rule_matches_ip(parsed, ip);
    }
    if has_classical_marker(rule) {
        return Ok(false);
    }
    prefix_contains_ip(rule, ip)
}

#[derive(Clone, Copy)]
pub(super) struct ParsedMatchRule<'a> {
    pub(super) kind: ClassicalKind,
    pub(super) payload: Option<&'a str>,
}

pub(super) fn parse_match_rule(rule: &str) -> Option<ParsedMatchRule<'_>> {
    let (kind, rest) = split_first_top_level_field(rule);
    let kind = parse_match_kind(kind.trim())?;
    let payload = if kind == ClassicalKind::Match {
        None
    } else {
        let (payload, _) = split_first_top_level_field(rest?);
        Some(payload.trim()).filter(|value| !value.is_empty())
    };
    Some(ParsedMatchRule { kind, payload })
}

fn split_first_top_level_field(value: &str) -> (&str, Option<&str>) {
    let mut depth = 0usize;
    for (index, ch) in value.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => return (&value[..index], Some(&value[index + ch.len_utf8()..])),
            _ => {}
        }
    }
    (value, None)
}

fn parse_match_kind(value: &str) -> Option<ClassicalKind> {
    if value.eq_ignore_ascii_case("DOMAIN") {
        Some(ClassicalKind::Domain)
    } else if value.eq_ignore_ascii_case("DOMAIN-SUFFIX") {
        Some(ClassicalKind::DomainSuffix)
    } else if value.eq_ignore_ascii_case("DOMAIN-KEYWORD") {
        Some(ClassicalKind::DomainKeyword)
    } else if value.eq_ignore_ascii_case("DOMAIN-REGEX") {
        Some(ClassicalKind::DomainRegex)
    } else if value.eq_ignore_ascii_case("DOMAIN-WILDCARD") {
        Some(ClassicalKind::DomainWildcard)
    } else if value.eq_ignore_ascii_case("IP-CIDR") || value.eq_ignore_ascii_case("IP-CIDR6") {
        Some(ClassicalKind::Ipcidr)
    } else if value.eq_ignore_ascii_case("SRC-IP-CIDR") {
        Some(ClassicalKind::SrcIpcidr)
    } else if value.eq_ignore_ascii_case("RULE-SET") {
        Some(ClassicalKind::RuleSet)
    } else if value.eq_ignore_ascii_case("MATCH") {
        Some(ClassicalKind::Match)
    } else {
        None
    }
}

fn has_classical_marker(rule: &str) -> bool {
    let (kind, rest) = split_first_top_level_field(rule);
    let kind = kind.trim();
    rest.is_some()
        && !kind.is_empty()
        && kind
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && kind
            .bytes()
            .any(|byte| byte.is_ascii_uppercase() || byte == b'-')
}

fn prefix_contains_ip_query(rule: &str) -> Option<()> {
    rule.trim().split_once('/')?;
    Some(())
}

fn plain_domain_rule_matches(rule: &str, domain: &str, target: RuleTarget) -> bool {
    let rule = normalize_domain_text(rule);
    let rule = rule.as_ref();
    if rule.is_empty() {
        return false;
    }
    if target == RuleTarget::Mihomo {
        if let Some(suffix) = rule.strip_prefix("+.") {
            return domain_matches_suffix(domain, suffix);
        }
        if let Some(suffix) = rule.strip_prefix('.') {
            return domain
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.') && !prefix.is_empty());
        }
        return domain == rule;
    }
    if let Some(suffix) = rule.strip_prefix("+.").or_else(|| rule.strip_prefix('.')) {
        return domain_matches_suffix(domain, suffix);
    }
    domain == rule
}

fn parsed_rule_matches_domain(parsed: ParsedMatchRule<'_>, domain: &str) -> Result<bool> {
    let Some(payload) = parsed.payload else {
        return Ok(false);
    };
    let payload = normalize_domain_text(payload);
    let payload = payload.as_ref();

    match parsed.kind {
        ClassicalKind::Domain => Ok(domain == payload),
        ClassicalKind::DomainSuffix => Ok(domain_matches_suffix(domain, payload)),
        ClassicalKind::DomainKeyword => Ok(domain.contains(payload)),
        ClassicalKind::DomainRegex => {
            Ok(Regex::new(payload).is_ok_and(|regex| regex.is_match(domain)))
        }
        ClassicalKind::DomainWildcard => Ok(wildcard_match(payload, domain)),
        _ => Ok(false),
    }
}

fn parsed_rule_matches_ip(parsed: ParsedMatchRule<'_>, ip: IpAddr) -> Result<bool> {
    let Some(payload) = parsed.payload else {
        return Ok(false);
    };
    match parsed.kind {
        ClassicalKind::Ipcidr | ClassicalKind::SrcIpcidr => prefix_contains_ip(payload.trim(), ip),
        _ => Ok(false),
    }
}

fn normalize_domain_text(value: &str) -> Cow<'_, str> {
    let value = value.trim().trim_end_matches('.');
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(value.to_ascii_lowercase())
    } else {
        Cow::Borrowed(value)
    }
}

fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    let suffix = suffix.trim_start_matches('.');
    domain == suffix
        || domain
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut p, mut v) = (0usize, 0usize);
    let mut star = None;
    let mut star_match = 0usize;

    while v < value.len() {
        if p < pattern.len() && (pattern[p] == value[v] || pattern[p] == b'?') {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            star_match = v;
        } else if let Some(star_pos) = star {
            p = star_pos + 1;
            star_match += 1;
            v = star_match;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}
