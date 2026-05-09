use anyhow::Result;

use crate::codec::dat::proto::{Domain, DomainType, GeoSite};
use crate::codec::mihomo::mrs::DomainSetBuilder;
use crate::rules::{RuleTextStore, classical_to_provider_rule};

pub(super) fn push_geosite_entry(
    builder: &mut DomainSetBuilder,
    mixed_rules: &mut RuleTextStore,
    entry: &GeoSite,
) -> Result<()> {
    for domain in &entry.domain {
        match DomainType::try_from(domain.r#type).unwrap_or(DomainType::Plain) {
            DomainType::RootDomain => {
                let value = domain.value.trim();
                if !value.is_empty() {
                    let rule = format!("+.{value}");
                    builder.insert(&rule)?;
                    mixed_rules.push(format!("DOMAIN-SUFFIX,{value}"));
                }
            }
            DomainType::Full => {
                let value = domain.value.trim();
                if !value.is_empty() {
                    builder.insert(value)?;
                    mixed_rules.push(format!("DOMAIN,{value}"));
                }
            }
            DomainType::Plain => {
                let value = domain.value.trim();
                if !value.is_empty() {
                    mixed_rules.push(format!("DOMAIN-KEYWORD,{value}"));
                }
            }
            DomainType::Regex => {
                let value = domain.value.trim();
                if !value.is_empty() {
                    mixed_rules.push(format!("DOMAIN-REGEX,{value}"));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn domain_from_rule(rule: &str) -> Option<Domain> {
    let rule = rule.trim();
    if let Some(suffix) = rule.strip_prefix("+.") {
        return Some(domain(DomainType::RootDomain, suffix));
    }
    if let Some(suffix) = rule.strip_prefix('.') {
        return Some(domain(DomainType::RootDomain, suffix));
    }
    if rule.is_empty() {
        None
    } else {
        Some(domain(DomainType::Full, rule))
    }
}

pub(super) fn domain_from_mixed_rule(rule: &str) -> Result<Option<Domain>> {
    let Some(rule) = classical_to_provider_rule(rule)? else {
        return Ok(None);
    };
    let mut parts = rule.splitn(3, ',');
    let Some(kind) = parts.next() else {
        return Ok(None);
    };
    let Some(value) = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let item = match kind.to_ascii_uppercase().as_str() {
        "DOMAIN-KEYWORD" => Some(domain(DomainType::Plain, value)),
        "DOMAIN-REGEX" => Some(domain(DomainType::Regex, value)),
        "DOMAIN" | "DOMAIN-SUFFIX" => None,
        _ => None,
    };
    Ok(item)
}

fn domain(kind: DomainType, value: &str) -> Domain {
    Domain {
        r#type: kind as i32,
        value: value.to_string(),
        attribute: Vec::new(),
    }
}
