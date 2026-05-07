use anyhow::{Result, anyhow};

use super::{ClassicalKind, ClassicalRule, option_start, parse_kind, split_top_level_commas};

pub fn looks_classical(rule: &str) -> bool {
    split_top_level_commas(rule)
        .first()
        .map(|head| parse_kind(head.trim()).is_some())
        .unwrap_or(false)
}

pub fn classical_to_domain(rule: &str) -> Result<Option<String>> {
    let parsed = ClassicalRule::parse(rule)?;
    let Some(payload) = parsed.payload else {
        return Ok(None);
    };

    match parsed.kind {
        ClassicalKind::Domain => Ok(Some(payload.to_string())),
        ClassicalKind::DomainSuffix if payload.starts_with('.') => Ok(Some(payload.to_string())),
        ClassicalKind::DomainSuffix => Ok(Some(format!("+.{}", payload.trim_start_matches('.')))),
        ClassicalKind::DomainWildcard
        | ClassicalKind::DomainKeyword
        | ClassicalKind::DomainRegex
        | ClassicalKind::Geosite => Ok(None),
        _ => Ok(None),
    }
}

pub fn classical_to_ipcidr(rule: &str) -> Result<Option<String>> {
    let parsed = ClassicalRule::parse(rule)?;
    let Some(payload) = parsed.payload else {
        return Ok(None);
    };

    match parsed.kind {
        ClassicalKind::Ipcidr => Ok(Some(payload.to_string())),
        ClassicalKind::SrcIpcidr | ClassicalKind::Geoip => Ok(None),
        _ => Ok(None),
    }
}

pub fn classical_to_mixed_rule(rule: &str) -> Result<Option<String>> {
    let parsed = ClassicalRule::parse(rule)?;
    let Some(payload) = parsed.payload else {
        return Ok(None);
    };

    match parsed.kind {
        ClassicalKind::Domain => Ok(Some(format!("DOMAIN,{payload}"))),
        ClassicalKind::DomainSuffix => Ok(Some(format!(
            "DOMAIN-SUFFIX,{}",
            payload.trim_start_matches('.')
        ))),
        ClassicalKind::Ipcidr => {
            let kind = if payload.contains(':') {
                "IP-CIDR6"
            } else {
                "IP-CIDR"
            };
            if parsed.no_resolve {
                Ok(Some(format!("{kind},{payload},no-resolve")))
            } else {
                Ok(Some(format!("{kind},{payload}")))
            }
        }
        _ => Ok(None),
    }
}

pub fn classical_to_provider_rule(rule: &str) -> Result<Option<String>> {
    let parsed = ClassicalRule::parse(rule)?;
    if matches!(parsed.kind, ClassicalKind::RuleSet | ClassicalKind::SubRule) {
        return Ok(None);
    }

    let fields = split_top_level_commas(rule);
    let kind = fields
        .first()
        .map(|field| field.trim())
        .filter(|field| !field.is_empty())
        .ok_or_else(|| anyhow!("empty classical rule type"))?;
    if parsed.kind == ClassicalKind::Match {
        return Ok(Some(kind.to_string()));
    }
    let payload = parsed.payload.expect("non-MATCH rules have payload");
    let option_start = option_start(&fields);

    let mut out = format!("{kind},{payload}");
    for option in fields.iter().skip(option_start).map(|part| part.trim()) {
        if !option.is_empty() {
            out.push(',');
            out.push_str(option);
        }
    }
    Ok(Some(out))
}

pub fn classical_has_no_resolve(rule: &str) -> bool {
    ClassicalRule::parse(rule)
        .map(|rule| rule.kind == ClassicalKind::Ipcidr && rule.no_resolve)
        .unwrap_or(false)
}
