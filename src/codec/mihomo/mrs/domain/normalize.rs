use anyhow::{Result, bail};

pub fn normalize_domain_rule(mut rule: &str, mut f: impl FnMut(&str) -> Result<()>) -> Result<()> {
    rule = rule.trim();
    if rule.contains('/') {
        bail!("invalid domain contains `/`");
    }
    if rule.is_empty() || rule.ends_with('.') {
        bail!("invalid domain");
    }
    if rule.chars().next().is_some_and(char::is_whitespace)
        || rule.chars().next_back().is_some_and(char::is_whitespace)
    {
        bail!("invalid domain has surrounding whitespace");
    }

    let lower;
    let domain = if rule.bytes().any(|byte| byte.is_ascii_uppercase()) {
        lower = rule.to_ascii_lowercase();
        lower.as_str()
    } else {
        rule
    };

    if let Some(suffix) = domain.strip_prefix("+.") {
        validate_domain_tail(suffix, "invalid complex wildcard domain")?;
        f(suffix)?;
        let wildcard = format!("+.{suffix}");
        f(&wildcard)?;
    } else if let Some(suffix) = domain.strip_prefix('.') {
        validate_domain_tail(suffix, "invalid wildcard domain")?;
        let wildcard = format!("+.{suffix}");
        f(&wildcard)?;
    } else {
        validate_domain_tail(domain, "invalid domain")?;
        f(domain)?;
    }

    Ok(())
}

fn validate_domain_tail(domain: &str, empty_error: &str) -> Result<()> {
    if domain.is_empty() {
        bail!(empty_error.to_string());
    }
    if domain.as_bytes().contains(&0) {
        bail!("invalid domain");
    }
    if domain.split('.').any(str::is_empty) {
        bail!("invalid domain");
    }
    Ok(())
}

pub(super) fn reversed_key_to_rule_buf(reversed: &[u8], out: &mut String) -> bool {
    reversed_key_to_rule_buf_prefixed(reversed, "", out)
}

pub(super) fn reversed_key_to_rule_buf_prefixed(
    reversed: &[u8],
    prefix: &str,
    out: &mut String,
) -> bool {
    let Ok(reversed) = std::str::from_utf8(reversed) else {
        return false;
    };
    out.clear();
    out.push_str(prefix);
    out.extend(reversed.chars().rev());
    true
}
