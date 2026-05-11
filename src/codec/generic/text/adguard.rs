use std::io::BufRead;
use std::net::IpAddr;

use anyhow::{Context, Result};

pub fn parse_adguard(raw: &[u8]) -> Result<Vec<String>> {
    let text = std::str::from_utf8(raw).context("failed to parse AdGuard filter as UTF-8")?;
    Ok(parse_lines(text))
}

pub fn parse_lines(text: &str) -> Vec<String> {
    text.lines()
        .enumerate()
        .filter_map(|(index, line)| normalize_adguard_line(index, line))
        .collect()
}

pub fn for_each_adguard_rule<R: BufRead>(
    mut reader: R,
    mut f: impl FnMut(&str) -> Result<()>,
) -> Result<usize> {
    let mut count = 0usize;
    let mut line = String::new();
    let mut index = 0usize;
    loop {
        line.clear();
        if reader
            .read_line(&mut line)
            .context("failed to read AdGuard filter line")?
            == 0
        {
            break;
        }
        if let Some(rule) = normalize_adguard_line(index, &line) {
            f(&rule)?;
            count += 1;
        }
        index += 1;
    }
    Ok(count)
}

pub fn looks_like_adguard_line(line: &str) -> bool {
    let line = line.trim();
    line.starts_with("||")
        || line.starts_with("@@")
        || line.starts_with('|')
        || line.ends_with('^')
        || parse_hosts_line(line).is_some()
}

pub fn write_adguard_domain_rule<W: std::io::Write>(
    writer: &mut W,
    rule: &str,
) -> std::io::Result<()> {
    let rule = rule.trim().trim_end_matches('.');
    if let Some(suffix) = rule.strip_prefix("+.") {
        writeln!(writer, "||{}^", suffix.trim_start_matches('.'))
    } else if let Some(suffix) = rule.strip_prefix('.') {
        writeln!(writer, "|*.{}^", suffix.trim_start_matches('.'))
    } else {
        writeln!(writer, "|{rule}^")
    }
}

fn normalize_adguard_line(index: usize, line: &str) -> Option<String> {
    let line = if index == 0 {
        line.trim_start_matches('\u{feff}')
    } else {
        line
    };
    let line = line.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('#') {
        return None;
    }
    if let Some(domain) = parse_hosts_line(line) {
        return Some(format!("DOMAIN,{domain}"));
    }
    normalize_filter_line(line)
}

fn parse_hosts_line(line: &str) -> Option<&str> {
    let mut parts = line.split_whitespace();
    let address = parts.next()?.parse::<IpAddr>().ok()?;
    if !address.is_unspecified() {
        return None;
    }
    let domain = parts.next()?;
    valid_domain(domain).then_some(domain)
}

fn normalize_filter_line(line: &str) -> Option<String> {
    let mut line = line.trim();
    if line.starts_with("@@") {
        return None;
    }
    if let Some((rule, modifiers)) = split_modifiers(line) {
        if !modifiers_supported(modifiers) {
            return None;
        }
        line = rule.trim_end_matches('|').trim();
    }
    line = line.trim_end_matches('|').trim();

    let (line, suffix, exact_start) = if let Some(rest) = line.strip_prefix("||") {
        (rest, true, false)
    } else if let Some(rest) = line.strip_prefix('|') {
        (rest, false, true)
    } else {
        (line, false, false)
    };
    let (line, exact_end) = line
        .strip_suffix('^')
        .map_or((line, false), |rest| (rest, true));

    if line.starts_with('/') && line.ends_with('/') && line.len() > 2 {
        return Some(format!("DOMAIN-REGEX,{}", &line[1..line.len() - 1]));
    }

    let line = line.split_once("://").map_or(line, |(_, rest)| rest);
    if line.contains('/') || line.contains("##") || line.contains("#$#") || line.is_empty() {
        return None;
    }
    if line.parse::<IpAddr>().is_ok() || looks_like_ip_prefix(line) {
        return None;
    }
    if line.contains('*') {
        return wildcard_to_rule(line, exact_start, exact_end);
    }
    let domain = line.trim_end_matches('.');
    if !valid_domain(domain) {
        return None;
    }
    if suffix {
        Some(format!("DOMAIN-SUFFIX,{domain}"))
    } else {
        Some(format!("DOMAIN,{domain}"))
    }
}

fn split_modifiers(line: &str) -> Option<(&str, &str)> {
    if line.starts_with('/') {
        return None;
    }
    line.split_once('$')
}

fn modifiers_supported(modifiers: &str) -> bool {
    modifiers.split(',').all(|modifier| {
        if modifier == "important" {
            return true;
        }
        modifier.strip_prefix("dnsrewrite=").is_some_and(|value| {
            value
                .parse::<IpAddr>()
                .is_ok_and(|addr| addr.is_unspecified())
        })
    })
}

fn wildcard_to_rule(line: &str, exact_start: bool, exact_end: bool) -> Option<String> {
    let mut value = String::new();
    if exact_start {
        value.push('^');
    }
    for ch in line.chars() {
        match ch {
            '*' => value.push_str(".*"),
            '.' => value.push_str("\\."),
            other if is_regex_meta(other) => {
                value.push('\\');
                value.push(other);
            }
            other => value.push(other),
        }
    }
    if exact_end {
        value.push('$');
    }
    Some(format!("DOMAIN-REGEX,{value}"))
}

fn is_regex_meta(ch: char) -> bool {
    matches!(
        ch,
        '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$' | '\\'
    )
}

fn valid_domain(value: &str) -> bool {
    let value = value.trim_end_matches('.');
    !value.is_empty()
        && value.contains('.')
        && value.len() <= 253
        && value.split('.').all(valid_domain_label)
}

fn valid_domain_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn looks_like_ip_prefix(value: &str) -> bool {
    let mut saw_dot = false;
    value.split('.').all(|part| {
        saw_dot = true;
        part.is_empty() || part.parse::<u8>().is_ok()
    }) && saw_dot
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_adguard_rules() {
        let rules = parse_adguard(
            b"! comment\n||example.com^\n|exact.example^\n0.0.0.0 hosts.example\n@@||allow.example^\n/ads[0-9]+/\n",
        )
        .unwrap();

        assert_eq!(
            rules,
            vec![
                "DOMAIN-SUFFIX,example.com",
                "DOMAIN,exact.example",
                "DOMAIN,hosts.example",
                "DOMAIN-REGEX,ads[0-9]+",
            ]
        );
    }

    #[test]
    fn writes_domain_rules_as_adguard_filter() {
        let mut out = Vec::new();
        write_adguard_domain_rule(&mut out, "+.example.com").unwrap();
        write_adguard_domain_rule(&mut out, "exact.example").unwrap();

        assert_eq!(
            String::from_utf8(out).unwrap(),
            "||example.com^\n|exact.example^\n"
        );
    }
}
