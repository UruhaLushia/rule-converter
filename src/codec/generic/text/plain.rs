use std::io::BufRead;

use anyhow::{Context, Result};

use crate::codec::mihomo::mrs::Behavior;

pub fn parse_plain(raw: &[u8]) -> Result<Vec<String>> {
    let text = std::str::from_utf8(raw).context("failed to parse text rules as UTF-8")?;
    Ok(parse_lines(text))
}

pub fn parse_domain_set(raw: &[u8]) -> Result<Vec<String>> {
    let text = std::str::from_utf8(raw).context("failed to parse domain-set as UTF-8")?;
    Ok(text
        .lines()
        .enumerate()
        .filter_map(|(index, line)| normalize_domain_set_line(index, line))
        .collect())
}

pub(crate) fn parse_lines(text: &str) -> Vec<String> {
    text.lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let line = if index == 0 {
                line.trim_start_matches('\u{feff}')
            } else {
                line
            };
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                return None;
            }
            Some(line.to_string())
        })
        .collect()
}

pub fn for_each_plain_rule<R: BufRead>(
    reader: R,
    mut f: impl FnMut(&str) -> Result<()>,
) -> Result<usize> {
    let mut count = 0usize;
    for (index, line) in reader.lines().enumerate() {
        let line = line.context("failed to read text rule line")?;
        let line = if index == 0 {
            line.trim_start_matches('\u{feff}')
        } else {
            line.as_str()
        };
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        f(line)?;
        count += 1;
    }
    Ok(count)
}

pub fn for_each_domain_set_rule<R: BufRead>(
    reader: R,
    mut f: impl FnMut(&str) -> Result<()>,
) -> Result<usize> {
    let mut count = 0usize;
    for (index, line) in reader.lines().enumerate() {
        let line = line.context("failed to read domain-set line")?;
        if let Some(rule) = normalize_domain_set_line(index, &line) {
            f(&rule)?;
            count += 1;
        }
    }
    Ok(count)
}

fn normalize_domain_set_line(index: usize, line: &str) -> Option<String> {
    let line = if index == 0 {
        line.trim_start_matches('\u{feff}')
    } else {
        line
    };
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
        return None;
    }
    if line == "." {
        return None;
    }
    Some(line.to_string())
}

pub fn write_plain_rules<W, I, S>(mut writer: W, rules: I) -> std::io::Result<()>
where
    W: std::io::Write,
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    for rule in rules {
        writeln!(writer, "{}", rule.as_ref())?;
    }
    Ok(())
}

pub fn write_plain_rule<W: std::io::Write>(writer: &mut W, rule: &str) -> std::io::Result<()> {
    writeln!(writer, "{rule}")
}

pub fn write_typed_rule<W: std::io::Write>(
    writer: &mut W,
    behavior: Behavior,
    rule: &str,
) -> std::io::Result<()> {
    match behavior {
        Behavior::Domain => {
            if let Some(suffix) = rule.strip_prefix("+.") {
                writeln!(writer, "DOMAIN-SUFFIX,{suffix}")
            } else {
                writeln!(writer, "DOMAIN,{rule}")
            }
        }
        Behavior::Ipcidr => {
            let kind = if rule.contains(':') {
                "IP-CIDR6"
            } else {
                "IP-CIDR"
            };
            writeln!(writer, "{kind},{rule}")
        }
    }
}

pub fn write_domain_set_rule<W: std::io::Write>(writer: &mut W, rule: &str) -> std::io::Result<()> {
    if let Some(suffix) = rule.strip_prefix("+.") {
        writeln!(writer, ".{suffix}")
    } else {
        writeln!(writer, "{rule}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_one_rule_per_line_and_skips_comments() {
        let rules =
            parse_plain(b"\xef\xbb\xbf# comment\nDOMAIN,example.com\n\n// comment\n.abc.example\n")
                .unwrap();

        assert_eq!(rules, vec!["DOMAIN,example.com", ".abc.example"]);
    }

    #[test]
    fn parses_domain_set_suffix_lines() {
        let rules = parse_domain_set(b"# comment\n.example.com\nfoo.example\n").unwrap();

        assert_eq!(rules, vec![".example.com", "foo.example"]);
    }
}
