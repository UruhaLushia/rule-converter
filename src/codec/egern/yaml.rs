use std::collections::HashMap;
use std::io::{BufRead, Cursor, Write};

use anyhow::{Context, Result, bail};
use yaml_rust2::parser::{Event, Parser};

use crate::codec::mihomo::mrs::{Behavior, RuleSetOutput};

pub fn parse_ruleset(raw: &[u8]) -> Result<Vec<String>> {
    let mut rules = Vec::new();
    for_each_ruleset_rule(Cursor::new(raw), |rule| {
        rules.push(rule.to_string());
        Ok(())
    })?;
    Ok(rules)
}

pub fn for_each_ruleset_rule<R: BufRead>(
    reader: R,
    f: impl FnMut(&str) -> Result<()>,
) -> Result<usize> {
    let mut extractor = RuleSetExtractor::new(f);
    let mut chars = BufReadChars::new(reader);
    let mut parser = Parser::new(&mut chars);

    loop {
        let (event, _mark) = parser
            .next_token()
            .map_err(|err| anyhow::anyhow!("failed to parse Egern ruleset YAML: {err}"))?;
        let done = event == Event::StreamEnd;
        extractor.on_event(event)?;
        if done {
            break;
        }
    }
    extractor.finish()?;
    drop(parser);

    if let Some(err) = chars.error.take() {
        return Err(err);
    }

    if extractor.count == 0 {
        bail!("Egern ruleset must contain supported set fields");
    }
    Ok(extractor.count)
}

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

struct RuleSetExtractor<F> {
    f: F,
    count: usize,
    depth: usize,
    root_mapping_depth: Option<usize>,
    capture_sequence_depths: HashMap<usize, EgernSetKind>,
    pending_set: Option<EgernSetKind>,
    pending_no_resolve: bool,
    no_resolve: bool,
    pending_ip_rules: Vec<String>,
    awaiting_top_key: bool,
}

impl<F> RuleSetExtractor<F>
where
    F: FnMut(&str) -> Result<()>,
{
    fn new(f: F) -> Self {
        Self {
            f,
            count: 0,
            depth: 0,
            root_mapping_depth: None,
            capture_sequence_depths: HashMap::new(),
            pending_set: None,
            pending_no_resolve: false,
            no_resolve: false,
            pending_ip_rules: Vec::new(),
            awaiting_top_key: false,
        }
    }

    fn on_event(&mut self, event: Event) -> Result<()> {
        match event {
            Event::MappingStart(..) => {
                if self.root_mapping_depth.is_none() && self.depth == 0 {
                    self.root_mapping_depth = Some(self.depth + 1);
                    self.awaiting_top_key = true;
                } else if self.pending_set.take().is_some() || self.pending_no_resolve {
                    self.pending_no_resolve = false;
                    self.skip_top_value();
                }
                self.depth += 1;
            }
            Event::MappingEnd => {
                if self.root_mapping_depth == Some(self.depth) {
                    self.root_mapping_depth = None;
                    self.awaiting_top_key = false;
                }
                self.depth = self.depth.saturating_sub(1);
            }
            Event::SequenceStart(..) => {
                let next_depth = self.depth + 1;
                if let Some(kind) = self.pending_set.take() {
                    self.capture_sequence_depths.insert(next_depth, kind);
                    self.awaiting_top_key = false;
                }
                self.depth = next_depth;
            }
            Event::SequenceEnd => {
                self.capture_sequence_depths.remove(&self.depth);
                self.depth = self.depth.saturating_sub(1);
                if self.root_mapping_depth == Some(self.depth) {
                    self.awaiting_top_key = true;
                }
            }
            Event::Scalar(value, ..) => self.on_scalar(value)?,
            Event::Alias(_) => {
                if self.pending_set.take().is_some() || self.pending_no_resolve {
                    self.pending_no_resolve = false;
                    self.skip_top_value();
                }
            }
            Event::Nothing
            | Event::StreamStart
            | Event::StreamEnd
            | Event::DocumentStart
            | Event::DocumentEnd => {}
        }
        Ok(())
    }

    fn on_scalar(&mut self, value: String) -> Result<()> {
        if let Some(kind) = self.capture_sequence_depths.get(&self.depth).copied() {
            self.emit_rule(kind, &value)?;
            return Ok(());
        }

        if self.root_mapping_depth == Some(self.depth) {
            if self.awaiting_top_key {
                self.pending_set = EgernSetKind::parse(&value);
                self.pending_no_resolve = self.pending_set.is_none() && value == "no_resolve";
                self.awaiting_top_key = false;
            } else if let Some(kind) = self.pending_set.take() {
                self.emit_rule(kind, &value)?;
                self.awaiting_top_key = true;
            } else if self.pending_no_resolve {
                self.no_resolve = parse_yaml_bool(&value);
                self.pending_no_resolve = false;
                self.awaiting_top_key = true;
            } else {
                self.awaiting_top_key = true;
            }
        }

        Ok(())
    }

    fn emit_rule(&mut self, kind: EgernSetKind, value: &str) -> Result<()> {
        let value = value.trim();
        if value.is_empty() || value.starts_with('#') || value.starts_with("//") {
            return Ok(());
        }

        let rule = match kind {
            EgernSetKind::Domain => value.to_string(),
            EgernSetKind::DomainSuffix => format!("+.{}", value.trim_start_matches('.')),
            EgernSetKind::IpCidr => {
                self.pending_ip_rules.push(value.to_string());
                self.count += 1;
                return Ok(());
            }
        };
        (self.f)(&rule)?;
        self.count += 1;
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        for rule in self.pending_ip_rules.drain(..) {
            let kind = if rule.contains(':') {
                "IP-CIDR6"
            } else {
                "IP-CIDR"
            };
            if self.no_resolve {
                (self.f)(&format!("{kind},{rule},no-resolve"))?;
            } else {
                (self.f)(&rule)?;
            }
        }
        Ok(())
    }

    fn skip_top_value(&mut self) {
        self.awaiting_top_key = true;
    }
}

fn parse_yaml_bool(value: &str) -> bool {
    matches!(
        value.trim(),
        "true" | "True" | "TRUE" | "yes" | "Yes" | "YES" | "on" | "On" | "ON"
    )
}

#[derive(Clone, Copy)]
enum EgernSetKind {
    Domain,
    DomainSuffix,
    IpCidr,
}

impl EgernSetKind {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "domain_set" => Some(Self::Domain),
            "domain_suffix_set" => Some(Self::DomainSuffix),
            "ip_cidr_set" | "ip_cidr6_set" => Some(Self::IpCidr),
            _ => None,
        }
    }
}

struct BufReadChars<R> {
    reader: R,
    pending: Vec<char>,
    line: String,
    done: bool,
    error: Option<anyhow::Error>,
}

impl<R: BufRead> BufReadChars<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            pending: Vec::new(),
            line: String::new(),
            done: false,
            error: None,
        }
    }
}

impl<R: BufRead> Iterator for BufReadChars<R> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ch) = self.pending.pop() {
                return Some(ch);
            }
            if self.done {
                return None;
            }

            self.line.clear();
            match self.reader.read_line(&mut self.line) {
                Ok(0) => {
                    self.done = true;
                    return None;
                }
                Ok(_) => {
                    self.pending.extend(self.line.chars().rev());
                }
                Err(err) => {
                    self.error = Some(err)
                        .context("failed to read Egern ruleset input")
                        .err();
                    self.done = true;
                    return None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn parses_supported_egern_ruleset_fields() {
        let yaml = r#"
no_resolve: true
domain_set:
  - www.google.com
domain_keyword_set:
  - ignored
domain_suffix_set: [google.com, .youtube.com]
ip_cidr_set:
  - 192.168.0.0/16
ip_cidr6_set:
  - "2001:db8::/32"
"#;
        let mut rules = Vec::new();
        let count = for_each_ruleset_rule(Cursor::new(yaml), |rule| {
            rules.push(rule.to_string());
            Ok(())
        })
        .unwrap();

        assert_eq!(count, 5);
        assert_eq!(
            rules,
            vec![
                "www.google.com",
                "+.google.com",
                "+.youtube.com",
                "IP-CIDR,192.168.0.0/16,no-resolve",
                "IP-CIDR6,2001:db8::/32,no-resolve"
            ]
        );
    }
}
