use std::collections::HashSet;
use std::io::{BufRead, Cursor};

use anyhow::{Context, Result, bail};
use yaml_rust2::parser::{Event, Parser};

use super::chars::BufReadChars;

pub fn parse_yaml(raw: &[u8]) -> Result<Vec<String>> {
    let mut rules = Vec::new();
    for_each_yaml_rule(Cursor::new(raw), |rule| {
        rules.push(rule.to_string());
        Ok(())
    })?;
    Ok(rules)
}

pub fn for_each_yaml_rule<R: BufRead>(
    reader: R,
    f: impl FnMut(&str) -> Result<()>,
) -> Result<usize> {
    let mut extractor = RuleExtractor::new(f);
    let mut chars = BufReadChars::new(reader);
    let mut parser = Parser::new(&mut chars);

    loop {
        let (event, _mark) = parser
            .next_token()
            .map_err(|err| anyhow::anyhow!("failed to parse mihomo YAML: {err}"))?;
        let done = event == Event::StreamEnd;
        extractor.on_event(event)?;
        if done {
            break;
        }
    }
    drop(parser);

    if let Some(err) = chars.error.take() {
        return Err(err);
    }

    if extractor.count == 0 {
        bail!("YAML must contain top-level `payload` or `rules`");
    }
    Ok(extractor.count)
}

pub fn for_each_simple_yaml_rule<R: BufRead>(
    mut reader: R,
    mut f: impl FnMut(&str) -> Result<()>,
) -> Result<Option<usize>> {
    let mut line = String::new();
    let mut count = 0usize;
    let mut in_rules = false;
    let mut rules_indent = 0usize;

    loop {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .context("failed to read mihomo YAML input")?;
        if read == 0 {
            break;
        }

        let trimmed_end = line.trim_end_matches(['\r', '\n']);
        let trimmed = trimmed_end.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let indent = trimmed_end.len() - trimmed.len();
        if !in_rules {
            if indent == 0 && matches!(trimmed, "payload:" | "rules:") {
                in_rules = true;
                rules_indent = indent;
                continue;
            }
            return Ok(None);
        }

        if indent <= rules_indent && !trimmed.starts_with('-') {
            if indent == 0 && matches!(trimmed, "payload:" | "rules:") {
                rules_indent = indent;
                continue;
            }
            return Ok(None);
        }

        let Some(rest) = trimmed.strip_prefix('-') else {
            return Ok(None);
        };
        let rule = rest.trim_start();
        if rule.is_empty()
            || rule.starts_with('#')
            || rule.starts_with('"')
            || rule.starts_with('\'')
            || rule.starts_with('[')
            || rule.contains(" #")
        {
            return Ok(None);
        }
        f(rule)?;
        count += 1;
    }

    if count == 0 {
        return Ok(None);
    }
    Ok(Some(count))
}

struct RuleExtractor<F> {
    f: F,
    count: usize,
    depth: usize,
    root_mapping_depth: Option<usize>,
    root_sequence_depth: Option<usize>,
    capture_sequence_depths: HashSet<usize>,
    pending_top_key: Option<TopRuleKey>,
    awaiting_top_key: bool,
}

impl<F> RuleExtractor<F>
where
    F: FnMut(&str) -> Result<()>,
{
    fn new(f: F) -> Self {
        Self {
            f,
            count: 0,
            depth: 0,
            root_mapping_depth: None,
            root_sequence_depth: None,
            capture_sequence_depths: HashSet::new(),
            pending_top_key: None,
            awaiting_top_key: false,
        }
    }

    fn on_event(&mut self, event: Event) -> Result<()> {
        match event {
            Event::MappingStart(..) => {
                if self.root_mapping_depth.is_none() && self.depth == 0 {
                    self.root_mapping_depth = Some(self.depth + 1);
                    self.awaiting_top_key = true;
                } else if self.pending_top_key.take().is_some() {
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
                if self.depth == 0 {
                    self.root_sequence_depth = Some(next_depth);
                } else if self.pending_top_key.take().is_some() {
                    self.capture_sequence_depths.insert(next_depth);
                    self.awaiting_top_key = false;
                }
                self.depth = next_depth;
            }
            Event::SequenceEnd => {
                self.capture_sequence_depths.remove(&self.depth);
                if self.root_sequence_depth == Some(self.depth) {
                    self.root_sequence_depth = None;
                }
                self.depth = self.depth.saturating_sub(1);
            }
            Event::Scalar(value, ..) => self.on_scalar(value)?,
            Event::Alias(_) => {
                if self.pending_top_key.take().is_some() {
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
        if self.root_sequence_depth == Some(self.depth)
            || self.capture_sequence_depths.contains(&self.depth)
        {
            self.emit_rule(&value)?;
            return Ok(());
        }

        if self.root_mapping_depth == Some(self.depth) {
            if self.awaiting_top_key {
                self.pending_top_key = TopRuleKey::parse(&value);
                self.awaiting_top_key = false;
            } else if self.pending_top_key.take().is_some() {
                self.emit_rule(&value)?;
                self.awaiting_top_key = true;
            } else {
                self.awaiting_top_key = true;
            }
        }

        Ok(())
    }

    fn emit_rule(&mut self, value: &str) -> Result<()> {
        let value = value.trim();
        if value.is_empty() || value.starts_with('#') || value.starts_with("//") {
            return Ok(());
        }
        (self.f)(value)?;
        self.count += 1;
        Ok(())
    }

    fn skip_top_value(&mut self) {
        self.awaiting_top_key = true;
    }
}

#[derive(Clone, Copy)]
enum TopRuleKey {
    Payload,
    Rules,
}

impl TopRuleKey {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "payload" => Some(Self::Payload),
            "rules" => Some(Self::Rules),
            _ => None,
        }
    }
}
