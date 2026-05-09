use std::collections::HashMap;

use anyhow::Result;
use yaml_rust2::parser::Event;

pub(super) struct RuleSetExtractor<F> {
    f: F,
    pub(super) count: usize,
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
    pub(super) fn new(f: F) -> Self {
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

    pub(super) fn on_event(&mut self, event: Event) -> Result<()> {
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

    pub(super) fn finish(&mut self) -> Result<()> {
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
