use std::net::IpAddr;

use anyhow::Result;

use super::rule::{rule_matches_domain, rule_matches_ip};
use super::{MatchQueryKind, MatchResult, MatchedRule};
use crate::codec::mihomo::mrs::{Behavior, RuleSetOutput};
use crate::input::DetectedInput;

pub(super) enum Query {
    Domain(String),
    Ip(IpAddr),
}

impl Query {
    fn value(&self) -> String {
        match self {
            Self::Domain(value) => value.clone(),
            Self::Ip(value) => value.to_string(),
        }
    }

    pub(super) fn kind(&self) -> MatchQueryKind {
        match self {
            Self::Domain(_) => MatchQueryKind::Domain,
            Self::Ip(_) => MatchQueryKind::Ip,
        }
    }
}

fn parse_query(query: &str) -> Query {
    let query = query.trim();
    if let Ok(ip) = query.parse::<IpAddr>() {
        return Query::Ip(ip);
    }
    Query::Domain(query.trim_end_matches('.').to_ascii_lowercase())
}

pub(super) struct MatchState {
    pub(super) query: Query,
    pub(super) rules: Vec<MatchedRule>,
}

impl MatchState {
    pub(super) fn new(query: &str) -> Self {
        Self {
            query: parse_query(query),
            rules: Vec::new(),
        }
    }

    pub(super) fn push_rule(&mut self, rule: &str, detected: DetectedInput) -> Result<()> {
        self.push_rule_with_context(rule, detected, "", "")
    }

    pub(super) fn push_rule_with_context(
        &mut self,
        rule: &str,
        detected: DetectedInput,
        source: &str,
        entry: &str,
    ) -> Result<()> {
        match &self.query {
            Query::Domain(domain) => {
                if rule_matches_domain(rule, domain, detected)? {
                    self.push_matched_rule_with_context(
                        Behavior::Domain,
                        rule.to_string(),
                        source,
                        entry,
                    );
                }
            }
            Query::Ip(ip) => {
                if rule_matches_ip(rule, *ip)? {
                    self.push_matched_rule_with_context(
                        Behavior::Ipcidr,
                        rule.to_string(),
                        source,
                        entry,
                    );
                }
            }
        }
        Ok(())
    }

    pub(super) fn push_matched_rule(&mut self, behavior: Behavior, rule: String) {
        self.push_matched_rule_with_context(behavior, rule, "", "");
    }

    fn push_matched_rule_with_context(
        &mut self,
        behavior: Behavior,
        rule: String,
        source: &str,
        entry: &str,
    ) {
        self.rules.push(MatchedRule {
            behavior,
            rule,
            source: non_empty(source),
            set: non_empty_lowercase(entry),
        });
    }

    pub(super) fn push_mrs_rule_set(&mut self, rule_set: &RuleSetOutput) -> usize {
        self.push_mrs_rule_set_with_context(rule_set, "", "")
    }

    pub(super) fn push_mrs_rule_set_with_context(
        &mut self,
        rule_set: &RuleSetOutput,
        source: &str,
        entry: &str,
    ) -> usize {
        let count = rule_set.count();
        match (&self.query, rule_set) {
            (Query::Domain(domain), RuleSetOutput::Domain(set)) if set.contains_domain(domain) => {
                self.rules.push(MatchedRule {
                    behavior: Behavior::Domain,
                    rule: domain.clone(),
                    source: non_empty(source),
                    set: non_empty_lowercase(entry),
                });
            }
            (Query::Ip(ip), RuleSetOutput::Ipcidr(set)) => {
                if let Some(rule) = set.matching_prefix(*ip) {
                    self.rules.push(MatchedRule {
                        behavior: Behavior::Ipcidr,
                        rule,
                        source: non_empty(source),
                        set: non_empty_lowercase(entry),
                    });
                }
            }
            _ => {}
        }
        count
    }

    pub(super) fn finish(self) -> MatchResult {
        MatchResult {
            matched: !self.rules.is_empty(),
            query: self.query.value(),
            kind: self.query.kind(),
            rules: self.rules,
        }
    }
}

fn non_empty(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn non_empty_lowercase(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_ascii_lowercase())
    }
}
