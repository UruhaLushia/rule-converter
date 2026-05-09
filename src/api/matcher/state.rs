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
        match &self.query {
            Query::Domain(domain) => {
                if rule_matches_domain(rule, domain, detected)? {
                    self.push_matched_rule(Behavior::Domain, rule.to_string());
                }
            }
            Query::Ip(ip) => {
                if rule_matches_ip(rule, *ip)? {
                    self.push_matched_rule(Behavior::Ipcidr, rule.to_string());
                }
            }
        }
        Ok(())
    }

    pub(super) fn push_matched_rule(&mut self, behavior: Behavior, rule: String) {
        self.rules.push(MatchedRule { behavior, rule });
    }

    pub(super) fn push_mrs_rule_set(&mut self, rule_set: &RuleSetOutput) -> usize {
        let count = rule_set.count();
        match (&self.query, rule_set) {
            (Query::Domain(domain), RuleSetOutput::Domain(set)) if set.contains_domain(domain) => {
                self.rules.push(MatchedRule {
                    behavior: Behavior::Domain,
                    rule: domain.clone(),
                });
            }
            (Query::Ip(ip), RuleSetOutput::Ipcidr(set)) => {
                if let Some(rule) = set.matching_prefix(*ip) {
                    self.rules.push(MatchedRule {
                        behavior: Behavior::Ipcidr,
                        rule,
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
