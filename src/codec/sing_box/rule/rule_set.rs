use crate::codec::mihomo::mrs::RuleSetOutput;
use crate::rules::{BehaviorMode, RuleTextStore};

use super::rule_item::{rule_set_output_matches_behavior, sing_box_domain_suffix};
use super::{Rule, RuleSet, VERSION_CURRENT};

impl RuleSet {
    pub fn from_outputs(
        outputs: &[RuleSetOutput],
        mixed_rules: &RuleTextStore,
        _behavior: BehaviorMode,
    ) -> Self {
        let mut rules = Vec::new();
        if !mixed_rules.is_empty() {
            for rule in mixed_rules.iter() {
                if let Some(rule) = Rule::from_classical_with_behavior(rule, _behavior) {
                    rules.push(rule);
                }
            }
        }

        if rules.is_empty() {
            for output in outputs {
                if !rule_set_output_matches_behavior(output, _behavior) {
                    continue;
                }
                match output {
                    RuleSetOutput::Domain(domain) => {
                        let mut rule = Rule::default();
                        let _ = domain.for_each_exact_rule(|value| {
                            rule.domain.push(value.to_string());
                            Ok(())
                        });
                        let _ = domain.for_each_suffix_rule(|value| {
                            rule.domain_suffix.push(sing_box_domain_suffix(value));
                            Ok(())
                        });
                        if !rule.is_empty() {
                            rules.push(rule);
                        }
                    }
                    RuleSetOutput::Ipcidr(ipcidr) => {
                        let mut rule = Rule::default();
                        let _ = ipcidr.for_each_rule(|value| {
                            rule.ip_cidr.push(value.to_string());
                            Ok(())
                        });
                        if !rule.is_empty() {
                            rules.push(rule);
                        }
                    }
                }
            }
        }

        Self {
            version: VERSION_CURRENT,
            rules,
        }
    }

    pub fn to_classical_rules(&self) -> Vec<String> {
        let mut out = Vec::new();
        for rule in &self.rules {
            rule.push_classical_rules(&mut out);
        }
        out
    }

    pub fn for_each_classical_rule(
        &self,
        mut f: impl FnMut(&str) -> anyhow::Result<()>,
    ) -> anyhow::Result<usize> {
        let mut count = 0usize;
        for rule in &self.rules {
            count += rule.for_each_classical_rule(&mut f)?;
        }
        Ok(count)
    }

    pub fn into_each_classical_rule(
        self,
        mut f: impl FnMut(&str) -> anyhow::Result<()>,
    ) -> anyhow::Result<usize> {
        let mut count = 0usize;
        for rule in self.rules {
            count += rule.into_each_classical_rule(&mut f)?;
        }
        Ok(count)
    }

    pub fn count(&self) -> usize {
        self.rules.iter().map(Rule::item_count).sum()
    }

    pub fn has_domain_rules(&self) -> bool {
        self.rules.iter().any(Rule::has_domain_items)
    }

    pub fn has_ip_rules(&self) -> bool {
        self.rules.iter().any(Rule::has_ip_items)
    }

    pub fn keep_behavior(&mut self, behavior: BehaviorMode) {
        match behavior {
            BehaviorMode::Domain => self.rules.retain(Rule::has_domain_items),
            BehaviorMode::Ipcidr => self.rules.retain(Rule::has_ip_items),
            BehaviorMode::Auto | BehaviorMode::Classical => {}
        }
    }
}
