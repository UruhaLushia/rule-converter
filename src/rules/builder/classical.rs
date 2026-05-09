use anyhow::Result;

use crate::api::SkippedRule;

use super::ConversionBuilder;
use crate::rules::{
    DomainSyntax, classical_has_no_resolve, classical_to_domain, classical_to_ipcidr,
    classical_to_mixed_rule, classical_to_provider_rule, looks_classical,
};

impl ConversionBuilder {
    pub(super) fn push_classical(&mut self, rule: &str) -> Result<()> {
        self.no_resolve |= classical_has_no_resolve(rule);
        if looks_classical(rule) {
            match classical_to_provider_rule(rule) {
                Ok(Some(provider_rule)) => self.push_mixed_rule(provider_rule),
                Ok(None) => {
                    self.skipped.push(SkippedRule::new(
                        rule,
                        "unsupported rule-provider rule type",
                    ));
                    return Ok(());
                }
                Err(err) => {
                    self.skipped.push(SkippedRule::new(rule, err.to_string()));
                    return Ok(());
                }
            }

            if !self.build_rule_sets {
                return Ok(());
            }
            if let Ok(Some(domain)) = classical_to_domain(rule)
                && let Err(err) = self.domains.insert(&domain)
            {
                self.skipped.push(SkippedRule::new(rule, err.to_string()));
            }
            if let Ok(Some(cidr)) = classical_to_ipcidr(rule)
                && let Err(err) = self.insert_cidr(&cidr)
            {
                self.skipped.push(SkippedRule::new(rule, err.to_string()));
            }
            return Ok(());
        }

        if self.insert_cidr(rule).is_ok() {
            self.push_plain_mixed_ip_rule(rule);
            return Ok(());
        }

        if let Err(err) = self.insert_domain(rule, DomainSyntax::Generic) {
            self.skipped.push(SkippedRule::new(rule, err.to_string()));
        } else {
            self.push_plain_mixed_domain_rule(rule);
        }
        Ok(())
    }

    pub(super) fn push_classical_auto(&mut self, rule: &str) -> Result<()> {
        self.no_resolve |= classical_has_no_resolve(rule);
        if !self.build_rule_sets {
            match classical_to_provider_rule(rule) {
                Ok(Some(provider_rule)) => self.push_mixed_rule(provider_rule),
                Ok(None) => self.skipped.push(SkippedRule::new(
                    rule,
                    "unsupported rule-provider rule type",
                )),
                Err(err) => self.skipped.push(SkippedRule::new(rule, err.to_string())),
            }
            return Ok(());
        }

        match classical_to_domain(rule) {
            Ok(Some(domain)) => {
                if let Err(err) = self.domains.insert(&domain) {
                    self.skipped.push(SkippedRule::new(rule, err.to_string()));
                } else if let Ok(Some(mixed)) = classical_to_mixed_rule(rule) {
                    self.push_mixed_rule(mixed);
                }
                return Ok(());
            }
            Ok(None) => {}
            Err(err) => {
                self.skipped.push(SkippedRule::new(rule, err.to_string()));
                return Ok(());
            }
        }

        match classical_to_ipcidr(rule) {
            Ok(Some(cidr)) => {
                if let Err(err) = self.insert_cidr(&cidr) {
                    self.skipped.push(SkippedRule::new(rule, err.to_string()));
                } else if let Ok(Some(mixed)) = classical_to_mixed_rule(rule) {
                    self.push_mixed_rule(mixed);
                }
            }
            Ok(None) => self
                .skipped
                .push(SkippedRule::new(rule, "unsupported classical rule type")),
            Err(err) => self.skipped.push(SkippedRule::new(rule, err.to_string())),
        }
        Ok(())
    }
}
