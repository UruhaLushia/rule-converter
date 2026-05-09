use anyhow::Result;

use crate::api::SkippedRule;
use crate::codec::mihomo::mrs::parse_prefix;

use super::ConversionBuilder;
use crate::rules::{
    ClassicalKind, ClassicalRule, DomainSyntax, classical_has_no_resolve,
    classical_to_provider_rule, looks_classical,
};

impl ConversionBuilder {
    pub(super) fn push_sing_box_auto(
        &mut self,
        rule: &str,
        domain_syntax: DomainSyntax,
    ) -> Result<()> {
        if looks_classical(rule) {
            return self.push_sing_box_classical(rule);
        }

        if self.insert_cidr(rule).is_ok() {
            self.push_plain_mixed_ip_rule(rule);
            return Ok(());
        }

        self.push_sing_box_plain_domain_rule(rule, domain_syntax);
        Ok(())
    }

    pub(super) fn push_sing_box_domain(
        &mut self,
        rule: &str,
        domain_syntax: DomainSyntax,
    ) -> Result<()> {
        if looks_classical(rule) {
            let parsed = ClassicalRule::parse(rule);
            match parsed {
                Ok(parsed)
                    if matches!(
                        parsed.kind,
                        ClassicalKind::Domain | ClassicalKind::DomainSuffix
                    ) =>
                {
                    self.push_sing_box_classical(rule)
                }
                Ok(_) => {
                    self.skipped
                        .push(SkippedRule::new(rule, "not a domain rule"));
                    Ok(())
                }
                Err(err) => {
                    self.skipped.push(SkippedRule::new(rule, err.to_string()));
                    Ok(())
                }
            }
        } else {
            self.push_sing_box_plain_domain_rule(rule, domain_syntax);
            Ok(())
        }
    }

    pub(super) fn push_sing_box_ipcidr(&mut self, rule: &str) -> Result<()> {
        if looks_classical(rule) {
            let parsed = ClassicalRule::parse(rule);
            match parsed {
                Ok(parsed) if parsed.kind == ClassicalKind::Ipcidr => {
                    self.push_sing_box_classical(rule)
                }
                Ok(_) => {
                    self.skipped
                        .push(SkippedRule::new(rule, "not an ipcidr rule"));
                    Ok(())
                }
                Err(err) => {
                    self.skipped.push(SkippedRule::new(rule, err.to_string()));
                    Ok(())
                }
            }
        } else {
            match parse_prefix(rule) {
                Ok(_) => self.push_sing_box_ip_rule(rule),
                Err(err) => self.skipped.push(SkippedRule::new(rule, err.to_string())),
            }
            Ok(())
        }
    }

    pub(super) fn push_sing_box_classical(&mut self, rule: &str) -> Result<()> {
        self.no_resolve |= classical_has_no_resolve(rule);
        if let Some(store) = &mut self.sing_box_rules
            && store.push_classical(rule)
        {
            return Ok(());
        }

        match classical_to_provider_rule(rule) {
            Ok(Some(provider_rule)) => self.push_mixed_rule(provider_rule),
            Ok(None) => self.skipped.push(SkippedRule::new(
                rule,
                "unsupported rule-provider rule type",
            )),
            Err(err) => self.skipped.push(SkippedRule::new(rule, err.to_string())),
        }
        Ok(())
    }

    pub(super) fn push_sing_box_plain_domain_rule(&mut self, rule: &str, syntax: DomainSyntax) {
        match syntax {
            DomainSyntax::Generic => {
                if let Some(suffix) = rule.strip_prefix('.') {
                    self.push_sing_box_suffix_rule(suffix.trim_start_matches('.'));
                } else {
                    self.push_sing_box_exact_rule(rule);
                }
            }
            DomainSyntax::Mihomo => {
                if let Some(suffix) = rule.strip_prefix("+.") {
                    self.push_sing_box_suffix_rule(suffix);
                } else if rule.starts_with('.') {
                    self.push_sing_box_suffix_rule(rule);
                } else {
                    self.push_sing_box_exact_rule(rule);
                }
            }
        }
    }

    pub(super) fn push_sing_box_exact_rule(&mut self, rule: &str) {
        if let Some(store) = &mut self.sing_box_rules {
            store.push_domain(rule);
        } else {
            self.push_mixed_rule(format!("DOMAIN,{rule}"));
        }
    }

    pub(super) fn push_sing_box_suffix_rule(&mut self, rule: &str) {
        if let Some(store) = &mut self.sing_box_rules {
            store.push_domain_suffix(rule);
        } else {
            self.push_mixed_rule(format!("DOMAIN-SUFFIX,{rule}"));
        }
    }

    pub(super) fn push_sing_box_ip_rule(&mut self, rule: &str) {
        if let Some(store) = &mut self.sing_box_rules {
            store.push_ip_cidr(rule);
        } else {
            self.push_plain_mixed_ip_rule(rule);
        }
    }
}
