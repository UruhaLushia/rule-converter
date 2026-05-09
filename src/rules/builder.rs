use anyhow::Result;

use crate::api::{ConvertResult, SkippedRule};
use crate::codec::mihomo::mrs::{DomainSetBuilder, IpCidrSetBuilder, RuleSetOutput, parse_prefix};
use crate::codec::sing_box::RuleStore;

mod classical;
mod mixed;
mod sing_box;

use super::{
    BehaviorMode, ConversionMode, DomainSyntax, RuleTextStore, classical_has_no_resolve,
    classical_to_domain, classical_to_ipcidr, classical_to_mixed_rule, looks_classical,
};

pub struct ConversionBuilder {
    mode: ConversionMode,
    output_behavior: BehaviorMode,
    saw_classical: bool,
    domains: DomainSetBuilder,
    cidrs: IpCidrSetBuilder,
    mixed_rules: RuleTextStore,
    keep_mixed_rules: bool,
    build_rule_sets: bool,
    domain_set_mixed_rules: bool,
    ip_set_mixed_rules: bool,
    sing_box_rules: Option<RuleStore>,
    skipped: Vec<SkippedRule>,
    no_resolve: bool,
}

impl ConversionBuilder {
    pub(crate) fn with_options(
        mode: ConversionMode,
        output_behavior: BehaviorMode,
        keep_mixed_rules: bool,
        build_rule_sets: bool,
        domain_set_mixed_rules: bool,
        ip_set_mixed_rules: bool,
    ) -> Self {
        Self {
            mode,
            output_behavior,
            saw_classical: false,
            domains: DomainSetBuilder::default(),
            cidrs: IpCidrSetBuilder::default(),
            mixed_rules: RuleTextStore::default(),
            keep_mixed_rules,
            build_rule_sets,
            domain_set_mixed_rules,
            ip_set_mixed_rules,
            sing_box_rules: if matches!(
                mode,
                ConversionMode::SingBoxAuto(_)
                    | ConversionMode::SingBoxDomain(_)
                    | ConversionMode::SingBoxIpcidr
            ) {
                Some(RuleStore::default())
            } else {
                None
            },
            skipped: Vec::new(),
            no_resolve: false,
        }
    }

    pub fn reserve(&mut self, items: usize, bytes: usize) {
        if items == 0 && bytes == 0 {
            return;
        }

        if self.keep_mixed_rules {
            self.mixed_rules.reserve(items, bytes);
        }

        match self.mode {
            ConversionMode::DomainSet
            | ConversionMode::DomainMihomo
            | ConversionMode::AutoGeneric
            | ConversionMode::AutoMihomo
            | ConversionMode::ClassicalAuto
                if self.build_rule_sets =>
            {
                self.domains.reserve(items, bytes);
            }
            ConversionMode::Ipcidr if self.build_rule_sets => {
                self.cidrs.reserve(items);
            }
            ConversionMode::ClassicalOutput if self.build_rule_sets => {
                self.domains.reserve(items / 2, bytes / 2);
                self.cidrs.reserve(items / 8);
            }
            ConversionMode::SingBoxDomain(_) => {
                if let Some(store) = &mut self.sing_box_rules {
                    store.reserve_domain(items, bytes);
                }
            }
            ConversionMode::SingBoxIpcidr => {
                if let Some(store) = &mut self.sing_box_rules {
                    store.reserve_ip_cidr(items, bytes);
                }
            }
            ConversionMode::SingBoxAuto(_) => {
                if let Some(store) = &mut self.sing_box_rules {
                    store.reserve_mixed(items, bytes);
                }
            }
            ConversionMode::DomainSet
            | ConversionMode::DomainMihomo
            | ConversionMode::Ipcidr
            | ConversionMode::AutoGeneric
            | ConversionMode::AutoMihomo
            | ConversionMode::ClassicalAuto
            | ConversionMode::ClassicalOutput => {}
        }
    }

    pub fn push(&mut self, rule: &str) -> Result<()> {
        if classical_has_no_resolve(rule) {
            self.no_resolve = true;
        }
        match self.mode {
            ConversionMode::AutoGeneric => self.push_auto(rule, DomainSyntax::Generic),
            ConversionMode::AutoMihomo => self.push_auto(rule, DomainSyntax::Mihomo),
            ConversionMode::DomainSet => self.push_domain(rule, DomainSyntax::Generic),
            ConversionMode::DomainMihomo => self.push_domain(rule, DomainSyntax::Mihomo),
            ConversionMode::Ipcidr => self.push_ipcidr(rule),
            ConversionMode::ClassicalOutput => self.push_classical(rule),
            ConversionMode::ClassicalAuto => self.push_classical_auto(rule),
            ConversionMode::SingBoxAuto(domain_syntax) => {
                self.push_sing_box_auto(rule, domain_syntax)
            }
            ConversionMode::SingBoxDomain(domain_syntax) => {
                self.push_sing_box_domain(rule, domain_syntax)
            }
            ConversionMode::SingBoxIpcidr => self.push_sing_box_ipcidr(rule),
        }
    }

    pub fn finish(self) -> Result<ConvertResult> {
        let mut outputs = Vec::new();
        if self.build_rule_sets {
            if !self.domains.is_empty() {
                outputs.push(RuleSetOutput::Domain(self.domains.finish()?));
            }
            if !self.cidrs.is_empty() {
                outputs.push(RuleSetOutput::Ipcidr(self.cidrs.finish()?));
            }
        }
        Ok(ConvertResult {
            outputs,
            mixed_rules: self.mixed_rules,
            sing_box_rules: self.sing_box_rules,
            output_behavior: self.output_behavior,
            no_resolve: self.no_resolve,
            skipped: self.skipped,
        })
    }

    fn push_auto(&mut self, rule: &str, domain_syntax: DomainSyntax) -> Result<()> {
        if looks_classical(rule) {
            self.saw_classical = true;
            if !self.build_rule_sets {
                return self.push_classical(rule);
            }
            return self.push_classical_auto(rule);
        }

        if self.saw_classical {
            if !self.build_rule_sets {
                return self.push_classical(rule);
            }
            return self.push_classical_auto(rule);
        }

        if self.insert_cidr(rule).is_ok() {
            self.push_sing_box_ip_rule(rule);
            return Ok(());
        }

        if let Err(err) = self.insert_domain(rule, domain_syntax) {
            self.skipped.push(SkippedRule::new(rule, err.to_string()));
        } else {
            self.push_plain_mixed_domain_rule(rule);
        }
        Ok(())
    }

    fn push_domain(&mut self, rule: &str, domain_syntax: DomainSyntax) -> Result<()> {
        let domain = if looks_classical(rule) {
            match classical_to_domain(rule) {
                Ok(Some(domain)) => domain,
                Ok(None) => {
                    self.skipped
                        .push(SkippedRule::new(rule, "not a domain rule"));
                    return Ok(());
                }
                Err(err) => {
                    self.skipped.push(SkippedRule::new(rule, err.to_string()));
                    return Ok(());
                }
            }
        } else {
            rule.to_string()
        };

        if let Err(err) = self.insert_domain(&domain, domain_syntax) {
            self.skipped.push(SkippedRule::new(rule, err.to_string()));
        } else if self.domain_set_mixed_rules {
            self.push_plain_mixed_domain_rule(&domain);
        } else if let Ok(Some(mixed)) = classical_to_mixed_rule(rule) {
            self.push_mixed_rule(mixed);
        } else {
            self.push_plain_mixed_domain_rule(&domain);
        }
        Ok(())
    }

    fn insert_domain(&mut self, rule: &str, syntax: DomainSyntax) -> Result<()> {
        if !self.build_rule_sets {
            return Ok(());
        }
        match syntax {
            DomainSyntax::Generic => self.domains.insert_domain_set(rule),
            DomainSyntax::Mihomo => self.domains.insert(rule),
        }
    }

    fn insert_cidr(&mut self, rule: &str) -> Result<()> {
        if !self.build_rule_sets {
            parse_prefix(rule)?;
            return Ok(());
        }
        self.cidrs.insert(rule)
    }

    fn push_ipcidr(&mut self, rule: &str) -> Result<()> {
        let cidr = if looks_classical(rule) {
            match classical_to_ipcidr(rule) {
                Ok(Some(cidr)) => cidr,
                Ok(None) => {
                    self.skipped
                        .push(SkippedRule::new(rule, "not an ipcidr rule"));
                    return Ok(());
                }
                Err(err) => {
                    self.skipped.push(SkippedRule::new(rule, err.to_string()));
                    return Ok(());
                }
            }
        } else {
            rule.to_string()
        };

        if let Err(err) = self.insert_cidr(&cidr) {
            self.skipped.push(SkippedRule::new(rule, err.to_string()));
        } else if self.ip_set_mixed_rules {
            self.push_plain_mixed_ip_rule(&cidr);
        } else if let Ok(Some(mixed)) = classical_to_mixed_rule(rule) {
            self.push_mixed_rule(mixed);
        } else {
            self.push_plain_mixed_ip_rule(&cidr);
        }
        Ok(())
    }
}
