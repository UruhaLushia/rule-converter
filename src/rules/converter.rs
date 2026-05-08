use anyhow::Result;

use crate::RuleTarget;
use crate::api::{ConvertResult, SkippedRule};
use crate::codec::mihomo::mrs::{IpCidrSetBuilder, RuleSetOutput};
use crate::rules::RuleTextStore;

use super::{
    BehaviorMode, ConversionBuilder, ConversionMode, DomainSyntax, InputBehaviorMode,
    classical_to_ipcidr, looks_classical,
};

pub struct Converter {
    mode: ConversionMode,
    output_behavior: BehaviorMode,
    keep_mixed_rules: bool,
}

impl Converter {
    pub fn new(output_behavior: BehaviorMode) -> Self {
        Self {
            mode: ConversionMode::from_output_behavior(output_behavior),
            output_behavior,
            keep_mixed_rules: true,
        }
    }

    pub fn with_input_context(
        input_behavior: InputBehaviorMode,
        input_target: RuleTarget,
        output_behavior: BehaviorMode,
    ) -> Self {
        Self {
            mode: ConversionMode::from_input_output(input_behavior, input_target, output_behavior),
            output_behavior,
            keep_mixed_rules: true,
        }
    }

    pub fn for_sing_box_output(
        input_behavior: InputBehaviorMode,
        input_target: RuleTarget,
        output_behavior: BehaviorMode,
    ) -> Self {
        let domain_syntax = if input_target == RuleTarget::General {
            DomainSyntax::Generic
        } else {
            DomainSyntax::Mihomo
        };

        let mode = match output_behavior {
            BehaviorMode::Domain => ConversionMode::SingBoxDomain(domain_syntax),
            BehaviorMode::Ipcidr => ConversionMode::SingBoxIpcidr,
            BehaviorMode::Classical => ConversionMode::SingBoxAuto(domain_syntax),
            BehaviorMode::Auto => match input_behavior {
                InputBehaviorMode::Ipcidr => ConversionMode::SingBoxIpcidr,
                InputBehaviorMode::Domain => ConversionMode::SingBoxDomain(domain_syntax),
                InputBehaviorMode::Auto | InputBehaviorMode::Classical => {
                    ConversionMode::SingBoxAuto(domain_syntax)
                }
            },
        };

        Self {
            mode,
            output_behavior,
            keep_mixed_rules: true,
        }
    }

    pub fn convert(&self, rules: &[String]) -> Result<ConvertResult> {
        match self.mode {
            ConversionMode::AutoGeneric | ConversionMode::AutoMihomo => self.convert_auto(rules),
            ConversionMode::DomainSet | ConversionMode::DomainMihomo => self.convert_domain(rules),
            ConversionMode::Ipcidr => self.convert_ipcidr(rules),
            ConversionMode::ClassicalOutput => self.convert_classical(rules),
            ConversionMode::ClassicalAuto => self.convert_auto(rules),
            ConversionMode::SingBoxAuto(_)
            | ConversionMode::SingBoxDomain(_)
            | ConversionMode::SingBoxIpcidr => self.convert_auto(rules),
        }
    }

    pub fn builder(&self) -> ConversionBuilder {
        ConversionBuilder::with_options(
            self.mode,
            self.output_behavior,
            self.keep_mixed_rules,
            true,
            false,
            false,
        )
    }

    pub fn builder_with_options(
        &self,
        keep_mixed_rules: bool,
        build_rule_sets: bool,
        domain_set_mixed_rules: bool,
        ip_set_mixed_rules: bool,
    ) -> ConversionBuilder {
        ConversionBuilder::with_options(
            self.mode,
            self.output_behavior,
            keep_mixed_rules,
            build_rule_sets,
            domain_set_mixed_rules,
            ip_set_mixed_rules,
        )
    }

    fn convert_auto(&self, rules: &[String]) -> Result<ConvertResult> {
        let mut builder = self.builder();
        for rule in rules {
            builder.push(rule)?;
        }
        builder.finish()
    }

    fn convert_domain(&self, rules: &[String]) -> Result<ConvertResult> {
        let mut builder = self.builder();
        for rule in rules {
            builder.push(rule)?;
        }
        builder.finish()
    }

    fn convert_ipcidr(&self, rules: &[String]) -> Result<ConvertResult> {
        let mut builder = IpCidrSetBuilder::default();
        let mut skipped = Vec::new();

        for rule in rules {
            let cidr = if looks_classical(rule) {
                match classical_to_ipcidr(rule) {
                    Ok(Some(cidr)) => cidr,
                    Ok(None) => {
                        skipped.push(SkippedRule::new(rule, "not an ipcidr rule"));
                        continue;
                    }
                    Err(err) => {
                        skipped.push(SkippedRule::new(rule, err.to_string()));
                        continue;
                    }
                }
            } else {
                rule.clone()
            };

            if let Err(err) = builder.insert(&cidr) {
                skipped.push(SkippedRule::new(rule, err.to_string()));
            }
        }

        let mut outputs = Vec::new();
        if !builder.is_empty() {
            outputs.push(RuleSetOutput::Ipcidr(builder.finish()?));
        }
        Ok(ConvertResult {
            outputs,
            mixed_rules: RuleTextStore::default(),
            sing_box_rules: None,
            output_behavior: self.output_behavior,
            no_resolve: false,
            skipped,
        })
    }

    fn convert_classical(&self, rules: &[String]) -> Result<ConvertResult> {
        let mut builder = self.builder();
        for rule in rules {
            builder.push(rule)?;
        }
        builder.finish()
    }
}
