mod behavior;
mod builder;
mod classical;
mod converter;
mod mode;
mod text_store;

pub use text_store::RuleTextStore;

pub use behavior::{BehaviorMode, InputBehaviorMode};
pub use builder::ConversionBuilder;
pub use classical::{
    ClassicalKind, ClassicalRule, classical_has_no_resolve, classical_to_domain,
    classical_to_ipcidr, classical_to_mixed_rule, classical_to_provider_rule, looks_classical,
};
pub use converter::Converter;
pub(crate) use mode::{ConversionMode, DomainSyntax};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuleTarget;
    use crate::codec::mihomo::mrs::RuleSetOutput;

    #[test]
    fn auto_routes_plain_domain_and_ipcidr_rules() {
        let rules = vec!["example.com".to_string(), "10.0.0.0/8".to_string()];

        let result = Converter::new(BehaviorMode::Auto).convert(&rules).unwrap();

        assert_eq!(result.outputs.len(), 2);
        assert!(matches!(result.outputs[0], RuleSetOutput::Domain(_)));
        assert!(matches!(result.outputs[1], RuleSetOutput::Ipcidr(_)));
    }

    #[test]
    fn auto_routes_classical_domain_and_ipcidr() {
        let rules = vec![
            "DOMAIN,example.com,DIRECT".to_string(),
            "DOMAIN-SUFFIX,example.net,PROXY".to_string(),
            "IP-CIDR,192.168.1.1/24,DIRECT,no-resolve".to_string(),
            "DOMAIN-WILDCARD,*.example.org,PROXY".to_string(),
            "DOMAIN-KEYWORD,ads,REJECT".to_string(),
        ];

        let result = Converter::new(BehaviorMode::Auto).convert(&rules).unwrap();
        assert_eq!(result.outputs.len(), 2);
        assert_eq!(result.skipped.len(), 2);
        assert!(matches!(result.outputs[0], RuleSetOutput::Domain(_)));
        assert!(matches!(result.outputs[1], RuleSetOutput::Ipcidr(_)));
        assert!(
            result
                .skipped
                .iter()
                .any(|item| item.rule.starts_with("DOMAIN-WILDCARD,"))
        );
    }

    #[test]
    fn classical_output_keeps_provider_rules_without_policy() {
        let rules = vec![
            "DOMAIN,example.com,DIRECT".to_string(),
            "DOMAIN-SUFFIX,example.net".to_string(),
            "IP-CIDR,192.168.1.0/24,DIRECT,no-resolve".to_string(),
            "DOMAIN-KEYWORD,ads,REJECT,extended-matching".to_string(),
            "USER-AGENT,Instagram*,DIRECT".to_string(),
        ];

        let result = Converter::new(BehaviorMode::Classical)
            .convert(&rules)
            .unwrap();

        assert_eq!(
            result.mixed_rules,
            vec![
                "DOMAIN,example.com",
                "DOMAIN-SUFFIX,example.net",
                "IP-CIDR,192.168.1.0/24,no-resolve",
                "DOMAIN-KEYWORD,ads,extended-matching",
                "USER-AGENT,Instagram*",
            ]
        );
        assert!(result.skipped.is_empty());
    }

    #[test]
    fn domain_behavior_keeps_domain_set_suffix_semantics() {
        let rules = vec![".example.com".to_string(), "static.example.net".to_string()];

        let result = Converter::new(BehaviorMode::Domain)
            .convert(&rules)
            .unwrap();

        assert_eq!(result.outputs.len(), 1);
        let RuleSetOutput::Domain(set) = &result.outputs[0] else {
            panic!("expected domain output");
        };
        assert_eq!(set.rules(), vec!["+.example.com", "static.example.net"]);
    }

    #[test]
    fn mihomo_domain_input_keeps_dot_as_subdomain_only() {
        let rules = vec![".example.com".to_string(), "+.example.net".to_string()];

        let result = Converter::with_input_context(
            InputBehaviorMode::Domain,
            RuleTarget::Mihomo,
            BehaviorMode::Domain,
        )
        .convert(&rules)
        .unwrap();

        let RuleSetOutput::Domain(set) = &result.outputs[0] else {
            panic!("expected domain output");
        };
        assert_eq!(set.rules(), vec![".example.com", "+.example.net"]);
    }

    #[test]
    fn auto_reads_generic_mixed_text_rules() {
        let rules = vec![
            "DOMAIN,example.com".to_string(),
            "IP-CIDR,203.0.113.0/24,no-resolve".to_string(),
        ];

        let result = Converter::new(BehaviorMode::Auto).convert(&rules).unwrap();

        assert_eq!(result.outputs.len(), 2);
        assert_eq!(
            result.mixed_rules,
            vec!["DOMAIN,example.com", "IP-CIDR,203.0.113.0/24,no-resolve"]
        );
        assert!(matches!(result.outputs[0], RuleSetOutput::Domain(_)));
        assert!(matches!(result.outputs[1], RuleSetOutput::Ipcidr(_)));
    }
}
