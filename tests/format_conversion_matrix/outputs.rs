use rule_converter::{BehaviorMode, OutputFormat, RuleTarget};

use super::types::{OutputCase, RuleKind};

pub(super) fn output_cases() -> Vec<OutputCase> {
    fn domain_or_classical(kind: RuleKind) -> bool {
        matches!(kind, RuleKind::Domain | RuleKind::Classical)
    }
    fn ip_or_classical(kind: RuleKind) -> bool {
        matches!(kind, RuleKind::Ip | RuleKind::Classical)
    }
    fn any(_: RuleKind) -> bool {
        true
    }
    fn classical(kind: RuleKind) -> bool {
        matches!(kind, RuleKind::Classical)
    }

    vec![
        OutputCase {
            name: "mihomo-mrs-domain",
            to: "mihomo-mrs-domain",
            target: RuleTarget::Mihomo,
            format: OutputFormat::Mrs,
            behavior: BehaviorMode::Domain,
            accepts: domain_or_classical,
        },
        OutputCase {
            name: "mihomo-mrs-ip",
            to: "mihomo-mrs-ip",
            target: RuleTarget::Mihomo,
            format: OutputFormat::Mrs,
            behavior: BehaviorMode::Ipcidr,
            accepts: ip_or_classical,
        },
        OutputCase {
            name: "mihomo-text-domain",
            to: "mihomo-text-domain",
            target: RuleTarget::Mihomo,
            format: OutputFormat::Text,
            behavior: BehaviorMode::Domain,
            accepts: domain_or_classical,
        },
        OutputCase {
            name: "mihomo-text-ip",
            to: "mihomo-text-ip",
            target: RuleTarget::Mihomo,
            format: OutputFormat::Text,
            behavior: BehaviorMode::Ipcidr,
            accepts: ip_or_classical,
        },
        OutputCase {
            name: "mihomo-text-classical",
            to: "mihomo-text-classical",
            target: RuleTarget::Mihomo,
            format: OutputFormat::Text,
            behavior: BehaviorMode::Classical,
            accepts: any,
        },
        OutputCase {
            name: "mihomo-yaml-domain",
            to: "mihomo-yaml-domain",
            target: RuleTarget::Mihomo,
            format: OutputFormat::Yaml,
            behavior: BehaviorMode::Domain,
            accepts: domain_or_classical,
        },
        OutputCase {
            name: "mihomo-yaml-ip",
            to: "mihomo-yaml-ip",
            target: RuleTarget::Mihomo,
            format: OutputFormat::Yaml,
            behavior: BehaviorMode::Ipcidr,
            accepts: ip_or_classical,
        },
        OutputCase {
            name: "mihomo-yaml-classical",
            to: "mihomo-yaml-classical",
            target: RuleTarget::Mihomo,
            format: OutputFormat::Yaml,
            behavior: BehaviorMode::Classical,
            accepts: any,
        },
        OutputCase {
            name: "general-domainset",
            to: "general-domainset",
            target: RuleTarget::General,
            format: OutputFormat::DomainSet,
            behavior: BehaviorMode::Domain,
            accepts: domain_or_classical,
        },
        OutputCase {
            name: "general-adguard",
            to: "general-adguard",
            target: RuleTarget::General,
            format: OutputFormat::Adguard,
            behavior: BehaviorMode::Domain,
            accepts: domain_or_classical,
        },
        OutputCase {
            name: "general-ipset",
            to: "general-ipset",
            target: RuleTarget::General,
            format: OutputFormat::IpSet,
            behavior: BehaviorMode::Ipcidr,
            accepts: ip_or_classical,
        },
        OutputCase {
            name: "general-ruleset-domain",
            to: "general-ruleset-domain",
            target: RuleTarget::General,
            format: OutputFormat::RuleSet,
            behavior: BehaviorMode::Domain,
            accepts: domain_or_classical,
        },
        OutputCase {
            name: "general-ruleset-ip",
            to: "general-ruleset-ip",
            target: RuleTarget::General,
            format: OutputFormat::RuleSet,
            behavior: BehaviorMode::Ipcidr,
            accepts: ip_or_classical,
        },
        OutputCase {
            name: "general-ruleset-classical",
            to: "general-ruleset-classical",
            target: RuleTarget::General,
            format: OutputFormat::RuleSet,
            behavior: BehaviorMode::Classical,
            accepts: any,
        },
        OutputCase {
            name: "egern-ruleset-domain",
            to: "egern-ruleset-domain",
            target: RuleTarget::Egern,
            format: OutputFormat::RuleSet,
            behavior: BehaviorMode::Domain,
            accepts: domain_or_classical,
        },
        OutputCase {
            name: "egern-ruleset-ip",
            to: "egern-ruleset-ip",
            target: RuleTarget::Egern,
            format: OutputFormat::RuleSet,
            behavior: BehaviorMode::Ipcidr,
            accepts: ip_or_classical,
        },
        OutputCase {
            name: "egern-ruleset-classical",
            to: "egern-ruleset-classical",
            target: RuleTarget::Egern,
            format: OutputFormat::RuleSet,
            behavior: BehaviorMode::Classical,
            accepts: any,
        },
        OutputCase {
            name: "sing-json-domain",
            to: "sing-box-json-domain",
            target: RuleTarget::SingBox,
            format: OutputFormat::Json,
            behavior: BehaviorMode::Domain,
            accepts: domain_or_classical,
        },
        OutputCase {
            name: "sing-json-ip",
            to: "sing-box-json-ip",
            target: RuleTarget::SingBox,
            format: OutputFormat::Json,
            behavior: BehaviorMode::Ipcidr,
            accepts: ip_or_classical,
        },
        OutputCase {
            name: "sing-json-classical",
            to: "sing-box-json-classical",
            target: RuleTarget::SingBox,
            format: OutputFormat::Json,
            behavior: BehaviorMode::Classical,
            accepts: classical,
        },
        OutputCase {
            name: "sing-srs-domain",
            to: "sing-box-srs-domain",
            target: RuleTarget::SingBox,
            format: OutputFormat::Srs,
            behavior: BehaviorMode::Domain,
            accepts: domain_or_classical,
        },
        OutputCase {
            name: "sing-srs-ip",
            to: "sing-box-srs-ip",
            target: RuleTarget::SingBox,
            format: OutputFormat::Srs,
            behavior: BehaviorMode::Ipcidr,
            accepts: ip_or_classical,
        },
        OutputCase {
            name: "sing-srs-classical",
            to: "sing-box-srs-classical",
            target: RuleTarget::SingBox,
            format: OutputFormat::Srs,
            behavior: BehaviorMode::Classical,
            accepts: classical,
        },
    ]
}
