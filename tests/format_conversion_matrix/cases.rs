use rule_converter::{InputBehaviorMode, InputFormat, RuleTarget};

use super::render::render;
use super::types::{InputCase, OutputCase, RuleKind};

fn seed_input_cases() -> Vec<InputCase> {
    let domain_text = b"+.example.com\n.ads.example.net\nstatic.example.org\n".to_vec();
    let ip_text = b"192.0.2.0/24\n198.51.100.0/24\n2001:db8::/32\n".to_vec();
    let classical_text = b"DOMAIN,example.com\nDOMAIN-SUFFIX,example.net\nDOMAIN-KEYWORD,ads\nIP-CIDR,192.0.2.0/24,no-resolve\nIP-CIDR6,2001:db8::/32\nSRC-IP-CIDR,10.0.0.0/8\nDST-PORT,443\n".to_vec();

    vec![
        InputCase {
            from: "general",
            target: RuleTarget::General,
            format: InputFormat::Text,
            behavior: InputBehaviorMode::Domain,
            kind: RuleKind::Domain,
            payload: domain_text,
        },
        InputCase {
            from: "general",
            target: RuleTarget::General,
            format: InputFormat::Text,
            behavior: InputBehaviorMode::Ipcidr,
            kind: RuleKind::Ip,
            payload: ip_text,
        },
        InputCase {
            from: "general",
            target: RuleTarget::General,
            format: InputFormat::Text,
            behavior: InputBehaviorMode::Classical,
            kind: RuleKind::Classical,
            payload: classical_text,
        },
    ]
}

pub(super) fn derived_input_cases() -> Vec<InputCase> {
    let seeds = seed_input_cases();
    let domain = seeds
        .iter()
        .find(|input| input.kind == RuleKind::Domain)
        .unwrap()
        .clone();
    let ip = seeds
        .iter()
        .find(|input| input.kind == RuleKind::Ip)
        .unwrap()
        .clone();
    let classical = seeds
        .iter()
        .find(|input| input.kind == RuleKind::Classical)
        .unwrap()
        .clone();

    let mut inputs = seeds;
    let mut add = |source: &InputCase, output: OutputCase, target, format, behavior, kind| {
        inputs.push(InputCase {
            from: output.to,
            target,
            format,
            behavior,
            kind,
            payload: render(source, output).unwrap(),
        });
    };

    add(
        &domain,
        output_by_name("mihomo-text-domain"),
        RuleTarget::Mihomo,
        InputFormat::Text,
        InputBehaviorMode::Domain,
        RuleKind::Domain,
    );
    add(
        &ip,
        output_by_name("mihomo-text-ip"),
        RuleTarget::Mihomo,
        InputFormat::Text,
        InputBehaviorMode::Ipcidr,
        RuleKind::Ip,
    );
    add(
        &domain,
        output_by_name("mihomo-yaml-domain"),
        RuleTarget::Mihomo,
        InputFormat::Yaml,
        InputBehaviorMode::Domain,
        RuleKind::Domain,
    );
    add(
        &ip,
        output_by_name("mihomo-yaml-ip"),
        RuleTarget::Mihomo,
        InputFormat::Yaml,
        InputBehaviorMode::Ipcidr,
        RuleKind::Ip,
    );
    add(
        &classical,
        output_by_name("mihomo-yaml-classical"),
        RuleTarget::Mihomo,
        InputFormat::Yaml,
        InputBehaviorMode::Classical,
        RuleKind::Classical,
    );
    add(
        &domain,
        output_by_name("mihomo-mrs-domain"),
        RuleTarget::Mihomo,
        InputFormat::Mrs,
        InputBehaviorMode::Domain,
        RuleKind::Domain,
    );
    add(
        &ip,
        output_by_name("mihomo-mrs-ip"),
        RuleTarget::Mihomo,
        InputFormat::Mrs,
        InputBehaviorMode::Ipcidr,
        RuleKind::Ip,
    );
    add(
        &classical,
        output_by_name("egern-ruleset-classical"),
        RuleTarget::Egern,
        InputFormat::Yaml,
        InputBehaviorMode::Classical,
        RuleKind::Classical,
    );
    add(
        &classical,
        output_by_name("sing-json-classical"),
        RuleTarget::SingBox,
        InputFormat::Json,
        InputBehaviorMode::Classical,
        RuleKind::Classical,
    );
    add(
        &classical,
        output_by_name("sing-srs-classical"),
        RuleTarget::SingBox,
        InputFormat::Srs,
        InputBehaviorMode::Classical,
        RuleKind::Classical,
    );
    add(
        &domain,
        output_by_name("general-domainset"),
        RuleTarget::General,
        InputFormat::Text,
        InputBehaviorMode::Domain,
        RuleKind::Domain,
    );
    add(
        &ip,
        output_by_name("general-ipset"),
        RuleTarget::General,
        InputFormat::Text,
        InputBehaviorMode::Ipcidr,
        RuleKind::Ip,
    );
    add(
        &classical,
        output_by_name("general-ruleset-classical"),
        RuleTarget::General,
        InputFormat::Text,
        InputBehaviorMode::Classical,
        RuleKind::Classical,
    );

    inputs
}

fn output_by_name(name: &str) -> OutputCase {
    super::outputs::output_cases()
        .into_iter()
        .find(|output| output.name == name)
        .unwrap()
}
