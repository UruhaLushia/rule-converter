use rule_converter::{
    BehaviorMode, ConvertOptions, InputBehaviorMode, InputFormat, OutputFormat, RuleTarget,
    convert_payload, write_outputs_as_to_memory_owned,
};

#[derive(Clone)]
struct InputCase {
    from: &'static str,
    target: RuleTarget,
    format: InputFormat,
    behavior: InputBehaviorMode,
    kind: RuleKind,
    payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RuleKind {
    Domain,
    Ip,
    Classical,
}

#[derive(Clone, Copy)]
struct OutputCase {
    name: &'static str,
    to: &'static str,
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
    accepts: fn(RuleKind) -> bool,
}

fn options(
    input: &InputCase,
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> ConvertOptions {
    ConvertOptions {
        input_target: Some(input.target),
        input_format: Some(input.format),
        input_behavior: input.behavior,
        output_target: target,
        output_format: format,
        output_behavior: behavior,
    }
}

fn render(input: &InputCase, output: OutputCase) -> anyhow::Result<Vec<u8>> {
    let result = convert_payload(
        &input.payload,
        options(input, output.target, output.format, output.behavior),
    )?;
    let (outputs, _) = write_outputs_as_to_memory_owned(result, output.target, output.format)?;
    anyhow::ensure!(
        !outputs.is_empty(),
        "{} did not produce output",
        case_name(input, output)
    );
    Ok(outputs
        .into_iter()
        .flat_map(|output| output.bytes)
        .collect())
}

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

fn output_cases() -> Vec<OutputCase> {
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

fn derived_input_cases() -> Vec<InputCase> {
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
    output_cases()
        .into_iter()
        .find(|output| output.name == name)
        .unwrap()
}

fn case_name(input: &InputCase, output: OutputCase) -> String {
    case_name_from_parts(input.from, output)
}

fn case_name_from_parts(from: &str, output: OutputCase) -> String {
    format!("{from}-to-{}", output.to)
}

#[test]
fn format_conversion_matrix() {
    let inputs = derived_input_cases();
    let outputs = output_cases();
    let mut checked = 0usize;

    for input in &inputs {
        for output in &outputs {
            if !(output.accepts)(input.kind) {
                continue;
            }

            let bytes = render(input, *output)
                .unwrap_or_else(|error| panic!("{} failed: {error:?}", case_name(input, *output)));
            assert!(
                !bytes.is_empty(),
                "{} produced empty bytes",
                case_name(input, *output)
            );
            checked += 1;
        }
    }

    assert!(checked > 0);
}
