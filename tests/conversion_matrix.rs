use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use rule_converter::{
    BehaviorMode, ConvertOptions, InputBehaviorMode, InputFormat, OutputFormat, RuleTarget,
    convert_payload, write_outputs_as,
};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

fn options(
    input_target: RuleTarget,
    input_format: InputFormat,
    input_behavior: InputBehaviorMode,
    output_target: RuleTarget,
    output_format: OutputFormat,
    output_behavior: BehaviorMode,
) -> ConvertOptions {
    ConvertOptions {
        input_target: Some(input_target),
        input_format: Some(input_format),
        input_behavior,
        output_target,
        output_format,
        output_behavior,
    }
}

fn temp_dir() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "rule-converter-matrix-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn read_lines(path: &Path) -> BTreeSet<String> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[test]
fn general_domain_set_to_mihomo_text_expands_dot_to_plus_dot() {
    let dir = temp_dir();
    let output = dir.join("domain.list");
    let result = convert_payload(
        ".example.com\nstatic.example.net\n",
        options(
            RuleTarget::General,
            InputFormat::Text,
            InputBehaviorMode::Domain,
            RuleTarget::Mihomo,
            OutputFormat::Text,
            BehaviorMode::Domain,
        ),
    )
    .unwrap();

    write_outputs_as(&result, &output, RuleTarget::Mihomo, OutputFormat::Text).unwrap();

    assert_eq!(
        read_lines(&output),
        BTreeSet::from([
            "+.example.com".to_string(),
            "static.example.net".to_string()
        ])
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn mihomo_domain_text_preserves_dot_and_plus_dot_semantics() {
    let dir = temp_dir();
    let output = dir.join("domain.list");
    let result = convert_payload(
        ".example.com\n+.example.net\nstatic.example.org\n",
        options(
            RuleTarget::Mihomo,
            InputFormat::Text,
            InputBehaviorMode::Domain,
            RuleTarget::Mihomo,
            OutputFormat::Text,
            BehaviorMode::Domain,
        ),
    )
    .unwrap();

    write_outputs_as(&result, &output, RuleTarget::Mihomo, OutputFormat::Text).unwrap();

    assert_eq!(
        read_lines(&output),
        BTreeSet::from([
            ".example.com".to_string(),
            "+.example.net".to_string(),
            "static.example.org".to_string()
        ])
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn mihomo_domain_text_to_general_domain_set_is_lossy_for_subdomain_only_dot() {
    let dir = temp_dir();
    let output = dir.join("domain.list");
    let result = convert_payload(
        ".example.com\n+.example.net\nstatic.example.org\n",
        options(
            RuleTarget::Mihomo,
            InputFormat::Text,
            InputBehaviorMode::Domain,
            RuleTarget::General,
            OutputFormat::DomainSet,
            BehaviorMode::Domain,
        ),
    )
    .unwrap();

    write_outputs_as(
        &result,
        &output,
        RuleTarget::General,
        OutputFormat::DomainSet,
    )
    .unwrap();

    assert_eq!(
        read_lines(&output),
        BTreeSet::from([
            ".example.com".to_string(),
            ".example.net".to_string(),
            "static.example.org".to_string()
        ])
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn mihomo_domain_text_to_general_classical_text_is_lossy_for_subdomain_only_dot() {
    let dir = temp_dir();
    let output = dir.join("rules.list");
    let result = convert_payload(
        ".example.com\n+.example.net\nstatic.example.org\n",
        options(
            RuleTarget::Mihomo,
            InputFormat::Text,
            InputBehaviorMode::Domain,
            RuleTarget::General,
            OutputFormat::RuleSet,
            BehaviorMode::Classical,
        ),
    )
    .unwrap();

    write_outputs_as(&result, &output, RuleTarget::General, OutputFormat::RuleSet).unwrap();

    assert_eq!(
        read_lines(&output),
        BTreeSet::from([
            "DOMAIN-SUFFIX,example.com".to_string(),
            "DOMAIN-SUFFIX,example.net".to_string(),
            "DOMAIN,static.example.org".to_string()
        ])
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn route_style_classical_to_provider_text_strips_policy_and_keeps_parameters() {
    let dir = temp_dir();
    let output = dir.join("rules.list");
    let result = convert_payload(
        "payload:\n  - DOMAIN,example.com,DIRECT\n  - IP-CIDR,192.0.2.0/24,REJECT,no-resolve\n  - DOMAIN-KEYWORD,ads,PROXY,extended-matching\n",
        options(
            RuleTarget::Mihomo,
            InputFormat::Yaml,
            InputBehaviorMode::Classical,
            RuleTarget::General,
            OutputFormat::RuleSet,
            BehaviorMode::Classical,
        ),
    )
    .unwrap();

    write_outputs_as(&result, &output, RuleTarget::General, OutputFormat::RuleSet).unwrap();

    assert_eq!(
        read_lines(&output),
        BTreeSet::from([
            "DOMAIN,example.com".to_string(),
            "IP-CIDR,192.0.2.0/24,no-resolve".to_string(),
            "DOMAIN-KEYWORD,ads,extended-matching".to_string(),
        ])
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn mixed_ip_no_resolve_is_preserved_when_writing_egern_yaml() {
    let dir = temp_dir();
    let output = dir.join("egern.yaml");
    let result = convert_payload(
        "IP-CIDR,203.0.113.0/24,no-resolve\n",
        options(
            RuleTarget::General,
            InputFormat::Text,
            InputBehaviorMode::Classical,
            RuleTarget::Egern,
            OutputFormat::RuleSet,
            BehaviorMode::Ipcidr,
        ),
    )
    .unwrap();

    write_outputs_as(&result, &output, RuleTarget::Egern, OutputFormat::RuleSet).unwrap();
    let yaml = fs::read_to_string(&output).unwrap();

    assert!(yaml.contains("no_resolve: true"));
    assert!(yaml.contains("ip_cidr_set:"));
    assert!(yaml.contains("\"203.0.113.0/24\""));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn domain_mrs_skips_rules_mrs_cannot_represent() {
    let result = convert_payload(
        "payload:\n  - DOMAIN,example.com\n  - DOMAIN-KEYWORD,ads\n  - DOMAIN-WILDCARD,*.example.net\n",
        options(
            RuleTarget::Mihomo,
            InputFormat::Yaml,
            InputBehaviorMode::Classical,
            RuleTarget::Mihomo,
            OutputFormat::Mrs,
            BehaviorMode::Domain,
        ),
    )
    .unwrap();

    assert_eq!(result.outputs.len(), 1);
    assert_eq!(result.skipped.len(), 2);
    assert!(
        result
            .skipped
            .iter()
            .any(|item| item.rule == "DOMAIN-KEYWORD,ads")
    );
    assert!(
        result
            .skipped
            .iter()
            .any(|item| item.rule == "DOMAIN-WILDCARD,*.example.net")
    );
}

#[test]
fn mrs_rejects_classical_output_behavior() {
    let dir = temp_dir();
    let output = dir.join("rules.mrs");
    let result = convert_payload(
        "DOMAIN,example.com\n",
        options(
            RuleTarget::General,
            InputFormat::Text,
            InputBehaviorMode::Classical,
            RuleTarget::Mihomo,
            OutputFormat::Mrs,
            BehaviorMode::Classical,
        ),
    )
    .unwrap();

    let err = write_outputs_as(&result, &output, RuleTarget::Mihomo, OutputFormat::Mrs)
        .expect_err("classical output must not be accepted by MRS writer");

    assert!(err.to_string().contains("does not support classical"));
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn classical_text_to_sing_box_json_preserves_supported_items() {
    let dir = temp_dir();
    let output = dir.join("rules.json");
    let result = convert_payload(
        "DOMAIN,example.com\nDOMAIN-SUFFIX,example.net\nDOMAIN-KEYWORD,ads\nDOMAIN-REGEX,^foo\nIP-CIDR,192.0.2.0/24\nSRC-IP-CIDR,10.0.0.0/8\n",
        options(
            RuleTarget::General,
            InputFormat::Text,
            InputBehaviorMode::Classical,
            RuleTarget::SingBox,
            OutputFormat::Json,
            BehaviorMode::Classical,
        ),
    )
    .unwrap();

    write_outputs_as(&result, &output, RuleTarget::SingBox, OutputFormat::Json).unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&output).unwrap()).unwrap();
    let rules = json["rules"].as_array().unwrap();

    assert_eq!(json["version"], 5);
    assert!(rules.iter().any(|rule| rule["domain"][0] == "example.com"));
    assert!(
        rules
            .iter()
            .any(|rule| rule["domain_suffix"][0] == "example.net")
    );
    assert!(rules.iter().any(|rule| rule["domain_keyword"][0] == "ads"));
    assert!(rules.iter().any(|rule| rule["domain_regex"][0] == "^foo"));
    assert!(
        rules
            .iter()
            .any(|rule| rule["ip_cidr"][0] == "192.0.2.0/24")
    );
    assert!(
        rules
            .iter()
            .any(|rule| rule["source_ip_cidr"][0] == "10.0.0.0/8")
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn sing_box_json_domain_suffix_maps_to_mihomo_domain_text_semantics() {
    let dir = temp_dir();
    let output = dir.join("domain.list");
    let payload = br#"{
  "version": 5,
  "rules": [
    { "domain": "static.example.org", "domain_suffix": [".example.com", "example.net"] }
  ]
}"#;
    let result = convert_payload(
        payload,
        options(
            RuleTarget::SingBox,
            InputFormat::Json,
            InputBehaviorMode::Domain,
            RuleTarget::Mihomo,
            OutputFormat::Text,
            BehaviorMode::Domain,
        ),
    )
    .unwrap();

    write_outputs_as(&result, &output, RuleTarget::Mihomo, OutputFormat::Text).unwrap();

    assert_eq!(
        read_lines(&output),
        BTreeSet::from([
            ".example.com".to_string(),
            "+.example.net".to_string(),
            "static.example.org".to_string(),
        ])
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn sing_box_srs_roundtrips_supported_rules_through_converter() {
    let dir = temp_dir();
    let srs = dir.join("rules.srs");
    let text = dir.join("rules.list");
    let result = convert_payload(
        "DOMAIN,example.com\nDOMAIN-SUFFIX,example.net\nDOMAIN-KEYWORD,ads\nIP-CIDR,192.0.2.0/24\n",
        options(
            RuleTarget::General,
            InputFormat::Text,
            InputBehaviorMode::Classical,
            RuleTarget::SingBox,
            OutputFormat::Srs,
            BehaviorMode::Classical,
        ),
    )
    .unwrap();

    write_outputs_as(&result, &srs, RuleTarget::SingBox, OutputFormat::Srs).unwrap();
    let raw = fs::read(&srs).unwrap();
    assert!(raw.starts_with(b"SRS"));

    let result = convert_payload(
        raw,
        options(
            RuleTarget::SingBox,
            InputFormat::Srs,
            InputBehaviorMode::Classical,
            RuleTarget::General,
            OutputFormat::RuleSet,
            BehaviorMode::Classical,
        ),
    )
    .unwrap();
    write_outputs_as(&result, &text, RuleTarget::General, OutputFormat::RuleSet).unwrap();

    assert_eq!(
        read_lines(&text),
        BTreeSet::from([
            "DOMAIN,example.com".to_string(),
            "DOMAIN-SUFFIX,example.net".to_string(),
            "DOMAIN-KEYWORD,ads".to_string(),
            "IP-CIDR,192.0.2.0/24".to_string(),
        ])
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn general_ruleset_domain_behavior_keeps_only_domain_rules() {
    let dir = temp_dir();
    let output = dir.join("domain-rules.list");
    let result = convert_payload(
        "DOMAIN,example.com\nDOMAIN-SUFFIX,example.net\nIP-CIDR,192.0.2.0/24\n",
        options(
            RuleTarget::General,
            InputFormat::Text,
            InputBehaviorMode::Classical,
            RuleTarget::General,
            OutputFormat::RuleSet,
            BehaviorMode::Domain,
        ),
    )
    .unwrap();

    write_outputs_as(&result, &output, RuleTarget::General, OutputFormat::RuleSet).unwrap();

    assert_eq!(
        read_lines(&output),
        BTreeSet::from([
            "DOMAIN,example.com".to_string(),
            "DOMAIN-SUFFIX,example.net".to_string(),
        ])
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn general_ruleset_ip_behavior_keeps_only_ip_rules() {
    let dir = temp_dir();
    let output = dir.join("ip-rules.list");
    let result = convert_payload(
        "DOMAIN,example.com\nIP-CIDR,192.0.2.0/24\nIP-CIDR6,2001:db8::/32\n",
        options(
            RuleTarget::General,
            InputFormat::Text,
            InputBehaviorMode::Classical,
            RuleTarget::General,
            OutputFormat::RuleSet,
            BehaviorMode::Ipcidr,
        ),
    )
    .unwrap();

    write_outputs_as(&result, &output, RuleTarget::General, OutputFormat::RuleSet).unwrap();

    assert_eq!(
        read_lines(&output),
        BTreeSet::from([
            "IP-CIDR,192.0.2.0/24".to_string(),
            "IP-CIDR6,2001:db8::/32".to_string(),
        ])
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn general_ruleset_classical_outputs_typed_rules_from_ip_set_input() {
    let dir = temp_dir();
    let output = dir.join("ip-classical.list");
    let result = convert_payload(
        "192.0.2.0/24\n2001:db8::/32\n",
        options(
            RuleTarget::General,
            InputFormat::Text,
            InputBehaviorMode::Ipcidr,
            RuleTarget::General,
            OutputFormat::RuleSet,
            BehaviorMode::Classical,
        ),
    )
    .unwrap();

    write_outputs_as(&result, &output, RuleTarget::General, OutputFormat::RuleSet).unwrap();

    assert_eq!(
        read_lines(&output),
        BTreeSet::from([
            "IP-CIDR,192.0.2.0/24".to_string(),
            "IP-CIDR6,2001:db8::/32".to_string(),
        ])
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn sing_box_json_ip_behavior_rejects_domain_only_input() {
    let result = convert_payload(
        "payload:\n  - +.0x0.st\n",
        options(
            RuleTarget::Mihomo,
            InputFormat::Yaml,
            InputBehaviorMode::Domain,
            RuleTarget::SingBox,
            OutputFormat::Json,
            BehaviorMode::Ipcidr,
        ),
    );
    match result {
        Ok(_) => panic!("ip behavior must not accept domain-only input"),
        Err(err) => assert!(err.to_string().contains("no supported rules")),
    }
}

#[test]
fn sing_box_json_domain_behavior_filters_mixed_input() {
    let dir = temp_dir();
    let output = dir.join("rules.json");
    let result = convert_payload(
        "DOMAIN-SUFFIX,example.com\nIP-CIDR,192.0.2.0/24\n",
        options(
            RuleTarget::General,
            InputFormat::Text,
            InputBehaviorMode::Classical,
            RuleTarget::SingBox,
            OutputFormat::Json,
            BehaviorMode::Domain,
        ),
    )
    .unwrap();

    write_outputs_as(&result, &output, RuleTarget::SingBox, OutputFormat::Json).unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&output).unwrap()).unwrap();
    let rules = json["rules"].as_array().unwrap();

    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["domain_suffix"][0], "example.com");
    assert!(rules[0].get("ip_cidr").is_none());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn sing_box_json_ip_behavior_filters_mixed_input() {
    let dir = temp_dir();
    let output = dir.join("rules.json");
    let result = convert_payload(
        "DOMAIN-SUFFIX,example.com\nIP-CIDR,192.0.2.0/24\n",
        options(
            RuleTarget::General,
            InputFormat::Text,
            InputBehaviorMode::Classical,
            RuleTarget::SingBox,
            OutputFormat::Json,
            BehaviorMode::Ipcidr,
        ),
    )
    .unwrap();

    write_outputs_as(&result, &output, RuleTarget::SingBox, OutputFormat::Json).unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&output).unwrap()).unwrap();
    let rules = json["rules"].as_array().unwrap();

    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["ip_cidr"][0], "192.0.2.0/24");
    assert!(rules[0].get("domain_suffix").is_none());
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn default_mihomo_mrs_follows_domain_input_behavior() {
    let result = convert_payload(
        "payload:\n  - +.example.com\n",
        ConvertOptions {
            input_target: Some(RuleTarget::Mihomo),
            input_format: Some(InputFormat::Yaml),
            input_behavior: InputBehaviorMode::Auto,
            output_target: RuleTarget::Mihomo,
            output_format: OutputFormat::Mrs,
            output_behavior: BehaviorMode::Auto,
        },
    )
    .unwrap();

    assert_eq!(result.output_behavior, BehaviorMode::Domain);
}

#[test]
fn default_mihomo_mrs_follows_ip_input_behavior() {
    let result = convert_payload(
        "192.0.2.0/24\n",
        ConvertOptions {
            input_target: Some(RuleTarget::General),
            input_format: Some(InputFormat::Text),
            input_behavior: InputBehaviorMode::Auto,
            output_target: RuleTarget::Mihomo,
            output_format: OutputFormat::Mrs,
            output_behavior: BehaviorMode::Auto,
        },
    )
    .unwrap();

    assert_eq!(result.output_behavior, BehaviorMode::Ipcidr);
}

#[test]
fn default_mihomo_mrs_rejects_mixed_input_without_output_behavior() {
    let result = convert_payload(
        "DOMAIN,example.com\nIP-CIDR,192.0.2.0/24\n",
        ConvertOptions {
            input_target: Some(RuleTarget::General),
            input_format: Some(InputFormat::Text),
            input_behavior: InputBehaviorMode::Auto,
            output_target: RuleTarget::Mihomo,
            output_format: OutputFormat::Mrs,
            output_behavior: BehaviorMode::Auto,
        },
    );

    match result {
        Ok(_) => panic!("mixed input must require explicit MRS behavior"),
        Err(err) => assert!(err.to_string().contains("needs explicit output behavior")),
    }
}

#[test]
fn general_domainset_ignores_classical_behavior_and_outputs_only_domains() {
    let dir = temp_dir();
    let output = dir.join("domains.list");
    let result = convert_payload(
        "DOMAIN,example.com\nIP-CIDR,192.0.2.0/24\n",
        options(
            RuleTarget::General,
            InputFormat::Text,
            InputBehaviorMode::Classical,
            RuleTarget::General,
            OutputFormat::DomainSet,
            BehaviorMode::Classical,
        ),
    )
    .unwrap();

    write_outputs_as(
        &result,
        &output,
        RuleTarget::General,
        OutputFormat::DomainSet,
    )
    .unwrap();

    assert_eq!(
        read_lines(&output),
        BTreeSet::from(["example.com".to_string()])
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn general_ipset_ignores_domain_behavior_and_outputs_only_ips() {
    let dir = temp_dir();
    let output = dir.join("ips.list");
    let result = convert_payload(
        "DOMAIN,example.com\nIP-CIDR,192.0.2.0/24\n",
        options(
            RuleTarget::General,
            InputFormat::Text,
            InputBehaviorMode::Classical,
            RuleTarget::General,
            OutputFormat::IpSet,
            BehaviorMode::Domain,
        ),
    )
    .unwrap();

    write_outputs_as(&result, &output, RuleTarget::General, OutputFormat::IpSet).unwrap();

    assert_eq!(
        read_lines(&output),
        BTreeSet::from(["192.0.2.0/24".to_string()])
    );
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn egern_classical_outputs_single_mixed_ruleset_yaml() {
    let dir = temp_dir();
    let output = dir.join("egern.yaml");
    let result = convert_payload(
        "payload:\n  - DOMAIN-SUFFIX,example.com\n  - DOMAIN,ads.example.net\n  - IP-CIDR,10.0.0.0/8,no-resolve\n",
        options(
            RuleTarget::Mihomo,
            InputFormat::Yaml,
            InputBehaviorMode::Classical,
            RuleTarget::Egern,
            OutputFormat::RuleSet,
            BehaviorMode::Classical,
        ),
    )
    .unwrap();

    let files =
        write_outputs_as(&result, &output, RuleTarget::Egern, OutputFormat::RuleSet).unwrap();
    let yaml = fs::read_to_string(&output).unwrap();

    assert_eq!(files.len(), 1);
    assert!(yaml.contains("domain_set:"));
    assert!(yaml.contains("domain_suffix_set:"));
    assert!(yaml.contains("no_resolve: true"));
    assert!(yaml.contains("ip_cidr_set:"));
    fs::remove_dir_all(dir).unwrap();
}
