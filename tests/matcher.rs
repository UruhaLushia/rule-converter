use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use rule_converter::codec::mihomo::mrs::{IpCidrSetBuilder, RuleSetOutput};
use rule_converter::{
    InputBehaviorMode, MatchInputFormat, MatchInputTarget, MatchOptions, MmdbFormat,
    build_asn_mmdb_from_cidrs, build_geosite_dat_to_memory, build_geosite_db_to_memory, match_file,
    match_payload,
};

fn temp_dir(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "rule-converter-{name}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}

fn ip_set<const N: usize>(rules: [&str; N]) -> RuleSetOutput {
    let mut builder = IpCidrSetBuilder::default();
    for rule in rules {
        builder.insert(rule).unwrap();
    }
    RuleSetOutput::Ipcidr(builder.finish().unwrap())
}

#[test]
fn matches_domain_suffix_and_ip_cidr() {
    let rules = b"DOMAIN-SUFFIX,example.com\nIP-CIDR,10.0.0.0/8,no-resolve\n";
    let options = MatchOptions {
        input_behavior: InputBehaviorMode::Classical,
        ..MatchOptions::default()
    };

    let domain = match_payload(rules, "ads.example.com", options).unwrap();
    assert!(domain.matched);
    assert_eq!(domain.kind.as_str(), "domain");
    assert!(
        domain
            .rules
            .iter()
            .any(|rule| rule.rule == "DOMAIN-SUFFIX,example.com")
    );

    let ip = match_payload(rules, "10.2.3.4", options).unwrap();
    assert!(ip.matched);
    assert_eq!(ip.kind.as_str(), "ip");
    assert!(
        ip.rules
            .iter()
            .any(|rule| rule.rule.starts_with("IP-CIDR,"))
    );

    let miss = match_payload(rules, "example.net", options).unwrap();
    assert!(!miss.matched);
}

#[test]
fn matches_keyword_and_regex_classical_rules() {
    let rules = b"DOMAIN-KEYWORD,ads\nDOMAIN-REGEX,^cdn[0-9]+\\.example\\.net$\n";
    let options = MatchOptions {
        input_behavior: InputBehaviorMode::Classical,
        ..MatchOptions::default()
    };

    assert!(
        match_payload(rules, "static-ads.example.org", options)
            .unwrap()
            .matched
    );
    assert!(
        match_payload(rules, "cdn12.example.net", options)
            .unwrap()
            .matched
    );
    assert!(
        !match_payload(rules, "cdn.example.net", options)
            .unwrap()
            .matched
    );
}

#[test]
fn matches_geosite_dat_payload_and_auto_detects_it() {
    let rules = b"DOMAIN-KEYWORD,ads\nDOMAIN-REGEX,[\n";
    let db = build_geosite_dat_to_memory([(
        "test".to_string(),
        rule_converter::convert_payload(
            rules,
            rule_converter::ConvertOptions {
                input_behavior: InputBehaviorMode::Classical,
                output_target: rule_converter::RuleTarget::General,
                output_format: rule_converter::OutputFormat::RuleSet,
                output_behavior: rule_converter::BehaviorMode::Classical,
                ..rule_converter::ConvertOptions::default()
            },
        )
        .unwrap(),
    )])
    .unwrap();

    let explicit = match_payload(
        &db.bytes,
        "static-ads.example.org",
        MatchOptions {
            input_target: Some(MatchInputTarget::Geosite),
            input_format: Some(MatchInputFormat::Dat),
            ..MatchOptions::default()
        },
    )
    .unwrap();
    assert!(explicit.matched);
    assert!(explicit.rules.iter().any(|rule| {
        rule.source.as_deref() == Some("geosite") && rule.set.as_deref() == Some("test")
    }));

    let auto = match_payload(&db.bytes, "static-ads.example.org", MatchOptions::default()).unwrap();
    assert!(auto.matched);
}

#[test]
fn matches_sing_geosite_payload_and_auto_detects_it() {
    let db = build_geosite_db_to_memory(
        [(
            "apple".to_string(),
            rule_converter::convert_payload(
                b"DOMAIN-SUFFIX,apple.com\n",
                rule_converter::ConvertOptions {
                    input_behavior: InputBehaviorMode::Classical,
                    output_target: rule_converter::RuleTarget::General,
                    output_format: rule_converter::OutputFormat::RuleSet,
                    output_behavior: rule_converter::BehaviorMode::Classical,
                    ..rule_converter::ConvertOptions::default()
                },
            )
            .unwrap(),
        )],
        MmdbFormat::SingGeosite,
    )
    .unwrap();

    let explicit = match_payload(
        &db.bytes,
        "www.apple.com",
        MatchOptions {
            input_target: Some(MatchInputTarget::Geosite),
            input_format: Some(MatchInputFormat::SingGeosite),
            ..MatchOptions::default()
        },
    )
    .unwrap();
    assert!(explicit.matched);
    assert!(explicit.rules.iter().any(|rule| {
        rule.source.as_deref() == Some("geosite") && rule.set.as_deref() == Some("apple")
    }));

    let auto = match_payload(&db.bytes, "www.apple.com", MatchOptions::default()).unwrap();
    assert!(auto.matched);
}

#[test]
fn matches_asn_mmdb_payload_with_asn_context() {
    let dir = temp_dir("asn-match");
    let path = dir.join("asn.mmdb");
    build_asn_mmdb_from_cidrs([(13335, "1.1.1.0/24".to_string())], &path).unwrap();
    let bytes = fs::read(path).unwrap();

    let result = match_payload(
        &bytes,
        "1.1.1.1",
        MatchOptions {
            input_target: Some(MatchInputTarget::Asn),
            input_format: Some(MatchInputFormat::Mmdb),
            ..MatchOptions::default()
        },
    )
    .unwrap();

    assert!(result.matched);
    assert!(result.rules.iter().any(|rule| {
        rule.source.as_deref() == Some("asn") && rule.set.as_deref() == Some("as13335")
    }));
}

#[test]
fn matches_sing_geoip_db_payload_as_mmdb() {
    let db = rule_converter::build_geoip_db_to_memory(
        [("cn".to_string(), ip_set(["1.1.1.0/24"]))],
        MmdbFormat::SingDb,
    )
    .unwrap();

    let result = match_payload(
        &db.bytes,
        "1.1.1.1",
        MatchOptions {
            input_target: Some(MatchInputTarget::Geoip),
            input_format: Some(MatchInputFormat::Mmdb),
            ..MatchOptions::default()
        },
    )
    .unwrap();

    assert!(result.matched);
    assert!(result.rules.iter().any(|rule| {
        rule.rule == "1.1.1.0/24"
            && rule.source.as_deref() == Some("geoip")
            && rule.set.as_deref() == Some("cn")
    }));
}

#[test]
fn matches_meta_geoip_db_payload_with_country_context() {
    let db = rule_converter::build_geoip_db_to_memory(
        [("cn".to_string(), ip_set(["1.1.1.0/24"]))],
        MmdbFormat::MetaDb,
    )
    .unwrap();

    let result = match_payload(
        &db.bytes,
        "1.1.1.1",
        MatchOptions {
            input_target: Some(MatchInputTarget::Geoip),
            input_format: Some(MatchInputFormat::Mmdb),
            ..MatchOptions::default()
        },
    )
    .unwrap();

    assert!(result.matched);
    assert!(result.rules.iter().any(|rule| {
        rule.rule == "1.1.1.0/24"
            && rule.source.as_deref() == Some("geoip")
            && rule.set.as_deref() == Some("cn")
    }));
}

#[test]
fn matches_geoip_dat_payload_with_country_context() {
    let db = rule_converter::build_geoip_db_to_memory(
        [("cn".to_string(), ip_set(["1.1.1.0/24"]))],
        MmdbFormat::Dat,
    )
    .unwrap();

    let result = match_payload(
        &db.bytes,
        "1.1.1.1",
        MatchOptions {
            input_target: Some(MatchInputTarget::Geoip),
            input_format: Some(MatchInputFormat::Dat),
            ..MatchOptions::default()
        },
    )
    .unwrap();

    assert!(result.matched);
    assert!(result.rules.iter().any(|rule| {
        rule.rule == "1.1.1.0/24"
            && rule.source.as_deref() == Some("geoip")
            && rule.set.as_deref() == Some("cn")
    }));
}

#[test]
fn matches_mihomo_config_rule_providers() {
    let base = std::env::temp_dir().join(format!(
        "rule-converter-matcher-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&base).unwrap();
    fs::write(base.join("github.list"), "DOMAIN-SUFFIX,github.com\n").unwrap();
    fs::write(base.join("private-ip.list"), "10.0.0.0/8\n").unwrap();
    fs::write(
        base.join("config.yaml"),
        r#"
rules:
  - RULE-SET,private_ip,Direct,no-resolve
  - RULE-SET,github_domain,Github
  - MATCH,Other
rule-anchor:
  ip: &ip {target: general, behavior: ipcidr, format: text}
  domain: &domain {target: general, behavior: classical, format: text}
rule-providers:
  github_domain:
    <<: *domain
    path: github.list
  private_ip:
    <<: *ip
    path: private-ip.list
"#,
    )
    .unwrap();

    let domain = match_file(
        base.join("config.yaml"),
        "api.github.com",
        MatchOptions::default(),
    )
    .unwrap();
    assert!(domain.matched);
    assert_eq!(domain.rules[0].rule, "RULE-SET,github_domain,Github");

    let ip = match_file(
        base.join("config.yaml"),
        "10.1.2.3",
        MatchOptions::default(),
    )
    .unwrap();
    assert!(ip.matched);
    assert_eq!(ip.rules[0].rule, "RULE-SET,private_ip,Direct,no-resolve");

    let fallback = match_file(
        base.join("config.yaml"),
        "example.net",
        MatchOptions::default(),
    )
    .unwrap();
    assert!(fallback.matched);
    assert_eq!(fallback.rules[0].rule, "MATCH,Other");

    fs::remove_dir_all(base).unwrap();
}
