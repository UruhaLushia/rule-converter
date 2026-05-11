use rule_converter::{
    BehaviorMode, ConvertOptions, InputBehaviorMode, InputFormat, MmdbFormat, OutputFormat,
    RuleTarget, build_geosite_db_to_memory, convert_payload, export_geosite_db_to_memory,
    list_geosite_dat_codes,
};

#[test]
fn builds_geosite_dat_from_classical_rule_input() {
    let result = convert_payload(
        b"payload:
  - DOMAIN,apple.com
  - DOMAIN-SUFFIX,icloud.com
  - DOMAIN-KEYWORD,apple
  - IP-CIDR,10.0.0.0/8,no-resolve
",
        ConvertOptions {
            input_target: Some(RuleTarget::Mihomo),
            input_format: Some(InputFormat::Yaml),
            input_behavior: InputBehaviorMode::Auto,
            output_target: RuleTarget::General,
            output_format: OutputFormat::RuleSet,
            output_behavior: BehaviorMode::Classical,
        },
    )
    .unwrap();

    let dat = build_geosite_db_to_memory([("apple".to_string(), result)], MmdbFormat::Dat).unwrap();
    assert_eq!(dat.count, 3);
    assert_eq!(list_geosite_dat_codes(&dat.bytes).unwrap(), ["APPLE"]);

    let outputs = export_geosite_db_to_memory(
        &dat.bytes,
        MmdbFormat::Dat,
        &["apple".to_string()],
        false,
        RuleTarget::General,
        OutputFormat::RuleSet,
        BehaviorMode::Classical,
    )
    .unwrap();
    let text = String::from_utf8(outputs[0].bytes.clone()).unwrap();
    assert!(text.contains("DOMAIN,apple.com"));
    assert!(text.contains("DOMAIN-SUFFIX,icloud.com"));
    assert!(text.contains("DOMAIN-KEYWORD,apple"));
    assert!(!text.contains("IP-CIDR"));
}
