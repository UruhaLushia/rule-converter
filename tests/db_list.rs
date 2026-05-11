use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rule_converter::codec::mihomo::mrs::IpCidrSetBuilder;
use rule_converter::{
    BehaviorMode, ConvertResult, MmdbFormat, OutputFormat, RuleSetOutput, RuleTarget,
    build_asn_mmdb_from_cidrs, build_geoip_db_to_memory, build_geoip_mmdb_from_cidrs,
    build_geosite_dat_to_memory, build_geosite_db_to_memory,
    convert_asn_mmdb_file_to_memory_filtered, convert_geoip_db_to_memory_filtered,
    convert_geoip_mmdb_file_to_memory_filtered, convert_geosite_db_to_memory_filtered,
    export_geosite_dat_general_ruleset_to_writer, export_geosite_dat_to_memory, list_asn_mmdb_asns,
    list_asn_mmdb_asns_from_bytes, list_geoip_dat_countries, list_geoip_mmdb_countries,
    list_geoip_mmdb_countries_from_bytes, list_geosite_dat_codes, list_sing_geosite_codes,
};

#[test]
fn lists_geoip_countries_from_file_and_bytes() {
    let dir = temp_dir("geoip-list");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("country.mmdb");

    build_geoip_mmdb_from_cidrs(
        [
            ("CN".to_string(), "1.0.1.0/24".to_string()),
            ("us".to_string(), "8.8.8.0/24".to_string()),
            ("cn".to_string(), "1.0.2.0/24".to_string()),
        ],
        &path,
        MmdbFormat::Mmdb,
    )
    .unwrap();

    let bytes = fs::read(&path).unwrap();
    assert_eq!(list_geoip_mmdb_countries(&path).unwrap(), ["cn", "us"]);
    assert_eq!(
        list_geoip_mmdb_countries_from_bytes(&bytes).unwrap(),
        ["cn", "us"]
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn lists_asn_numbers_from_file_and_bytes() {
    let dir = temp_dir("asn-list");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("asn.mmdb");

    build_asn_mmdb_from_cidrs(
        [
            (13335, "1.1.1.0/24".to_string()),
            (15169, "8.8.8.0/24".to_string()),
            (13335, "1.0.0.0/24".to_string()),
        ],
        &path,
    )
    .unwrap();

    let bytes = fs::read(&path).unwrap();
    assert_eq!(list_asn_mmdb_asns(&path).unwrap(), [13335, 15169]);
    assert_eq!(
        list_asn_mmdb_asns_from_bytes(&bytes).unwrap(),
        [13335, 15169]
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn converts_geoip_dat_to_mmdb_and_filters_dat() {
    let dat = build_geoip_db_to_memory(
        [
            ("cn".to_string(), ip_set(["1.0.1.0/24"])),
            ("us".to_string(), ip_set(["8.8.8.0/24"])),
        ],
        MmdbFormat::Dat,
    )
    .unwrap();

    assert_eq!(list_geoip_dat_countries(&dat.bytes).unwrap(), ["CN", "US"]);

    let filtered_dat = convert_geoip_db_to_memory_filtered(
        &dat.bytes,
        MmdbFormat::Dat,
        &["cn".to_string()],
        MmdbFormat::Dat,
    )
    .unwrap();
    assert_eq!(filtered_dat.count, 1);
    assert_eq!(
        list_geoip_dat_countries(&filtered_dat.bytes).unwrap(),
        ["CN"]
    );

    let mmdb = convert_geoip_db_to_memory_filtered(
        &dat.bytes,
        MmdbFormat::Dat,
        &["us".to_string()],
        MmdbFormat::Mmdb,
    )
    .unwrap();
    assert_eq!(mmdb.count, 1);
    assert_eq!(
        list_geoip_mmdb_countries_from_bytes(&mmdb.bytes).unwrap(),
        ["us"]
    );
}

#[test]
fn converts_geosite_dat_to_rules_and_filters_dat() {
    let dat = build_geosite_dat_to_memory([
        (
            "cn".to_string(),
            domain_result(["+.example.cn"], ["DOMAIN-KEYWORD,example"]),
        ),
        (
            "us".to_string(),
            domain_result(["example.com"], ["DOMAIN-REGEX,^ads\\\\."]),
        ),
    ])
    .unwrap();

    assert_eq!(list_geosite_dat_codes(&dat.bytes).unwrap(), ["CN", "US"]);

    let filtered =
        rule_converter::convert_geosite_dat_to_memory_filtered(&dat.bytes, &["us".to_string()])
            .unwrap();
    assert_eq!(filtered.count, 2);
    assert_eq!(list_geosite_dat_codes(&filtered.bytes).unwrap(), ["US"]);

    let outputs = export_geosite_dat_to_memory(
        &dat.bytes,
        &["cn".to_string()],
        false,
        RuleTarget::General,
        OutputFormat::RuleSet,
        BehaviorMode::Classical,
    )
    .unwrap();
    assert_eq!(outputs.len(), 1);
    let text = String::from_utf8(outputs[0].bytes.clone()).unwrap();
    assert!(text.contains("DOMAIN-SUFFIX,example.cn"));
    assert!(text.contains("DOMAIN-KEYWORD,example"));

    let mut streamed = Vec::new();
    let count = export_geosite_dat_general_ruleset_to_writer(
        std::io::Cursor::new(&dat.bytes),
        &mut streamed,
        &["cn".to_string()],
    )
    .unwrap();
    let streamed = String::from_utf8(streamed).unwrap();
    assert_eq!(count, 2);
    assert!(streamed.contains("DOMAIN-SUFFIX,example.cn"));
    assert!(streamed.contains("DOMAIN-KEYWORD,example"));
}

#[test]
fn converts_sing_geosite_to_rules_and_dat() {
    let sing = build_geosite_db_to_memory(
        [
            (
                "cn".to_string(),
                domain_result(["+.example.cn"], ["DOMAIN-KEYWORD,example"]),
            ),
            (
                "apple".to_string(),
                domain_result(["apple.com"], ["DOMAIN-SUFFIX,icloud.com"]),
            ),
        ],
        MmdbFormat::SingGeosite,
    )
    .unwrap();

    assert_eq!(sing.format, MmdbFormat::SingGeosite);
    assert_eq!(
        list_sing_geosite_codes(&sing.bytes).unwrap(),
        ["apple", "cn"]
    );
    let detected = rule_converter::detect_payload_type(&sing.bytes).unwrap();
    assert_eq!(detected.target, "geosite");
    assert_eq!(detected.format, "sing-geosite");

    let dat = convert_geosite_db_to_memory_filtered(
        &sing.bytes,
        MmdbFormat::SingGeosite,
        &["apple".to_string()],
        MmdbFormat::Dat,
    )
    .unwrap();
    assert_eq!(list_geosite_dat_codes(&dat.bytes).unwrap(), ["APPLE"]);

    let filtered = convert_geosite_db_to_memory_filtered(
        &sing.bytes,
        MmdbFormat::SingGeosite,
        &["cn".to_string()],
        MmdbFormat::SingGeosite,
    )
    .unwrap();
    assert_eq!(list_sing_geosite_codes(&filtered.bytes).unwrap(), ["cn"]);
}

#[test]
fn filters_geoip_db_to_db() {
    let dir = temp_dir("geoip-filter-db");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("country.mmdb");

    build_geoip_mmdb_from_cidrs(
        [
            ("cn".to_string(), "1.0.1.0/24".to_string()),
            ("us".to_string(), "8.8.8.0/24".to_string()),
        ],
        &path,
        MmdbFormat::Mmdb,
    )
    .unwrap();

    let output =
        convert_geoip_mmdb_file_to_memory_filtered(&path, &["cn".to_string()], MmdbFormat::Mmdb)
            .unwrap();
    assert_eq!(output.count, 1);
    assert_eq!(
        list_geoip_mmdb_countries_from_bytes(&output.bytes).unwrap(),
        ["cn"]
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn filters_asn_db_to_db() {
    let dir = temp_dir("asn-filter-db");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("asn.mmdb");

    build_asn_mmdb_from_cidrs(
        [
            (13335, "1.1.1.0/24".to_string()),
            (15169, "8.8.8.0/24".to_string()),
        ],
        &path,
    )
    .unwrap();

    let output = convert_asn_mmdb_file_to_memory_filtered(&path, &[13335]).unwrap();
    assert_eq!(output.count, 1);
    assert_eq!(
        list_asn_mmdb_asns_from_bytes(&output.bytes).unwrap(),
        [13335]
    );

    fs::remove_dir_all(dir).unwrap();
}

fn ip_set<const N: usize>(rules: [&str; N]) -> RuleSetOutput {
    let mut builder = IpCidrSetBuilder::default();
    for rule in rules {
        builder.insert(rule).unwrap();
    }
    RuleSetOutput::Ipcidr(builder.finish().unwrap())
}

fn domain_result<const D: usize, const M: usize>(
    domains: [&str; D],
    mixed: [&str; M],
) -> ConvertResult {
    let rules = domains
        .into_iter()
        .chain(mixed)
        .map(str::to_string)
        .collect::<Vec<_>>();
    rule_converter::convert_rules(&rules, BehaviorMode::Classical).unwrap()
}

fn temp_dir(name: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("rule-converter-{name}-{suffix}"))
}
