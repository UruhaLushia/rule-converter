use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rule_converter::codec::mihomo::mrs::IpCidrSetBuilder;
use rule_converter::{
    BehaviorMode, ConvertResult, InputIndexSection, MmdbFormat, RuleSetOutput,
    build_asn_mmdb_from_cidrs, build_geoip_db_to_memory, build_geoip_mmdb_from_cidrs,
    build_geosite_dat_to_memory, build_geosite_db_to_memory, list_input_indexes,
    list_input_indexes_from_bytes,
};

#[test]
fn lists_indexes_from_any_detected_db_input() {
    let dir = temp_dir("any-db-list");
    fs::create_dir_all(&dir).unwrap();

    let geoip_mmdb = dir.join("country.mmdb");
    build_geoip_mmdb_from_cidrs(
        [("cn".to_string(), "1.0.1.0/24".to_string())],
        &geoip_mmdb,
        MmdbFormat::Mmdb,
    )
    .unwrap();
    assert_eq!(
        list_input_indexes(&geoip_mmdb).unwrap(),
        [index_section("GeoIP Countries", ["cn"])]
    );

    let asn_mmdb = dir.join("asn.mmdb");
    build_asn_mmdb_from_cidrs([(13335, "1.1.1.0/24".to_string())], &asn_mmdb).unwrap();
    assert_eq!(
        list_input_indexes(&asn_mmdb).unwrap(),
        [index_section("ASN Numbers", ["AS13335"])]
    );

    let geoip_dat = build_geoip_db_to_memory(
        [("cn".to_string(), ip_set(["1.0.1.0/24"]))],
        MmdbFormat::Dat,
    )
    .unwrap();
    assert_eq!(
        list_input_indexes_from_bytes(&geoip_dat.bytes).unwrap(),
        [index_section("GeoIP DAT Countries", ["CN"])]
    );

    let geosite_dat = build_geosite_dat_to_memory([(
        "apple".to_string(),
        domain_result(["apple.com"], ["DOMAIN-SUFFIX,icloud.com"]),
    )])
    .unwrap();
    assert_eq!(
        list_input_indexes_from_bytes(&geosite_dat.bytes).unwrap(),
        [index_section("Geosite Codes", ["APPLE"])]
    );

    let sing_geosite = build_geosite_db_to_memory(
        [(
            "apple".to_string(),
            domain_result(["apple.com"], ["DOMAIN-SUFFIX,icloud.com"]),
        )],
        MmdbFormat::SingGeosite,
    )
    .unwrap();
    assert_eq!(
        list_input_indexes_from_bytes(&sing_geosite.bytes).unwrap(),
        [index_section("Geosite Codes", ["apple"])]
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

fn index_section<const N: usize>(title: &str, items: [&str; N]) -> InputIndexSection {
    InputIndexSection {
        title: title.to_string(),
        items: items.into_iter().map(str::to_string).collect(),
    }
}
