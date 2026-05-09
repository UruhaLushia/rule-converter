use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rule_converter::{
    MmdbFormat, build_asn_mmdb_from_cidrs, build_geoip_mmdb_from_cidrs,
    convert_asn_mmdb_file_to_memory_filtered, convert_geoip_mmdb_file_to_memory_filtered,
    list_asn_mmdb_asns, list_asn_mmdb_asns_from_bytes, list_geoip_mmdb_countries,
    list_geoip_mmdb_countries_from_bytes,
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

fn temp_dir(name: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("rule-converter-{name}-{suffix}"))
}
