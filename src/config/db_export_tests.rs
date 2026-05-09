use std::path::{Path, PathBuf};

use super::*;

#[test]
fn parses_geoip_export_job() {
    let raw = r#"
jobs:
  - input:
      path: geoip.mmdb
      target: geoip
      format: mmdb
    output:
      dir: geoip
      target: general
      format: text
"#;
    let config: ConfigFile = serde_yaml::from_str(raw).unwrap();
    let jobs = config.into_jobs(Path::new("/tmp/base")).unwrap();

    match &jobs[0] {
        ConfigJob::Db(DbConfigJob::Export {
            target,
            format,
            input,
            output,
            countries,
            asns,
        }) => {
            assert_eq!(target, &DbTarget::Geoip);
            assert_eq!(format, &MmdbFormat::Mmdb);
            assert_eq!(input, &PathBuf::from("/tmp/base/geoip.mmdb"));
            assert_eq!(
                output,
                &DbExportOutput {
                    base: PathBuf::from("/tmp/base/geoip"),
                    split: true,
                    target: RuleTarget::General,
                    format: OutputFormat::Text,
                    behavior: BehaviorMode::Ipcidr,
                }
            );
            assert!(countries.is_empty());
            assert!(asns.is_empty());
        }
        _ => panic!("expected geoip export job"),
    }
}

#[test]
fn parses_filtered_db_convert_jobs() {
    let raw = r#"
jobs:
  - input:
      path: geoip.mmdb
      target: geoip
      format: mmdb
    output:
      path: cn.mmdb
      target: geoip
      format: mmdb
      country: cn
  - input:
      path: asn.mmdb
      target: asn
      format: mmdb
    output:
      path: as13335.mmdb
      target: asn
      format: mmdb
      asn: 13335
"#;
    let config: ConfigFile = serde_yaml::from_str(raw).unwrap();
    let jobs = config.into_jobs(Path::new("/tmp/base")).unwrap();

    match &jobs[0] {
        ConfigJob::Db(DbConfigJob::Convert {
            countries, asns, ..
        }) => {
            assert_eq!(countries, &vec!["cn".to_string()]);
            assert!(asns.is_empty());
        }
        _ => panic!("expected geoip convert job"),
    }
    match &jobs[1] {
        ConfigJob::Db(DbConfigJob::Convert {
            countries, asns, ..
        }) => {
            assert!(countries.is_empty());
            assert_eq!(asns, &vec![13335]);
        }
        _ => panic!("expected asn convert job"),
    }
}

#[test]
fn parses_single_geoip_country_output_filter() {
    let raw = r#"
jobs:
  - input:
      path: geoip.mmdb
      target: geoip
      format: mmdb
    output:
      path: cn.list
      target: general
      format: ipset
      country: cn
"#;
    let config: ConfigFile = serde_yaml::from_str(raw).unwrap();
    let jobs = config.into_jobs(Path::new("/tmp/base")).unwrap();

    match &jobs[0] {
        ConfigJob::Db(DbConfigJob::Export {
            output, countries, ..
        }) => {
            assert_eq!(output.base, PathBuf::from("/tmp/base/cn.list"));
            assert!(!output.split);
            assert_eq!(countries, &vec!["cn".to_string()]);
        }
        _ => panic!("expected geoip export job"),
    }
}

#[test]
fn parses_single_asn_output_filter() {
    let raw = r#"
jobs:
  - input:
      path: asn.mmdb
      target: asn
      format: mmdb
    output:
      path: as13335.list
      target: general
      format: ipset
      asn: 13335
"#;
    let config: ConfigFile = serde_yaml::from_str(raw).unwrap();
    let jobs = config.into_jobs(Path::new("/tmp/base")).unwrap();

    match &jobs[0] {
        ConfigJob::Db(DbConfigJob::Export { output, asns, .. }) => {
            assert_eq!(output.base, PathBuf::from("/tmp/base/as13335.list"));
            assert!(!output.split);
            assert_eq!(asns, &vec![13335]);
        }
        _ => panic!("expected asn export job"),
    }
}

#[test]
fn rejects_unfiltered_db_export_to_path() {
    let raw = r#"
jobs:
  - input:
      path: geoip.mmdb
      target: geoip
      format: mmdb
    output:
      path: geoip.mrs
      target: mihomo
      format: mrs
      behavior: ip
"#;
    let config: ConfigFile = serde_yaml::from_str(raw).unwrap();
    let err = config.into_jobs(Path::new("/tmp/base")).unwrap_err();
    assert!(
        err.to_string().contains("GeoIP DB export without country"),
        "{err}"
    );
}
