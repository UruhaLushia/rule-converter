use std::path::{Path, PathBuf};

use super::*;

#[test]
fn parses_geoip_build_job() {
    let raw = r#"
jobs:
  - input:
      inputs:
        - country: cn
          path: cn.list
          target: general
          format: text
          behavior: ip
        - country: us
          path: us.list
    output:
      path: geoip.mmdb
      target: geoip
      format: mmdb
"#;
    let config: ConfigFile = serde_yaml::from_str(raw).unwrap();
    let jobs = config.into_jobs(Path::new("/tmp/base")).unwrap();

    match &jobs[0] {
        ConfigJob::Db(DbConfigJob::Build {
            target,
            format,
            input,
            output,
        }) => {
            assert_eq!(target, &DbTarget::Geoip);
            assert_eq!(format, &MmdbFormat::Mmdb);
            assert_eq!(
                input,
                &vec![
                    DbInputPath::Country {
                        country: "cn".to_string(),
                        input: FileInput {
                            path: PathBuf::from("/tmp/base/cn.list"),
                            target: Some(RuleTarget::General),
                            format: Some(InputFormat::Text),
                            behavior: InputBehaviorMode::Ipcidr,
                        },
                    },
                    DbInputPath::Country {
                        country: "us".to_string(),
                        input: FileInput::path("/tmp/base/us.list"),
                    },
                ]
            );
            assert_eq!(output, &PathBuf::from("/tmp/base/geoip.mmdb"));
        }
        _ => panic!("expected geoip build job"),
    }
}

#[test]
fn parses_geoip_convert_job() {
    let raw = r#"
jobs:
  - input:
      path: geoip.mmdb
      target: geoip
      format: mmdb
    output:
      path: geoip.metadb
      target: geoip
      format: metadb
"#;
    let config: ConfigFile = serde_yaml::from_str(raw).unwrap();
    let jobs = config.into_jobs(Path::new("/tmp/base")).unwrap();

    match &jobs[0] {
        ConfigJob::Db(DbConfigJob::Convert {
            target,
            input_format,
            output_format,
            input,
            output,
            countries,
            asns,
        }) => {
            assert_eq!(target, &DbTarget::Geoip);
            assert_eq!(input_format, &MmdbFormat::Mmdb);
            assert_eq!(output_format, &MmdbFormat::MetaDb);
            assert_eq!(input, &PathBuf::from("/tmp/base/geoip.mmdb"));
            assert_eq!(output, &PathBuf::from("/tmp/base/geoip.metadb"));
            assert!(countries.is_empty());
            assert!(asns.is_empty());
        }
        _ => panic!("expected geoip convert job"),
    }
}

#[test]
fn parses_filtered_db_convert_job() {
    let raw = r#"
jobs:
  - input:
      path: geoip.mmdb
      target: geoip
      format: mmdb
    output:
      path: cn.metadb
      target: geoip
      format: metadb
      country: cn
  - input:
      path: asn.mmdb
      target: asn
      format: mmdb
    output:
      path: 13335.mmdb
      target: asn
      format: mmdb
      asn: 13335
"#;
    let config: ConfigFile = serde_yaml::from_str(raw).unwrap();
    let jobs = config.into_jobs(Path::new("/tmp/base")).unwrap();

    match &jobs[0] {
        ConfigJob::Db(DbConfigJob::Convert {
            output, countries, ..
        }) => {
            assert_eq!(output, &PathBuf::from("/tmp/base/cn.metadb"));
            assert_eq!(countries, &vec!["cn".to_string()]);
        }
        _ => panic!("expected geoip convert job"),
    }
    match &jobs[1] {
        ConfigJob::Db(DbConfigJob::Convert { output, asns, .. }) => {
            assert_eq!(output, &PathBuf::from("/tmp/base/13335.mmdb"));
            assert_eq!(asns, &vec![13335]);
        }
        _ => panic!("expected asn convert job"),
    }
}
