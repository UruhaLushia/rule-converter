use std::path::{Path, PathBuf};

use super::*;

#[test]
fn parses_geosite_dat_jobs_with_code_alias() {
    let raw = r#"
jobs:
  - input:
      path: geosite.dat
      target: geosite
      format: dat
    outputs:
      - dir: geosite
        target: general
        format: ruleset
      - path: cn.dat
        target: geosite
        format: dat
        code: cn
  - input:
      inputs:
        - code: cn
          path: cn.yaml
          target: mihomo
          format: yaml
          behavior: classical
    output:
      path: geosite.dat
      target: geosite
      format: dat
"#;
    let config: ConfigFile = serde_yaml::from_str(raw).unwrap();
    let jobs = config.into_jobs(Path::new("/tmp/base")).unwrap();

    assert_eq!(jobs.len(), 3);
    match &jobs[0] {
        ConfigJob::Db(DbConfigJob::Export {
            target,
            format,
            output,
            countries,
            ..
        }) => {
            assert_eq!(target, &DbTarget::Geosite);
            assert_eq!(format, &MmdbFormat::Dat);
            assert_eq!(output.base, PathBuf::from("/tmp/base/geosite"));
            assert!(countries.is_empty());
        }
        _ => panic!("expected geosite export job"),
    }
    match &jobs[1] {
        ConfigJob::Db(DbConfigJob::Convert {
            target,
            input_format,
            output_format,
            countries,
            ..
        }) => {
            assert_eq!(target, &DbTarget::Geosite);
            assert_eq!(input_format, &MmdbFormat::Dat);
            assert_eq!(output_format, &MmdbFormat::Dat);
            assert_eq!(countries, &vec!["cn".to_string()]);
        }
        _ => panic!("expected geosite convert job"),
    }
    match &jobs[2] {
        ConfigJob::Db(DbConfigJob::Build { target, input, .. }) => {
            assert_eq!(target, &DbTarget::Geosite);
            assert_eq!(
                input,
                &vec![DbInputPath::Country {
                    country: "cn".to_string(),
                    input: FileInput {
                        path: PathBuf::from("/tmp/base/cn.yaml"),
                        target: Some(RuleTarget::Mihomo),
                        format: Some(InputFormat::Yaml),
                        behavior: InputBehaviorMode::Classical,
                    },
                }]
            );
        }
        _ => panic!("expected geosite build job"),
    }
}

#[test]
fn parses_asn_mmdb_jobs() {
    let raw = r#"
jobs:
  - input:
      path: asn.mmdb
      target: asn
      format: mmdb
    output:
      dir: asn
      target: general
      format: ipset
  - input:
      inputs:
        - asn: 13335
          path: as13335.list
          target: general
          format: ipset
    output:
      path: asn.mmdb
      target: asn
      format: mmdb
"#;
    let config: ConfigFile = serde_yaml::from_str(raw).unwrap();
    let jobs = config.into_jobs(Path::new("/tmp/base")).unwrap();

    match &jobs[0] {
        ConfigJob::Db(DbConfigJob::Export {
            target,
            format,
            output,
            asns,
            ..
        }) => {
            assert_eq!(target, &DbTarget::Asn);
            assert_eq!(format, &MmdbFormat::Mmdb);
            assert_eq!(
                output,
                &DbExportOutput {
                    base: PathBuf::from("/tmp/base/asn"),
                    split: true,
                    target: RuleTarget::General,
                    format: OutputFormat::IpSet,
                    behavior: BehaviorMode::Auto,
                }
            );
            assert!(asns.is_empty());
        }
        _ => panic!("expected asn export job"),
    }

    match &jobs[1] {
        ConfigJob::Db(DbConfigJob::Build { target, input, .. }) => {
            assert_eq!(target, &DbTarget::Asn);
            assert_eq!(
                input,
                &vec![DbInputPath::Asn {
                    asn: 13335,
                    input: FileInput {
                        path: PathBuf::from("/tmp/base/as13335.list"),
                        target: Some(RuleTarget::General),
                        format: Some(InputFormat::Text),
                        behavior: InputBehaviorMode::Ipcidr,
                    },
                }]
            );
        }
        _ => panic!("expected asn build job"),
    }
}
