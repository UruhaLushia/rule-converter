use std::path::{Path, PathBuf};

use super::*;

fn as_rule(job: &ConfigJob) -> &RuleConfigJob {
    match job {
        ConfigJob::Rules(job) => job,
        ConfigJob::Db(_) => panic!("expected rule job"),
    }
}

#[test]
fn parses_nested_yaml_job_with_defaults() {
    let raw = r#"
defaults:
  input_target: egern
  input_format: yaml
  input_behavior: auto
  output_target: egern
  output_format: ruleset
  output_behavior: domain
jobs:
  - input:
      path: rules/egern.yaml
    output:
      path: dist/rules.yaml
"#;
    let config: ConfigFile = serde_yaml::from_str(raw).unwrap();
    let jobs = config.into_jobs(Path::new("/tmp/base")).unwrap();
    let job = as_rule(&jobs[0]);

    assert_eq!(jobs.len(), 1);
    assert_eq!(
        job.input,
        vec![FileInput::path("/tmp/base/rules/egern.yaml")]
    );
    assert_eq!(job.options.input_target, Some(RuleTarget::Egern));
    assert_eq!(job.options.input_format, Some(InputFormat::Yaml));
    assert_eq!(job.options.input_behavior, InputBehaviorMode::Auto);
    assert_eq!(job.options.output_target, RuleTarget::Egern);
    assert_eq!(job.options.output_format, OutputFormat::RuleSet);
    assert_eq!(job.options.output_behavior, BehaviorMode::Domain);
}

#[test]
fn parses_nested_json_jobs() {
    let raw = r#"{
  "defaults": { "input_target": "general", "input_format": "text", "output_format": "mrs" },
  "jobs": [
    { "input": { "path": "a.list" }, "output": { "path": "a.mrs" } },
    { "input": { "path": "b.yaml", "target": "egern", "format": "yaml" }, "output": { "path": "b.yaml", "target": "egern", "format": "ruleset" } }
  ]
}"#;
    let config: ConfigFile = serde_json::from_str(raw).unwrap();
    let jobs = config.into_jobs(Path::new("/tmp/base")).unwrap();
    let first = as_rule(&jobs[0]);
    let second = as_rule(&jobs[1]);

    assert_eq!(jobs.len(), 2);
    assert_eq!(first.options.input_target, Some(RuleTarget::General));
    assert_eq!(first.options.input_format, Some(InputFormat::Text));
    assert_eq!(second.options.input_target, Some(RuleTarget::Egern));
    assert_eq!(second.options.input_format, Some(InputFormat::Yaml));
    assert_eq!(second.options.output_target, RuleTarget::Egern);
    assert_eq!(second.options.output_format, OutputFormat::RuleSet);
}

#[test]
fn parses_nested_toml_jobs() {
    let raw = r#"
[defaults]
input_target = "mihomo"
input_format = "yaml"
output_format = "mrs"

[[jobs]]
[jobs.input]
path = "rules.yaml"
behavior = "classical"

[jobs.output]
path = "rules.mrs"
behavior = "domain"
"#;
    let config: ConfigFile = toml::from_str(raw).unwrap();
    let jobs = config.into_jobs(Path::new("/tmp/base")).unwrap();
    let job = as_rule(&jobs[0]);

    assert_eq!(jobs.len(), 1);
    assert_eq!(job.options.input_target, Some(RuleTarget::Mihomo));
    assert_eq!(job.options.input_format, Some(InputFormat::Yaml));
    assert_eq!(job.options.input_behavior, InputBehaviorMode::Classical);
    assert_eq!(job.options.output_behavior, BehaviorMode::Domain);
}

#[test]
fn parses_input_paths() {
    let raw = r#"
jobs:
  - input:
      inputs:
        - rules/a.yaml
        - path: rules/b.list
          target: general
          format: text
          behavior: classical
    output:
      path: dist/rules.mrs
"#;
    let config: ConfigFile = serde_yaml::from_str(raw).unwrap();
    let jobs = config.into_jobs(Path::new("/tmp/base")).unwrap();
    let job = as_rule(&jobs[0]);

    assert_eq!(
        job.input,
        vec![
            FileInput::path("/tmp/base/rules/a.yaml"),
            FileInput {
                path: PathBuf::from("/tmp/base/rules/b.list"),
                target: Some(RuleTarget::General),
                format: Some(InputFormat::Text),
                behavior: InputBehaviorMode::Classical,
            },
        ]
    );
}

#[test]
fn parses_multiple_rule_outputs() {
    let raw = r#"
jobs:
  - input:
      path: rules.yaml
      target: mihomo
      format: yaml
      behavior: classical
    outputs:
      - path: domain.mrs
        target: mihomo
        format: mrs
        behavior: domain
      - path: rules.srs
        target: sing-box
        format: srs
        behavior: classical
"#;
    let config: ConfigFile = serde_yaml::from_str(raw).unwrap();
    let jobs = config.into_jobs(Path::new("/tmp/base")).unwrap();

    assert_eq!(jobs.len(), 2);
    let first = as_rule(&jobs[0]);
    let second = as_rule(&jobs[1]);
    assert_eq!(first.output, PathBuf::from("/tmp/base/domain.mrs"));
    assert_eq!(first.options.output_target, RuleTarget::Mihomo);
    assert_eq!(first.options.output_format, OutputFormat::Mrs);
    assert_eq!(first.options.output_behavior, BehaviorMode::Domain);
    assert_eq!(second.output, PathBuf::from("/tmp/base/rules.srs"));
    assert_eq!(second.options.output_target, RuleTarget::SingBox);
    assert_eq!(second.options.output_format, OutputFormat::Srs);
    assert_eq!(second.options.output_behavior, BehaviorMode::Classical);
}

#[test]
fn parses_multiple_db_outputs() {
    let raw = r#"
jobs:
  - input:
      path: geoip.mmdb
      target: geoip
      format: mmdb
    outputs:
      - dir: geoip
        target: general
        format: ipset
      - path: geoip.metadb
        target: geoip
        format: metadb
"#;
    let config: ConfigFile = serde_yaml::from_str(raw).unwrap();
    let jobs = config.into_jobs(Path::new("/tmp/base")).unwrap();

    assert_eq!(jobs.len(), 2);
    match &jobs[0] {
        ConfigJob::Db(DbConfigJob::Export { output, .. }) => {
            assert_eq!(output.base, PathBuf::from("/tmp/base/geoip"));
            assert!(output.split);
            assert_eq!(output.target, RuleTarget::General);
            assert_eq!(output.format, OutputFormat::IpSet);
        }
        _ => panic!("expected geoip export job"),
    }
    match &jobs[1] {
        ConfigJob::Db(DbConfigJob::Convert {
            output,
            output_format,
            ..
        }) => {
            assert_eq!(output, &PathBuf::from("/tmp/base/geoip.metadb"));
            assert_eq!(output_format, &MmdbFormat::MetaDb);
        }
        _ => panic!("expected geoip convert job"),
    }
}

#[test]
fn rejects_output_and_outputs_together() {
    let raw = r#"
jobs:
  - input:
      path: rules.yaml
    output:
      path: rules.mrs
    outputs:
      - path: rules.srs
"#;
    let config: ConfigFile = serde_yaml::from_str(raw).unwrap();
    let err = config.into_jobs(Path::new("/tmp/base")).unwrap_err();
    assert!(
        err.to_string()
            .contains("config job cannot contain both output and outputs"),
        "{err}"
    );
}

#[test]
fn parses_example_configs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for path in [
        "examples/config.yaml",
        "examples/config.toml",
        "examples/config.json",
    ] {
        load_config(root.join(path)).unwrap_or_else(|err| panic!("{path}: {err}"));
    }
}
