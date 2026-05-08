use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::{
    BehaviorMode, ConvertOptions, InputBehaviorMode, InputFormat, OutputFormat, RuleTarget,
};

#[derive(Clone, Debug)]
pub struct ConfigJob {
    pub input: Vec<PathBuf>,
    pub output: PathBuf,
    pub options: ConvertOptions,
}

impl ConfigJob {
    pub fn single_input(&self) -> Option<&Path> {
        match self.input.as_slice() {
            [path] => Some(path.as_path()),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    #[serde(default)]
    defaults: ConfigDefaults,
    input: Option<ConfigInput>,
    output: Option<PathBuf>,
    input_format: Option<String>,
    input_target: Option<String>,
    input_behavior: Option<String>,
    output_format: Option<String>,
    output_target: Option<String>,
    output_behavior: Option<String>,
    jobs: Option<Vec<ConfigJobFile>>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigDefaults {
    input_format: Option<String>,
    input_target: Option<String>,
    input_behavior: Option<String>,
    output_format: Option<String>,
    output_target: Option<String>,
    output_behavior: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigJobFile {
    input: ConfigInput,
    output: PathBuf,
    input_format: Option<String>,
    input_target: Option<String>,
    input_behavior: Option<String>,
    output_format: Option<String>,
    output_target: Option<String>,
    output_behavior: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ConfigInput {
    One(PathBuf),
    Many(Vec<PathBuf>),
}

impl ConfigInput {
    fn resolve(self, base: &Path) -> Result<Vec<PathBuf>> {
        let inputs = match self {
            Self::One(path) => vec![path],
            Self::Many(paths) => paths,
        };
        if inputs.is_empty() {
            bail!("config input list must not be empty");
        }
        Ok(inputs
            .into_iter()
            .map(|path| resolve_config_path(base, path))
            .collect())
    }
}

pub fn load_config(path: impl AsRef<Path>) -> Result<Vec<ConfigJob>> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config {}", path.display()))?;
    let config = parse_config(path, &raw)?;
    config.into_jobs(path.parent().unwrap_or_else(|| Path::new("")))
}

fn parse_config(path: &Path, raw: &str) -> Result<ConfigFile> {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        Some("yaml") => serde_yaml::from_str(raw).context("failed to parse YAML config"),
        Some("toml") => toml::from_str(raw).context("failed to parse TOML config"),
        Some("json") => serde_json::from_str(raw).context("failed to parse JSON config"),
        Some(other) => bail!("unsupported config format: {other}"),
        None => bail!("config path must have yaml, toml, or json extension"),
    }
}

impl ConfigFile {
    fn into_jobs(self, base: &Path) -> Result<Vec<ConfigJob>> {
        if let Some(jobs) = self.jobs {
            if self.input.is_some() || self.output.is_some() {
                bail!("config cannot combine top-level input/output with jobs");
            }
            if jobs.is_empty() {
                bail!("config jobs must not be empty");
            }
            return jobs
                .into_iter()
                .map(|job| job.into_job(base, &self.defaults))
                .collect();
        }

        let input = self
            .input
            .ok_or_else(|| anyhow::anyhow!("config must contain input/output or jobs"))?;
        let output = self
            .output
            .ok_or_else(|| anyhow::anyhow!("config must contain input/output or jobs"))?;
        ConfigJobFile {
            input,
            output,
            input_format: self.input_format,
            input_target: self.input_target,
            input_behavior: self.input_behavior,
            output_format: self.output_format,
            output_target: self.output_target,
            output_behavior: self.output_behavior,
        }
        .into_job(base, &self.defaults)
        .map(|job| vec![job])
    }
}

impl ConfigJobFile {
    fn into_job(self, base: &Path, defaults: &ConfigDefaults) -> Result<ConfigJob> {
        let input_format = self
            .input_format
            .as_deref()
            .or(defaults.input_format.as_deref())
            .map(InputFormat::parse_arg)
            .transpose()?;
        let input_target = self
            .input_target
            .as_deref()
            .or(defaults.input_target.as_deref())
            .map(RuleTarget::parse_arg)
            .transpose()?;
        let input_behavior = self
            .input_behavior
            .as_deref()
            .or(defaults.input_behavior.as_deref())
            .map(InputBehaviorMode::parse_arg)
            .transpose()?
            .unwrap_or(InputBehaviorMode::Auto);
        let output_format = self
            .output_format
            .as_deref()
            .or(defaults.output_format.as_deref())
            .map(OutputFormat::parse_arg)
            .transpose()?
            .unwrap_or(OutputFormat::Mrs);
        let output_target = self
            .output_target
            .as_deref()
            .or(defaults.output_target.as_deref())
            .map(RuleTarget::parse_arg)
            .transpose()?
            .unwrap_or(RuleTarget::Mihomo);
        let output_behavior = self
            .output_behavior
            .as_deref()
            .or(defaults.output_behavior.as_deref())
            .map(BehaviorMode::parse_arg)
            .transpose()?
            .unwrap_or_else(|| crate::api::default_output_behavior(output_target, output_format));

        Ok(ConfigJob {
            input: self.input.resolve(base)?,
            output: resolve_config_path(base, self.output),
            options: ConvertOptions {
                input_target,
                input_format,
                input_behavior,
                output_target,
                output_format,
                output_behavior,
            },
        })
    }
}

fn resolve_config_path(base: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        return path;
    }
    base.join(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_yaml_job_with_defaults() {
        let raw = r#"
defaults:
  input_target: egern
  input_format: yaml
  input_behavior: auto
  output_target: egern
  output_format: ruleset
  output_behavior: domain
input: rules/egern.yaml
output: dist/rules.yaml
"#;
        let config: ConfigFile = serde_yaml::from_str(raw).unwrap();
        let jobs = config.into_jobs(Path::new("/tmp/base")).unwrap();

        assert_eq!(jobs.len(), 1);
        assert_eq!(
            jobs[0].input,
            vec![PathBuf::from("/tmp/base/rules/egern.yaml")]
        );
        assert_eq!(jobs[0].options.input_target, Some(RuleTarget::Egern));
        assert_eq!(jobs[0].options.input_format, Some(InputFormat::Yaml));
        assert_eq!(jobs[0].options.input_behavior, InputBehaviorMode::Auto);
        assert_eq!(jobs[0].options.output_target, RuleTarget::Egern);
        assert_eq!(jobs[0].options.output_format, OutputFormat::RuleSet);
        assert_eq!(jobs[0].options.output_behavior, BehaviorMode::Domain);
    }

    #[test]
    fn parses_json_jobs() {
        let raw = r#"{
  "defaults": { "input_target": "general", "input_format": "text", "output_format": "mrs" },
  "jobs": [
    { "input": "a.list", "output": "a.mrs" },
    { "input": "b.yaml", "output": "b.yaml", "input_target": "egern", "input_format": "yaml", "output_target": "egern", "output_format": "ruleset" }
  ]
}"#;
        let config: ConfigFile = serde_json::from_str(raw).unwrap();
        let jobs = config.into_jobs(Path::new("/tmp/base")).unwrap();

        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].options.input_target, Some(RuleTarget::General));
        assert_eq!(jobs[0].options.input_format, Some(InputFormat::Text));
        assert_eq!(jobs[1].options.input_target, Some(RuleTarget::Egern));
        assert_eq!(jobs[1].options.input_format, Some(InputFormat::Yaml));
        assert_eq!(jobs[1].options.output_target, RuleTarget::Egern);
        assert_eq!(jobs[1].options.output_format, OutputFormat::RuleSet);
    }

    #[test]
    fn parses_toml_jobs() {
        let raw = r#"
[defaults]
input_target = "mihomo"
input_format = "yaml"
output_format = "mrs"

[[jobs]]
input = "rules.yaml"
output = "rules.mrs"
input_behavior = "classical"
output_behavior = "domain"
"#;
        let config: ConfigFile = toml::from_str(raw).unwrap();
        let jobs = config.into_jobs(Path::new("/tmp/base")).unwrap();

        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].options.input_target, Some(RuleTarget::Mihomo));
        assert_eq!(jobs[0].options.input_format, Some(InputFormat::Yaml));
        assert_eq!(jobs[0].options.input_behavior, InputBehaviorMode::Classical);
        assert_eq!(jobs[0].options.output_behavior, BehaviorMode::Domain);
    }

    #[test]
    fn parses_input_list() {
        let raw = r#"
input:
  - rules/a.yaml
  - rules/b.yaml
output: dist/rules.mrs
"#;
        let config: ConfigFile = serde_yaml::from_str(raw).unwrap();
        let jobs = config.into_jobs(Path::new("/tmp/base")).unwrap();

        assert_eq!(
            jobs[0].input,
            vec![
                PathBuf::from("/tmp/base/rules/a.yaml"),
                PathBuf::from("/tmp/base/rules/b.yaml")
            ]
        );
    }
}
