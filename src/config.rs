use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::{
    BehaviorMode, ConvertOptions, FileInput, InputBehaviorMode, InputFormat, OutputFormat,
    RuleTarget, codec::db::MmdbFormat,
};

#[derive(Clone, Debug)]
pub enum ConfigJob {
    Rules(RuleConfigJob),
    Db(DbConfigJob),
}

#[derive(Clone, Debug)]
pub struct RuleConfigJob {
    pub input: Vec<FileInput>,
    pub output: PathBuf,
    pub options: ConvertOptions,
}

#[derive(Clone, Debug)]
pub enum DbConfigJob {
    Export {
        target: DbTarget,
        format: MmdbFormat,
        input: PathBuf,
        output: DbExportOutput,
        countries: Vec<String>,
        asns: Vec<u32>,
    },
    Build {
        target: DbTarget,
        format: MmdbFormat,
        input: Vec<DbInputPath>,
        output: PathBuf,
    },
    Convert {
        target: DbTarget,
        input_format: MmdbFormat,
        output_format: MmdbFormat,
        input: PathBuf,
        output: PathBuf,
        countries: Vec<String>,
        asns: Vec<u32>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DbTarget {
    Geoip,
    Asn,
}

impl DbTarget {
    pub fn parse(value: &str) -> Option<Self> {
        if value.eq_ignore_ascii_case("geoip") {
            Some(Self::Geoip)
        } else if value.eq_ignore_ascii_case("asn") {
            Some(Self::Asn)
        } else {
            None
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Geoip => "geoip",
            Self::Asn => "asn",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DbInputPath {
    Country { country: String, input: FileInput },
    Asn { asn: u32, input: FileInput },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DbExportOutput {
    pub base: PathBuf,
    pub split: bool,
    pub target: RuleTarget,
    pub format: OutputFormat,
    pub behavior: BehaviorMode,
}

impl RuleConfigJob {
    pub fn single_input(&self) -> Option<&Path> {
        match self.input.as_slice() {
            [input] => Some(input.path.as_path()),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    #[serde(default)]
    defaults: ConfigDefaults,
    jobs: Vec<ConfigJobFile>,
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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigJobFile {
    input: ConfigInputFile,
    output: Option<ConfigOutputFile>,
    outputs: Option<Vec<ConfigOutputFile>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigInputFile {
    path: Option<PathBuf>,
    inputs: Option<Vec<ConfigInputPath>>,
    target: Option<String>,
    format: Option<String>,
    behavior: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum ConfigInputPath {
    Path(ConfigPathInput),
    Country(ConfigCountryInputPath),
    Asn(ConfigAsnInputPath),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum ConfigPathInput {
    Path(PathBuf),
    Options(ConfigRuleInputPath),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigRuleInputPath {
    path: PathBuf,
    target: Option<String>,
    format: Option<String>,
    behavior: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigCountryInputPath {
    country: String,
    path: PathBuf,
    target: Option<String>,
    format: Option<String>,
    behavior: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigAsnInputPath {
    asn: u32,
    path: PathBuf,
    target: Option<String>,
    format: Option<String>,
    behavior: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigOutputFile {
    path: Option<PathBuf>,
    dir: Option<PathBuf>,
    #[serde(default, alias = "country", alias = "countrys")]
    countries: Option<OneOrMany<String>>,
    #[serde(default, alias = "asn")]
    asns: Option<OneOrMany<u32>>,
    target: Option<String>,
    format: Option<String>,
    behavior: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    fn into_vec(self) -> Vec<T> {
        match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        }
    }
}

impl ConfigOutputFile {
    fn countries(&self) -> Vec<String> {
        self.countries
            .clone()
            .map(OneOrMany::into_vec)
            .unwrap_or_default()
    }

    fn asns(&self) -> Vec<u32> {
        self.asns
            .clone()
            .map(OneOrMany::into_vec)
            .unwrap_or_default()
    }
}

impl ConfigInputFile {
    fn rule_inputs(self, base: &Path) -> Result<Vec<FileInput>> {
        let parent_options = InputItemOptions {
            target: self.target,
            format: self.format,
            behavior: self.behavior,
        };
        match (self.path, self.inputs) {
            (Some(path), None) => Ok(vec![file_input_from_parts(base, path, parent_options)?]),
            (None, Some(inputs)) if !inputs.is_empty() => inputs
                .into_iter()
                .map(|input| match input {
                    ConfigInputPath::Path(path) => {
                        file_input_from_config(base, path, parent_options.clone())
                    }
                    ConfigInputPath::Country(_) | ConfigInputPath::Asn(_) => {
                        bail!("config rule inputs must not contain country or asn")
                    }
                })
                .collect(),
            (Some(_), Some(_)) => bail!("config input cannot contain both path and inputs"),
            (None, Some(_)) | (None, None) => bail!("config input must contain path or inputs"),
        }
    }

    fn single_path(self, base: &Path) -> Result<PathBuf> {
        match (self.path, self.inputs) {
            (Some(path), None) => Ok(resolve_config_path(base, path)),
            (None, Some(inputs)) => match inputs.as_slice() {
                [ConfigInputPath::Path(ConfigPathInput::Path(path))] => {
                    Ok(resolve_config_path(base, path.clone()))
                }
                [ConfigInputPath::Path(ConfigPathInput::Options(input))] => {
                    Ok(resolve_config_path(base, input.path.clone()))
                }
                _ => bail!("config input needs exactly one path"),
            },
            (Some(_), Some(_)) => bail!("config input cannot contain both path and inputs"),
            (None, None) => bail!("config input must contain path"),
        }
    }

    fn db_paths(self, base: &Path, target: DbTarget) -> Result<Vec<DbInputPath>> {
        let parent_options = InputItemOptions {
            target: self.target,
            format: self.format,
            behavior: self.behavior,
        };
        match (self.path, self.inputs) {
            (None, Some(inputs)) if !inputs.is_empty() => inputs
                .into_iter()
                .map(|path| match path {
                    ConfigInputPath::Country(path) if target == DbTarget::Geoip => {
                        let options = merge_input_options(
                            path.target,
                            path.format,
                            path.behavior,
                            parent_options.clone(),
                        );
                        Ok(DbInputPath::Country {
                            country: path.country,
                            input: file_input_from_parts(base, path.path, options)?,
                        })
                    }
                    ConfigInputPath::Asn(path) if target == DbTarget::Asn => {
                        let options = merge_input_options(
                            path.target,
                            path.format,
                            path.behavior,
                            parent_options.clone(),
                        );
                        Ok(DbInputPath::Asn {
                            asn: path.asn,
                            input: file_input_from_parts(base, path.path, options)?,
                        })
                    }
                    ConfigInputPath::Country(_) => bail!("ASN DB input needs asn and path"),
                    ConfigInputPath::Asn(_) => bail!("GeoIP DB input needs country and path"),
                    ConfigInputPath::Path(_) => bail!(
                        "{} DB build input needs typed path entries",
                        target.as_str()
                    ),
                })
                .collect(),
            (Some(_), None) => bail!("{} DB build input needs typed entries", target.as_str()),
            (Some(_), Some(_)) => bail!("config input cannot contain both path and inputs"),
            (None, Some(_)) | (None, None) => bail!("config input must contain inputs"),
        }
    }
}

#[derive(Clone)]
struct InputItemOptions {
    target: Option<String>,
    format: Option<String>,
    behavior: Option<String>,
}

fn file_input_from_config(
    base: &Path,
    input: ConfigPathInput,
    parent: InputItemOptions,
) -> Result<FileInput> {
    match input {
        ConfigPathInput::Path(path) => file_input_from_parts(base, path, parent),
        ConfigPathInput::Options(input) => {
            let options = merge_input_options(input.target, input.format, input.behavior, parent);
            file_input_from_parts(base, input.path, options)
        }
    }
}

fn merge_input_options(
    target: Option<String>,
    format: Option<String>,
    behavior: Option<String>,
    parent: InputItemOptions,
) -> InputItemOptions {
    InputItemOptions {
        target: target.or(parent.target),
        format: format.or(parent.format),
        behavior: behavior.or(parent.behavior),
    }
}

fn file_input_from_parts(
    base: &Path,
    path: PathBuf,
    options: InputItemOptions,
) -> Result<FileInput> {
    let (format, format_behavior) = options
        .format
        .as_deref()
        .map(parse_config_input_format)
        .transpose()?
        .unwrap_or((None, InputBehaviorMode::Auto));
    let behavior = options
        .behavior
        .as_deref()
        .map(InputBehaviorMode::parse_arg)
        .transpose()?
        .unwrap_or(format_behavior);

    Ok(FileInput {
        path: resolve_config_path(base, path),
        target: options
            .target
            .as_deref()
            .map(RuleTarget::parse_arg)
            .transpose()?,
        format,
        behavior,
    })
}

fn parse_config_input_format(value: &str) -> Result<(Option<InputFormat>, InputBehaviorMode)> {
    match value.to_ascii_lowercase().as_str() {
        "domainset" => Ok((Some(InputFormat::Text), InputBehaviorMode::Domain)),
        "ipset" => Ok((Some(InputFormat::Text), InputBehaviorMode::Ipcidr)),
        "ruleset" => Ok((Some(InputFormat::Text), InputBehaviorMode::Classical)),
        _ => Ok((
            Some(InputFormat::parse_arg(value)?),
            InputBehaviorMode::Auto,
        )),
    }
}

impl ConfigOutputFile {
    fn path(&self, base: &Path) -> Result<PathBuf> {
        match (&self.path, &self.dir) {
            (Some(path), None) => Ok(resolve_config_path(base, path.clone())),
            (None, Some(_)) => bail!("config output needs path for this job"),
            (Some(_), Some(_)) => bail!("config output cannot contain both path and dir"),
            (None, None) => bail!("config output must contain path"),
        }
    }

    fn db_export_output(&self, base: &Path, defaults: &ConfigDefaults) -> Result<DbExportOutput> {
        let (base, split) = match (&self.path, &self.dir) {
            (Some(path), None) => (resolve_config_path(base, path.clone()), false),
            (None, Some(dir)) => (resolve_config_path(base, dir.clone()), true),
            (Some(_), Some(_)) => bail!("config output cannot contain both path and dir"),
            (None, None) => bail!("config output must contain path or dir"),
        };
        let target = self
            .target
            .as_deref()
            .or(defaults.output_target.as_deref())
            .map(RuleTarget::parse_arg)
            .transpose()?
            .unwrap_or(RuleTarget::General);
        let format = self
            .format
            .as_deref()
            .or(defaults.output_format.as_deref())
            .map(OutputFormat::parse_arg)
            .transpose()?
            .unwrap_or(OutputFormat::IpSet);
        let behavior = self
            .behavior
            .as_deref()
            .map(BehaviorMode::parse_arg)
            .transpose()?
            .unwrap_or(BehaviorMode::Ipcidr);

        Ok(DbExportOutput {
            base,
            split,
            target,
            format,
            behavior,
        })
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
        if self.jobs.is_empty() {
            bail!("config jobs must not be empty");
        }
        let mut jobs = Vec::new();
        for job in self.jobs {
            jobs.extend(job.into_jobs(base, &self.defaults)?);
        }
        Ok(jobs)
    }
}

impl ConfigJobFile {
    fn into_jobs(self, base: &Path, defaults: &ConfigDefaults) -> Result<Vec<ConfigJob>> {
        let outputs = match (self.output, self.outputs) {
            (Some(output), None) => vec![output],
            (None, Some(outputs)) if !outputs.is_empty() => outputs,
            (Some(_), Some(_)) => bail!("config job cannot contain both output and outputs"),
            (None, Some(_)) => bail!("config outputs must not be empty"),
            (None, None) => bail!("config job must contain output or outputs"),
        };

        let mut jobs = Vec::with_capacity(outputs.len());
        for output in outputs {
            jobs.push(Self::into_job_for_output(
                self.input.clone(),
                output,
                base,
                defaults,
            )?);
        }
        Ok(jobs)
    }

    fn into_job_for_output(
        input: ConfigInputFile,
        output_file: ConfigOutputFile,
        base: &Path,
        defaults: &ConfigDefaults,
    ) -> Result<ConfigJob> {
        if let Some((target, input_format, output_format)) = db_convert_job(&input, &output_file)? {
            return Ok(ConfigJob::Db(DbConfigJob::Convert {
                target,
                input_format,
                output_format,
                input: input.single_path(base)?,
                output: output_file.path(base)?,
                countries: output_file.countries(),
                asns: output_file.asns(),
            }));
        }
        if let Some((target, format)) = db_export_job(&input, &output_file, defaults)? {
            let output = output_file.db_export_output(base, defaults)?;
            let countries = output_file.countries();
            let asns = output_file.asns();
            if !output.split {
                match target {
                    DbTarget::Geoip if countries.is_empty() => {
                        bail!("GeoIP DB export without country needs output.dir")
                    }
                    DbTarget::Asn if asns.is_empty() => {
                        bail!("ASN DB export without asn needs output.dir")
                    }
                    _ => {}
                }
            }
            return Ok(ConfigJob::Db(DbConfigJob::Export {
                target,
                format,
                input: input.single_path(base)?,
                output,
                countries,
                asns,
            }));
        }
        if let Some((target, format)) = db_build_job(&input, &output_file)? {
            return Ok(ConfigJob::Db(DbConfigJob::Build {
                target,
                format,
                input: input.db_paths(base, target)?,
                output: output_file.path(base)?,
            }));
        }

        let input_format = input
            .format
            .as_deref()
            .or(defaults.input_format.as_deref())
            .map(InputFormat::parse_arg)
            .transpose()?;
        let input_target = input
            .target
            .as_deref()
            .or(defaults.input_target.as_deref())
            .map(RuleTarget::parse_arg)
            .transpose()?;
        let input_behavior = input
            .behavior
            .as_deref()
            .or(defaults.input_behavior.as_deref())
            .map(InputBehaviorMode::parse_arg)
            .transpose()?
            .unwrap_or(InputBehaviorMode::Auto);
        let output_format = output_file
            .format
            .as_deref()
            .or(defaults.output_format.as_deref())
            .map(OutputFormat::parse_arg)
            .transpose()?
            .unwrap_or(OutputFormat::Mrs);
        let output_target = output_file
            .target
            .as_deref()
            .or(defaults.output_target.as_deref())
            .map(RuleTarget::parse_arg)
            .transpose()?
            .unwrap_or(RuleTarget::Mihomo);
        let output_behavior = output_file
            .behavior
            .as_deref()
            .or(defaults.output_behavior.as_deref())
            .map(BehaviorMode::parse_arg)
            .transpose()?
            .unwrap_or_else(|| crate::api::default_output_behavior(output_target, output_format));

        Ok(ConfigJob::Rules(RuleConfigJob {
            input: input.rule_inputs(base)?,
            output: output_file.path(base)?,
            options: ConvertOptions {
                input_target,
                input_format,
                input_behavior,
                output_target,
                output_format,
                output_behavior,
            },
        }))
    }
}

fn db_export_job(
    input: &ConfigInputFile,
    output: &ConfigOutputFile,
    defaults: &ConfigDefaults,
) -> Result<Option<(DbTarget, MmdbFormat)>> {
    let Some(target) = input.target.as_deref().and_then(DbTarget::parse) else {
        return Ok(None);
    };
    let format = parse_db_format(input.format.as_deref())?;
    validate_db_format(target, format)?;
    if !output.path.is_some() && !output.dir.is_some() {
        return Ok(None);
    }
    if output
        .target
        .as_deref()
        .or(defaults.output_target.as_deref())
        .and_then(DbTarget::parse)
        .is_some()
    {
        return Ok(None);
    }
    Ok(Some((target, format)))
}

fn db_build_job(
    input: &ConfigInputFile,
    output: &ConfigOutputFile,
) -> Result<Option<(DbTarget, MmdbFormat)>> {
    let Some(target) = output.target.as_deref().and_then(DbTarget::parse) else {
        return Ok(None);
    };
    let format = parse_db_format(output.format.as_deref())?;
    validate_db_format(target, format)?;
    if !input.inputs.is_some() || !output.path.is_some() {
        return Ok(None);
    }
    Ok(Some((target, format)))
}

fn db_convert_job(
    input: &ConfigInputFile,
    output: &ConfigOutputFile,
) -> Result<Option<(DbTarget, MmdbFormat, MmdbFormat)>> {
    let Some(input_target) = input.target.as_deref().and_then(DbTarget::parse) else {
        return Ok(None);
    };
    let Some(output_target) = output.target.as_deref().and_then(DbTarget::parse) else {
        return Ok(None);
    };
    if input_target != output_target || !input.path.is_some() || !output.path.is_some() {
        return Ok(None);
    }

    let input_format = parse_db_format(input.format.as_deref())?;
    let output_format = parse_db_format(output.format.as_deref())?;
    validate_db_format(input_target, input_format)?;
    validate_db_format(output_target, output_format)?;
    Ok(Some((input_target, input_format, output_format)))
}

fn parse_db_format(format: Option<&str>) -> Result<MmdbFormat> {
    format
        .map(MmdbFormat::parse)
        .transpose()
        .map(|value| value.unwrap_or(MmdbFormat::Mmdb))
}

fn validate_db_format(target: DbTarget, format: MmdbFormat) -> Result<()> {
    if target == DbTarget::Asn && format != MmdbFormat::Mmdb {
        bail!("ASN target only supports mmdb format");
    }
    Ok(())
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
                        behavior: BehaviorMode::Ipcidr,
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
}
