use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::{
    BehaviorMode, ConvertOptions, FileInput, InputBehaviorMode, InputFormat, OutputFormat,
    RuleTarget, codec::db::MmdbFormat,
};

mod db;
mod file;
mod input;
mod job;
mod output;

#[cfg(test)]
mod db_build_tests;
#[cfg(test)]
mod db_export_tests;
#[cfg(test)]
mod db_geosite_tests;
#[cfg(test)]
mod rule_tests;

pub use file::load_config;

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
    Geosite,
    Asn,
}

impl DbTarget {
    pub fn parse(value: &str) -> Option<Self> {
        if value.eq_ignore_ascii_case("geoip") {
            Some(Self::Geoip)
        } else if value.eq_ignore_ascii_case("geosite") {
            Some(Self::Geosite)
        } else if value.eq_ignore_ascii_case("asn") {
            Some(Self::Asn)
        } else {
            None
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Geoip => "geoip",
            Self::Geosite => "geosite",
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
    #[serde(alias = "code")]
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
    #[serde(
        default,
        alias = "country",
        alias = "countrys",
        alias = "code",
        alias = "codes"
    )]
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

fn resolve_config_path(base: &Path, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        return path;
    }
    base.join(path)
}
