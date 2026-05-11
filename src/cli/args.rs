use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use rule_converter::{ConfigJob, ConvertOptions, FileInput, InputBehaviorMode, RuleConfigJob};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Convert and match rule files between supported targets and formats"
)]
pub(super) struct Cli {
    #[command(subcommand)]
    pub(super) command: Command,
}

#[derive(Debug, Subcommand)]
pub(super) enum Command {
    /// Convert rule files between supported targets and formats.
    Convert(ConvertCli),
    /// Detect input file type without converting it.
    Detect(DetectCli),
    /// List indexes contained in a DB input file.
    List(ListCli),
    /// Match a domain or IP against rule files.
    Match(MatchCli),
}

#[derive(Debug, Parser)]
pub(super) struct DetectCli {
    /// Input file(s) to inspect.
    #[arg(value_name = "PATH", num_args = 1..)]
    pub(super) paths: Vec<PathBuf>,
}

#[derive(Debug, Parser)]
pub(super) struct ConvertCli {
    #[arg(value_name = "PATH", num_args = 0..)]
    pub(super) paths: Vec<PathBuf>,

    #[arg(short, long)]
    pub(super) config: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = RuleTargetArg::Mihomo)]
    pub(super) output_target: RuleTargetArg,

    #[arg(long, value_enum, default_value_t = OutputFormatArg::Mrs)]
    pub(super) output_format: OutputFormatArg,

    /// Output behavior. Omit to infer from the output target and format.
    #[arg(long, value_enum)]
    pub(super) output_behavior: Option<BehaviorArg>,
}

#[derive(Debug, Parser)]
pub(super) struct ListCli {
    /// Input DB file to inspect.
    pub(super) path: PathBuf,
}

#[derive(Debug, Parser)]
pub(super) struct MatchCli {
    pub(super) query: String,

    #[arg(value_name = "PATH", num_args = 1..)]
    pub(super) paths: Vec<PathBuf>,

    /// Input rule target.
    #[arg(long, value_enum)]
    pub(super) input_target: Option<MatchTargetArg>,

    /// Input format.
    #[arg(long, value_enum)]
    pub(super) input_format: Option<MatchFormatArg>,

    /// Input behavior.
    #[arg(long, value_enum)]
    pub(super) input_behavior: Option<InputBehaviorArg>,
}

impl ConvertCli {
    pub(super) fn into_jobs(self) -> Result<Vec<ConfigJob>> {
        if let Some(config) = self.config {
            if !self.paths.is_empty() {
                anyhow::bail!("--config cannot be combined with positional paths");
            }
            return rule_converter::load_config(config);
        }

        if self.paths.len() < 2 {
            anyhow::bail!("missing input path(s) and output path, or --config");
        }

        let mut paths = self.paths;
        let output = paths.pop().expect("paths length checked");
        let input_target = None;
        let input_format = None;
        let input_behavior = InputBehaviorMode::Auto;
        let output_target = self.output_target.into();
        let output_format = self.output_format.into();
        let output_behavior = self.output_behavior.map(Into::into).unwrap_or_else(|| {
            rule_converter::default_output_behavior(output_target, output_format)
        });
        let input = paths
            .into_iter()
            .map(|path| FileInput {
                path,
                target: input_target,
                format: input_format,
                behavior: input_behavior,
            })
            .collect();

        Ok(vec![ConfigJob::Rules(RuleConfigJob {
            input,
            output,
            options: ConvertOptions {
                input_target,
                input_format,
                input_behavior,
                output_target,
                output_format,
                output_behavior,
            },
        })])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(super) enum InputBehaviorArg {
    Auto,
    Domain,
    Ip,
    Classical,
}

impl From<InputBehaviorArg> for InputBehaviorMode {
    fn from(value: InputBehaviorArg) -> Self {
        match value {
            InputBehaviorArg::Auto => InputBehaviorMode::Auto,
            InputBehaviorArg::Domain => InputBehaviorMode::Domain,
            InputBehaviorArg::Ip => InputBehaviorMode::Ipcidr,
            InputBehaviorArg::Classical => InputBehaviorMode::Classical,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(super) enum BehaviorArg {
    Domain,
    Ip,
    Classical,
}

impl From<BehaviorArg> for rule_converter::BehaviorMode {
    fn from(value: BehaviorArg) -> Self {
        match value {
            BehaviorArg::Domain => rule_converter::BehaviorMode::Domain,
            BehaviorArg::Ip => rule_converter::BehaviorMode::Ipcidr,
            BehaviorArg::Classical => rule_converter::BehaviorMode::Classical,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(super) enum RuleTargetArg {
    Mihomo,
    General,
    Egern,
    SingBox,
}

impl From<RuleTargetArg> for rule_converter::RuleTarget {
    fn from(value: RuleTargetArg) -> Self {
        match value {
            RuleTargetArg::Mihomo => rule_converter::RuleTarget::Mihomo,
            RuleTargetArg::General => rule_converter::RuleTarget::General,
            RuleTargetArg::Egern => rule_converter::RuleTarget::Egern,
            RuleTargetArg::SingBox => rule_converter::RuleTarget::SingBox,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(super) enum MatchTargetArg {
    Mihomo,
    General,
    Egern,
    SingBox,
    Geoip,
    Geosite,
    Asn,
}

impl From<MatchTargetArg> for rule_converter::MatchInputTarget {
    fn from(value: MatchTargetArg) -> Self {
        match value {
            MatchTargetArg::Mihomo => rule_converter::RuleTarget::Mihomo.into(),
            MatchTargetArg::General => rule_converter::RuleTarget::General.into(),
            MatchTargetArg::Egern => rule_converter::RuleTarget::Egern.into(),
            MatchTargetArg::SingBox => rule_converter::RuleTarget::SingBox.into(),
            MatchTargetArg::Geoip => rule_converter::MatchInputTarget::Geoip,
            MatchTargetArg::Geosite => rule_converter::MatchInputTarget::Geosite,
            MatchTargetArg::Asn => rule_converter::MatchInputTarget::Asn,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(super) enum InputFormatArg {
    Yaml,
    Mrs,
    Text,
    Json,
    Srs,
    Domainset,
    Ruleset,
    Ipset,
}

impl From<InputFormatArg> for rule_converter::InputFormat {
    fn from(value: InputFormatArg) -> Self {
        match value {
            InputFormatArg::Yaml => rule_converter::InputFormat::Yaml,
            InputFormatArg::Mrs => rule_converter::InputFormat::Mrs,
            InputFormatArg::Text
            | InputFormatArg::Domainset
            | InputFormatArg::Ruleset
            | InputFormatArg::Ipset => rule_converter::InputFormat::Text,
            InputFormatArg::Json => rule_converter::InputFormat::Json,
            InputFormatArg::Srs => rule_converter::InputFormat::Srs,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(super) enum MatchFormatArg {
    Yaml,
    Mrs,
    Text,
    Json,
    Srs,
    Domainset,
    Ruleset,
    Ipset,
    Dat,
    SingGeosite,
    Mmdb,
    SingDb,
    Metadb,
}

impl From<MatchFormatArg> for rule_converter::MatchInputFormat {
    fn from(value: MatchFormatArg) -> Self {
        match value {
            MatchFormatArg::Yaml => rule_converter::InputFormat::Yaml.into(),
            MatchFormatArg::Mrs => rule_converter::InputFormat::Mrs.into(),
            MatchFormatArg::Text
            | MatchFormatArg::Domainset
            | MatchFormatArg::Ruleset
            | MatchFormatArg::Ipset => rule_converter::InputFormat::Text.into(),
            MatchFormatArg::Json => rule_converter::InputFormat::Json.into(),
            MatchFormatArg::Srs => rule_converter::InputFormat::Srs.into(),
            MatchFormatArg::Dat => rule_converter::MatchInputFormat::Dat,
            MatchFormatArg::SingGeosite => rule_converter::MatchInputFormat::SingGeosite,
            MatchFormatArg::Mmdb | MatchFormatArg::SingDb | MatchFormatArg::Metadb => {
                rule_converter::MatchInputFormat::Mmdb
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(super) enum OutputFormatArg {
    Mrs,
    Text,
    Yaml,
    Json,
    Srs,
    Domainset,
    Ruleset,
    Ipset,
}

impl From<OutputFormatArg> for rule_converter::OutputFormat {
    fn from(value: OutputFormatArg) -> Self {
        match value {
            OutputFormatArg::Mrs => rule_converter::OutputFormat::Mrs,
            OutputFormatArg::Text => rule_converter::OutputFormat::Text,
            OutputFormatArg::Yaml => rule_converter::OutputFormat::Yaml,
            OutputFormatArg::Json => rule_converter::OutputFormat::Json,
            OutputFormatArg::Srs => rule_converter::OutputFormat::Srs,
            OutputFormatArg::Domainset => rule_converter::OutputFormat::DomainSet,
            OutputFormatArg::Ruleset => rule_converter::OutputFormat::RuleSet,
            OutputFormatArg::Ipset => rule_converter::OutputFormat::IpSet,
        }
    }
}
