use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use rule_converter::{
    BehaviorMode, ConfigJob, ConvertOptions, FileInput, InputBehaviorMode, MatchInputFormat,
    MatchInputTarget, OutputFormat, RuleConfigJob, RuleTarget, load_config,
};

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
    /// Match a domain or IP against rule files.
    Match(MatchCli),
}

#[derive(Debug, Parser)]
pub(super) struct ConvertCli {
    /// Source rule file(s), followed by the target output file.
    #[arg(value_name = "PATH", num_args = 0..)]
    pub(super) paths: Vec<PathBuf>,

    /// YAML, TOML, or JSON automation config. Supports a single job or a jobs list.
    #[arg(short, long)]
    pub(super) config: Option<PathBuf>,

    /// Output rule target.
    #[arg(long, value_enum, default_value_t = RuleTargetArg::Mihomo)]
    pub(super) output_target: RuleTargetArg,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormatArg::Mrs)]
    pub(super) output_format: OutputFormatArg,

    /// Output behavior. Omit to infer from the output target and format.
    #[arg(long, value_enum)]
    pub(super) output_behavior: Option<BehaviorArg>,

    /// List GeoIP country codes or ASN numbers from an MMDB file.
    #[arg(long, value_enum)]
    pub(super) list: Option<DbListArg>,
}

#[derive(Debug, Parser)]
pub(super) struct MatchCli {
    /// Domain name or IP address to match.
    pub(super) query: String,

    /// Rule input file(s), directory, or wildcard path.
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
            return load_config(config);
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
pub(super) enum DbListArg {
    Geoip,
    Asn,
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

impl From<BehaviorArg> for BehaviorMode {
    fn from(value: BehaviorArg) -> Self {
        match value {
            BehaviorArg::Domain => BehaviorMode::Domain,
            BehaviorArg::Ip => BehaviorMode::Ipcidr,
            BehaviorArg::Classical => BehaviorMode::Classical,
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

impl From<RuleTargetArg> for RuleTarget {
    fn from(value: RuleTargetArg) -> Self {
        match value {
            RuleTargetArg::Mihomo => RuleTarget::Mihomo,
            RuleTargetArg::General => RuleTarget::General,
            RuleTargetArg::Egern => RuleTarget::Egern,
            RuleTargetArg::SingBox => RuleTarget::SingBox,
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

impl From<MatchTargetArg> for MatchInputTarget {
    fn from(value: MatchTargetArg) -> Self {
        match value {
            MatchTargetArg::Mihomo => RuleTarget::Mihomo.into(),
            MatchTargetArg::General => RuleTarget::General.into(),
            MatchTargetArg::Egern => RuleTarget::Egern.into(),
            MatchTargetArg::SingBox => RuleTarget::SingBox.into(),
            MatchTargetArg::Geoip => MatchInputTarget::Geoip,
            MatchTargetArg::Geosite => MatchInputTarget::Geosite,
            MatchTargetArg::Asn => MatchInputTarget::Asn,
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
    Mmdb,
    SingDb,
    Metadb,
}

impl From<MatchFormatArg> for MatchInputFormat {
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
            MatchFormatArg::Dat => MatchInputFormat::Dat,
            MatchFormatArg::Mmdb | MatchFormatArg::SingDb | MatchFormatArg::Metadb => {
                MatchInputFormat::Mmdb
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

impl From<OutputFormatArg> for OutputFormat {
    fn from(value: OutputFormatArg) -> Self {
        match value {
            OutputFormatArg::Mrs => OutputFormat::Mrs,
            OutputFormatArg::Text => OutputFormat::Text,
            OutputFormatArg::Yaml => OutputFormat::Yaml,
            OutputFormatArg::Json => OutputFormat::Json,
            OutputFormatArg::Srs => OutputFormat::Srs,
            OutputFormatArg::Domainset => OutputFormat::DomainSet,
            OutputFormatArg::Ruleset => OutputFormat::RuleSet,
            OutputFormatArg::Ipset => OutputFormat::IpSet,
        }
    }
}
