use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use rule_converter::{
    BehaviorMode, ConfigJob, ConvertOptions, InputBehaviorMode, InputFormat, OutputFormat,
    RuleTarget, convert_files, convert_files_to_path_streaming, load_config,
    write_outputs_as_owned,
};

fn main() -> Result<()> {
    let cli = Cli::parse();
    configure_threads(cli.threads)?;
    let jobs = cli.into_jobs()?;

    for job in jobs {
        run_job(job)?;
    }

    Ok(())
}

#[cfg(feature = "parallel")]
fn configure_threads(threads: Option<usize>) -> Result<()> {
    let Some(threads) = threads else {
        return Ok(());
    };
    if threads == 0 {
        anyhow::bail!("--threads must be greater than 0");
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
        .map_err(|err| anyhow::anyhow!("failed to configure worker threads: {err}"))
}

#[cfg(not(feature = "parallel"))]
fn configure_threads(threads: Option<usize>) -> Result<()> {
    if threads.is_some() {
        anyhow::bail!("--threads requires the `parallel` feature");
    }
    Ok(())
}

fn run_job(job: ConfigJob) -> Result<()> {
    if let Some((files, skipped)) =
        convert_files_to_path_streaming(&job.input, &job.output, job.options)?
    {
        return report_result(files, skipped);
    }

    let result = convert_files(&job.input, job.options)?;
    let (files, skipped) = write_outputs_as_owned(
        result,
        &job.output,
        job.options.output_target,
        job.options.output_format,
    )?;

    report_result(files, skipped)
}

fn report_result(
    files: Vec<rule_converter::OutputFile>,
    skipped: Vec<rule_converter::SkippedRule>,
) -> Result<()> {
    for file in files {
        eprintln!(
            "wrote {} rules to {} ({})",
            file.count,
            file.path.display(),
            file.behavior.as_str()
        );
    }

    if !skipped.is_empty() {
        eprintln!("skipped {} unsupported rules", skipped.len());
        for item in skipped.iter().take(10) {
            eprintln!("  - {}: {}", item.reason, item.rule);
        }
        if skipped.len() > 10 {
            eprintln!("  ... {} more", skipped.len() - 10);
        }
    }

    Ok(())
}

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Convert rule files between supported targets and formats"
)]
struct Cli {
    /// Source rule file(s), followed by the target output file.
    #[arg(value_name = "PATH", num_args = 0..)]
    paths: Vec<PathBuf>,

    /// YAML, TOML, or JSON automation config. Supports a single job or a jobs list.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Input rule target override. Omit to auto-detect.
    #[arg(long, value_enum)]
    input_target: Option<RuleTargetArg>,

    /// Input format override. Omit to auto-detect.
    #[arg(long, value_enum)]
    input_format: Option<InputFormatArg>,

    /// Input behavior hint. Use when auto-detection cannot distinguish text/domain/classical intent.
    #[arg(long, value_enum, default_value_t = InputBehaviorArg::Auto)]
    input_behavior: InputBehaviorArg,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormatArg::Mrs)]
    output_format: OutputFormatArg,

    /// Output rule target.
    #[arg(long, value_enum, default_value_t = RuleTargetArg::Mihomo)]
    output_target: RuleTargetArg,

    /// Output behavior. Use domain, ip, or classical. Omit to infer from output format.
    #[arg(long, value_enum)]
    output_behavior: Option<BehaviorArg>,

    /// Worker thread count for CPU-heavy conversion stages.
    #[arg(long)]
    threads: Option<usize>,
}

impl Cli {
    fn into_jobs(self) -> Result<Vec<ConfigJob>> {
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
        let input = paths;
        let input_target = self.input_target.map(Into::into);
        let input_format = self.input_format.map(Into::into);
        let input_behavior = self.input_behavior.into();
        let output_target = self.output_target.into();
        let output_format = self.output_format.into();
        let output_behavior = self.output_behavior.map(Into::into).unwrap_or_else(|| {
            rule_converter::default_output_behavior(output_target, output_format)
        });

        Ok(vec![ConfigJob {
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
        }])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum BehaviorArg {
    Domain,
    Ip,
    Classical,
}

impl From<BehaviorArg> for BehaviorMode {
    fn from(value: BehaviorArg) -> Self {
        match value {
            BehaviorArg::Domain => Self::Domain,
            BehaviorArg::Ip => Self::Ipcidr,
            BehaviorArg::Classical => Self::Classical,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum InputBehaviorArg {
    Auto,
    Domain,
    Ip,
    Classical,
}

impl From<InputBehaviorArg> for InputBehaviorMode {
    fn from(value: InputBehaviorArg) -> Self {
        match value {
            InputBehaviorArg::Auto => Self::Auto,
            InputBehaviorArg::Domain => Self::Domain,
            InputBehaviorArg::Ip => Self::Ipcidr,
            InputBehaviorArg::Classical => Self::Classical,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum RuleTargetArg {
    Mihomo,
    General,
    Egern,
    SingBox,
}

impl From<RuleTargetArg> for RuleTarget {
    fn from(value: RuleTargetArg) -> Self {
        match value {
            RuleTargetArg::Mihomo => Self::Mihomo,
            RuleTargetArg::General => Self::General,
            RuleTargetArg::Egern => Self::Egern,
            RuleTargetArg::SingBox => Self::SingBox,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum InputFormatArg {
    Yaml,
    Mrs,
    Text,
    Json,
    Srs,
}

impl From<InputFormatArg> for InputFormat {
    fn from(value: InputFormatArg) -> Self {
        match value {
            InputFormatArg::Yaml => Self::Yaml,
            InputFormatArg::Mrs => Self::Mrs,
            InputFormatArg::Text => Self::Text,
            InputFormatArg::Json => Self::Json,
            InputFormatArg::Srs => Self::Srs,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum OutputFormatArg {
    Mrs,
    Text,
    Yaml,
    Json,
    Srs,
    #[value(name = "domainset")]
    DomainSet,
    #[value(name = "ruleset")]
    RuleSet,
    #[value(name = "ipset")]
    IpSet,
}

impl From<OutputFormatArg> for OutputFormat {
    fn from(value: OutputFormatArg) -> Self {
        match value {
            OutputFormatArg::Mrs => Self::Mrs,
            OutputFormatArg::Text => Self::Text,
            OutputFormatArg::Yaml => Self::Yaml,
            OutputFormatArg::Json => Self::Json,
            OutputFormatArg::Srs => Self::Srs,
            OutputFormatArg::DomainSet => Self::DomainSet,
            OutputFormatArg::RuleSet => Self::RuleSet,
            OutputFormatArg::IpSet => Self::IpSet,
        }
    }
}
