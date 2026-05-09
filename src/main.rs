use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, ValueEnum};
use rule_converter::{
    Behavior, BehaviorMode, ConfigJob, ConvertOptions, DbConfigJob, DbExportOutput, DbInputPath,
    DbTarget, FileInput, InputBehaviorMode, OutputFile, OutputFormat, RuleConfigJob, RuleSetOutput,
    RuleTarget, build_asn_mmdb_from_rule_sets, build_geoip_dat_from_rule_sets,
    build_geoip_mmdb_from_rule_sets, build_geosite_dat_from_rule_sets, collect_asn_mmdb_rule_set,
    collect_asn_mmdb_rule_sets, collect_geoip_dat_rule_set, collect_geoip_dat_rule_sets,
    collect_geoip_mmdb_rule_set, collect_geoip_mmdb_rule_sets, collect_geosite_dat_rule_set,
    collect_geosite_dat_rule_sets, convert_asn_mmdb, convert_file_inputs,
    convert_file_inputs_to_path_streaming, convert_geoip_db_to_memory_filtered,
    convert_geoip_mmdb_filtered, convert_rule_set_output, export_asn_mmdb_ipset_to_path,
    export_asn_mmdb_mrs_to_path, export_geoip_dat_ipset_to_dir, export_geoip_mmdb_ipset_to_path,
    export_geoip_mmdb_mrs_to_path, export_geosite_dat_general_ruleset_to_dir,
    export_geosite_dat_general_ruleset_to_path, filter_geoip_dat_to_path,
    filter_geosite_dat_to_path, list_asn_mmdb_asns, list_geoip_mmdb_countries, load_config,
    write_outputs_as_owned,
};

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Some(target) = cli.list {
        if cli.config.is_some() || cli.paths.len() != 1 {
            anyhow::bail!(
                "--list needs exactly one MMDB path and cannot be combined with --config"
            );
        }
        return run_db_list(target, &cli.paths[0]);
    }
    let jobs = cli.into_jobs()?;

    for job in jobs {
        run_job(job)?;
    }

    Ok(())
}

fn run_job(job: ConfigJob) -> Result<()> {
    let ConfigJob::Rules(job) = job else {
        return run_db_job(job);
    };

    run_rule_job(job)
}

fn run_db_list(target: DbListArg, input: &Path) -> Result<()> {
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    match target {
        DbListArg::Geoip => {
            for country in list_geoip_mmdb_countries(input)? {
                if !write_db_list_item(&mut writer, country)? {
                    return Ok(());
                }
            }
        }
        DbListArg::Asn => {
            for asn in list_asn_mmdb_asns(input)? {
                if !write_db_list_item(&mut writer, asn)? {
                    return Ok(());
                }
            }
        }
    }
    Ok(())
}

fn write_db_list_item(writer: &mut impl Write, item: impl std::fmt::Display) -> Result<bool> {
    match writeln!(writer, "{item}") {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::BrokenPipe => Ok(false),
        Err(err) => Err(err.into()),
    }
}

fn run_rule_job(job: RuleConfigJob) -> Result<()> {
    if let Some((files, skipped)) =
        convert_file_inputs_to_path_streaming(job.input.clone(), &job.output, job.options)?
    {
        return report_result(files, skipped);
    }

    let result = convert_file_inputs(job.input, job.options)?;
    let (files, skipped) = write_outputs_as_owned(
        result,
        &job.output,
        job.options.output_target,
        job.options.output_format,
    )?;

    report_result(files, skipped)
}

fn collect_ip_rule_set(input: FileInput) -> Result<RuleSetOutput> {
    let result = convert_file_inputs(
        [input],
        ConvertOptions {
            input_target: None,
            input_format: None,
            input_behavior: InputBehaviorMode::Auto,
            output_target: RuleTarget::General,
            output_format: OutputFormat::IpSet,
            output_behavior: BehaviorMode::Ipcidr,
        },
    )?;
    for output in result.outputs {
        if matches!(output, RuleSetOutput::Ipcidr(_)) {
            return Ok(output);
        }
    }
    anyhow::bail!("DB build input does not contain any IP CIDR rules");
}

fn write_db_rule_set_output(
    base: &Path,
    rule_set: RuleSetOutput,
    output: &DbExportOutput,
) -> Result<()> {
    let result = convert_rule_set_output(rule_set, output.behavior);
    let (files, skipped) = write_outputs_as_owned(result, base, output.target, output.format)?;
    report_result(files, skipped)
}

fn write_db_bytes_output(
    path: &Path,
    count: usize,
    bytes: Vec<u8>,
    name: &str,
    format: rule_converter::MmdbFormat,
) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    eprintln!(
        "wrote {count} records to {} ({name} {})",
        path.display(),
        format.as_str()
    );
    Ok(())
}

fn is_dat(format: rule_converter::MmdbFormat) -> bool {
    format == rule_converter::MmdbFormat::Dat
}

fn db_export_base(output: &DbExportOutput, name: &str) -> PathBuf {
    if output.split {
        output.base.join(name)
    } else {
        output.base.clone()
    }
}

fn ensure_db_export_filter_or_dir(
    output: &DbExportOutput,
    has_filter: bool,
    name: &str,
) -> Result<()> {
    if !output.split && !has_filter {
        anyhow::bail!(
            "{name} export without filters needs output.dir; use output.path only with explicit country/asn filters"
        );
    }
    Ok(())
}

fn can_stream_db_ipset(output: &DbExportOutput) -> bool {
    !output.split
        && output.target == RuleTarget::General
        && output.format == OutputFormat::IpSet
        && output.behavior == BehaviorMode::Ipcidr
}

fn can_stream_db_mrs(output: &DbExportOutput) -> bool {
    !output.split
        && output.target == RuleTarget::Mihomo
        && output.format == OutputFormat::Mrs
        && output.behavior == BehaviorMode::Ipcidr
}

fn can_stream_geosite_general_ruleset(output: &DbExportOutput) -> bool {
    !output.split
        && output.target == RuleTarget::General
        && output.format == OutputFormat::RuleSet
        && output.behavior == BehaviorMode::Classical
}

fn ipset_output_file(count: usize, path: PathBuf) -> OutputFile {
    OutputFile {
        behavior: Behavior::Ipcidr,
        format: OutputFormat::IpSet,
        count,
        path,
    }
}

fn mrs_output_file(count: usize, path: PathBuf) -> OutputFile {
    OutputFile {
        behavior: Behavior::Ipcidr,
        format: OutputFormat::Mrs,
        count,
        path,
    }
}

fn dat_ipset_output_file(count: usize, path: PathBuf) -> OutputFile {
    OutputFile {
        behavior: Behavior::Ipcidr,
        format: OutputFormat::IpSet,
        count,
        path,
    }
}

fn general_ruleset_output_file(count: usize, path: PathBuf) -> OutputFile {
    OutputFile {
        behavior: Behavior::Domain,
        format: OutputFormat::RuleSet,
        count,
        path,
    }
}

fn run_db_job(job: ConfigJob) -> Result<()> {
    let ConfigJob::Db(job) = job else {
        unreachable!("checked by caller")
    };

    match job {
        DbConfigJob::Export {
            target,
            format,
            input,
            output,
            countries,
            asns,
        } => match target {
            DbTarget::Geoip => {
                ensure_db_export_filter_or_dir(&output, !countries.is_empty(), "GeoIP")?;
                if is_dat(format) {
                    if output.split
                        && output.target == RuleTarget::General
                        && output.format == OutputFormat::IpSet
                        && output.behavior == BehaviorMode::Ipcidr
                    {
                        let files = export_geoip_dat_ipset_to_dir(input, &output.base, &countries)?
                            .into_iter()
                            .map(|file| dat_ipset_output_file(file.count, file.path))
                            .collect();
                        return report_result(files, Vec::new());
                    }
                    let raw = fs::read(input)?;
                    if output.split {
                        for set in collect_geoip_dat_rule_sets(&raw, &countries)? {
                            let base = db_export_base(&output, &set.country);
                            write_db_rule_set_output(&base, set.output, &output)?;
                        }
                    } else {
                        let rule_set = collect_geoip_dat_rule_set(&raw, &countries)?;
                        write_db_rule_set_output(&output.base, rule_set, &output)?;
                    }
                    return Ok(());
                }
                if can_stream_db_ipset(&output) {
                    let file = export_geoip_mmdb_ipset_to_path(input, &output.base, &countries)?;
                    return report_result(
                        vec![ipset_output_file(file.count, file.path)],
                        Vec::new(),
                    );
                }
                if can_stream_db_mrs(&output) {
                    let file = export_geoip_mmdb_mrs_to_path(input, &output.base, &countries)?;
                    return report_result(vec![mrs_output_file(file.count, file.path)], Vec::new());
                }
                if output.split {
                    for set in collect_geoip_mmdb_rule_sets(input, &countries)? {
                        let base = db_export_base(&output, &set.country);
                        write_db_rule_set_output(&base, set.output, &output)?;
                    }
                } else {
                    let rule_set = collect_geoip_mmdb_rule_set(input, &countries)?;
                    write_db_rule_set_output(&output.base, rule_set, &output)?;
                }
            }
            DbTarget::Geosite => {
                ensure_db_export_filter_or_dir(&output, !countries.is_empty(), "Geosite")?;
                if is_dat(format) {
                    if can_stream_geosite_general_ruleset(&output) {
                        let count = export_geosite_dat_general_ruleset_to_path(
                            input,
                            &output.base,
                            &countries,
                        )?;
                        return report_result(
                            vec![general_ruleset_output_file(count, output.base)],
                            Vec::new(),
                        );
                    }
                    if output.split
                        && output.target == RuleTarget::General
                        && output.format == OutputFormat::RuleSet
                        && output.behavior == BehaviorMode::Classical
                    {
                        let files = export_geosite_dat_general_ruleset_to_dir(
                            input,
                            &output.base,
                            &countries,
                        )?
                        .into_iter()
                        .map(|file| general_ruleset_output_file(file.count, file.path))
                        .collect();
                        return report_result(files, Vec::new());
                    }
                }
                let raw = fs::read(input)?;
                if output.split {
                    for set in collect_geosite_dat_rule_sets(&raw, &countries)? {
                        let base = db_export_base(&output, &set.code);
                        let (files, skipped) = write_outputs_as_owned(
                            set.into_result(),
                            &base,
                            output.target,
                            output.format,
                        )?;
                        report_result(files, skipped)?;
                    }
                } else {
                    let result = collect_geosite_dat_rule_set(&raw, &countries)?;
                    let (files, skipped) =
                        write_outputs_as_owned(result, &output.base, output.target, output.format)?;
                    report_result(files, skipped)?;
                }
            }
            DbTarget::Asn => {
                ensure_db_export_filter_or_dir(&output, !asns.is_empty(), "ASN")?;
                if can_stream_db_ipset(&output) {
                    let file = export_asn_mmdb_ipset_to_path(input, &output.base, &asns)?;
                    return report_result(
                        vec![ipset_output_file(file.count, file.path)],
                        Vec::new(),
                    );
                }
                if can_stream_db_mrs(&output) {
                    let file = export_asn_mmdb_mrs_to_path(input, &output.base, &asns)?;
                    return report_result(vec![mrs_output_file(file.count, file.path)], Vec::new());
                }
                if output.split {
                    for set in collect_asn_mmdb_rule_sets(input, &asns)? {
                        let base = db_export_base(&output, &set.asn.to_string());
                        write_db_rule_set_output(&base, set.output, &output)?;
                    }
                } else {
                    let rule_set = collect_asn_mmdb_rule_set(input, &asns)?;
                    write_db_rule_set_output(&output.base, rule_set, &output)?;
                }
            }
        },
        DbConfigJob::Build {
            target,
            format,
            input,
            output,
        } => match target {
            DbTarget::Geoip => {
                let mut entries = Vec::new();
                for item in input {
                    let DbInputPath::Country { country, input } = item else {
                        anyhow::bail!("GeoIP build needs country paths");
                    };
                    entries.push((country, collect_ip_rule_set(input)?));
                }
                if is_dat(format) {
                    let (count, bytes) = build_geoip_dat_from_rule_sets(entries)?;
                    write_db_bytes_output(&output, count, bytes, "geoip", format)?;
                    return Ok(());
                }
                let count = build_geoip_mmdb_from_rule_sets(entries, &output, format)?;
                eprintln!(
                    "wrote {count} CIDR records to {} (geoip {})",
                    output.display(),
                    format.as_str()
                );
            }
            DbTarget::Geosite => {
                let mut entries = Vec::new();
                for item in input {
                    let DbInputPath::Country { country, input } = item else {
                        anyhow::bail!("Geosite build needs country paths");
                    };
                    let result = convert_file_inputs(
                        [input],
                        ConvertOptions {
                            input_target: None,
                            input_format: None,
                            input_behavior: InputBehaviorMode::Auto,
                            output_target: RuleTarget::General,
                            output_format: OutputFormat::RuleSet,
                            output_behavior: BehaviorMode::Classical,
                        },
                    )?;
                    entries.push((country, result));
                }
                let (count, bytes) = build_geosite_dat_from_rule_sets(entries)?;
                write_db_bytes_output(&output, count, bytes, "geosite", format)?;
            }
            DbTarget::Asn => {
                let mut entries = Vec::new();
                for item in input {
                    let DbInputPath::Asn { asn, input } = item else {
                        anyhow::bail!("ASN build needs asn paths");
                    };
                    entries.push((asn, collect_ip_rule_set(input)?));
                }
                let count = build_asn_mmdb_from_rule_sets(entries, &output)?;
                eprintln!("wrote {count} CIDR records to {} (asn)", output.display());
            }
        },
        DbConfigJob::Convert {
            target,
            input_format,
            output_format,
            input,
            output,
            countries,
            asns,
        } => match target {
            DbTarget::Geoip => {
                if is_dat(input_format) && is_dat(output_format) {
                    let count = filter_geoip_dat_to_path(input, &output, &countries)?;
                    eprintln!(
                        "wrote {count} records to {} (geoip {})",
                        output.display(),
                        output_format.as_str()
                    );
                    return Ok(());
                }
                if is_dat(input_format) || is_dat(output_format) {
                    let raw = fs::read(input)?;
                    let db = convert_geoip_db_to_memory_filtered(
                        raw,
                        input_format,
                        &countries,
                        output_format,
                    )?;
                    write_db_bytes_output(&output, db.count, db.bytes, "geoip", output_format)?;
                    return Ok(());
                }
                let count = convert_geoip_mmdb_filtered(input, &output, output_format, &countries)?;
                eprintln!(
                    "wrote {count} CIDR records to {} (geoip {})",
                    output.display(),
                    output_format.as_str()
                );
            }
            DbTarget::Geosite => {
                let count = filter_geosite_dat_to_path(input, &output, &countries)?;
                eprintln!(
                    "wrote {count} records to {} (geosite {})",
                    output.display(),
                    output_format.as_str()
                );
            }
            DbTarget::Asn => {
                let count = if asns.is_empty() {
                    convert_asn_mmdb(input, &output)?
                } else {
                    let entries = collect_asn_mmdb_rule_sets(input, &asns)?
                        .into_iter()
                        .map(|set| (set.asn, set.output));
                    build_asn_mmdb_from_rule_sets(entries, &output)?
                };
                eprintln!("wrote {count} CIDR records to {} (asn)", output.display());
            }
        },
    }
    Ok(())
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

    /// Output rule target.
    #[arg(long, value_enum, default_value_t = RuleTargetArg::Mihomo)]
    output_target: RuleTargetArg,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormatArg::Mrs)]
    output_format: OutputFormatArg,

    /// Output behavior. Omit to infer from the output target and format.
    #[arg(long, value_enum)]
    output_behavior: Option<BehaviorArg>,

    /// List GeoIP country codes or ASN numbers from an MMDB file.
    #[arg(long, value_enum)]
    list: Option<DbListArg>,
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
enum DbListArg {
    Geoip,
    Asn,
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
            BehaviorArg::Domain => BehaviorMode::Domain,
            BehaviorArg::Ip => BehaviorMode::Ipcidr,
            BehaviorArg::Classical => BehaviorMode::Classical,
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
            RuleTargetArg::Mihomo => RuleTarget::Mihomo,
            RuleTargetArg::General => RuleTarget::General,
            RuleTargetArg::Egern => RuleTarget::Egern,
            RuleTargetArg::SingBox => RuleTarget::SingBox,
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
