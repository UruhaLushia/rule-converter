use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use rule_converter::{
    Behavior, BehaviorMode, ConvertOptions, DbExportOutput, FileInput, InputBehaviorMode,
    OutputFile, OutputFormat, RuleSetOutput, RuleTarget, convert_file_inputs,
    convert_rule_set_output, list_input_indexes, write_outputs_as_owned,
};

use crate::cli::report::report_result;

pub(crate) fn run_db_list(input: &Path) -> Result<()> {
    let stdout = io::stdout();
    let mut writer = stdout.lock();
    for section in list_input_indexes(input)? {
        for item in section.items {
            if !write_db_list_item(&mut writer, item)? {
                return Ok(());
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

pub(super) fn collect_ip_rule_set(input: FileInput) -> Result<RuleSetOutput> {
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

pub(super) fn write_db_rule_set_output(
    base: &Path,
    rule_set: RuleSetOutput,
    output: &DbExportOutput,
) -> Result<()> {
    let result = convert_rule_set_output(rule_set, output.behavior);
    let (files, skipped) = write_outputs_as_owned(result, base, output.target, output.format)?;
    report_result(files, skipped)
}

pub(super) fn write_db_bytes_output(
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

pub(super) fn is_dat(format: rule_converter::MmdbFormat) -> bool {
    format == rule_converter::MmdbFormat::Dat
}

pub(super) fn db_export_base(output: &DbExportOutput, name: &str) -> PathBuf {
    if output.split {
        output.base.join(name)
    } else {
        output.base.clone()
    }
}

pub(super) fn ensure_db_export_filter_or_dir(
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

pub(super) fn can_stream_db_ipset(output: &DbExportOutput) -> bool {
    !output.split
        && output.target == RuleTarget::General
        && output.format == OutputFormat::IpSet
        && output.behavior == BehaviorMode::Ipcidr
}

pub(super) fn can_stream_db_mrs(output: &DbExportOutput) -> bool {
    !output.split
        && output.target == RuleTarget::Mihomo
        && output.format == OutputFormat::Mrs
        && output.behavior == BehaviorMode::Ipcidr
}

pub(super) fn can_stream_geosite_general_ruleset(output: &DbExportOutput) -> bool {
    !output.split
        && output.target == RuleTarget::General
        && output.format == OutputFormat::RuleSet
        && output.behavior == BehaviorMode::Classical
}

pub(super) fn ipset_output_file(count: usize, path: PathBuf) -> OutputFile {
    OutputFile {
        behavior: Behavior::Ipcidr,
        format: OutputFormat::IpSet,
        count,
        path,
    }
}

pub(super) fn mrs_output_file(count: usize, path: PathBuf) -> OutputFile {
    OutputFile {
        behavior: Behavior::Ipcidr,
        format: OutputFormat::Mrs,
        count,
        path,
    }
}

pub(super) fn dat_ipset_output_file(count: usize, path: PathBuf) -> OutputFile {
    OutputFile {
        behavior: Behavior::Ipcidr,
        format: OutputFormat::IpSet,
        count,
        path,
    }
}

pub(super) fn general_ruleset_output_file(count: usize, path: PathBuf) -> OutputFile {
    OutputFile {
        behavior: Behavior::Domain,
        format: OutputFormat::RuleSet,
        count,
        path,
    }
}
