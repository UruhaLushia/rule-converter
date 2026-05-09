use std::path::Path;

use anyhow::Result;

use super::types::{ConvertResult, SkippedRule};
use crate::RuleTarget;
use crate::output::{
    MemoryOutput, OutputFile, OutputFormat, OutputTarget, write_owned_sing_box_rule_set,
    write_owned_sing_box_rule_set_to_memory, write_rule_sets, write_rule_sets_to_memory,
};

pub fn write_outputs(result: &ConvertResult, output: impl AsRef<Path>) -> Result<Vec<OutputFile>> {
    write_outputs_as(result, output, RuleTarget::Mihomo, OutputFormat::Mrs)
}

pub fn write_outputs_owned(
    result: ConvertResult,
    output: impl AsRef<Path>,
) -> Result<(Vec<OutputFile>, Vec<SkippedRule>)> {
    write_outputs_as_owned(result, output, RuleTarget::Mihomo, OutputFormat::Mrs)
}

pub fn write_outputs_as(
    result: &ConvertResult,
    output: impl AsRef<Path>,
    target: RuleTarget,
    format: OutputFormat,
) -> Result<Vec<OutputFile>> {
    write_rule_sets(
        &result.outputs,
        &result.mixed_rules,
        result.sing_box_rules.as_ref(),
        OutputTarget::FilePath(output.as_ref()),
        target,
        format,
        result.output_behavior,
        result.no_resolve,
    )
}

pub fn write_outputs_as_owned(
    result: ConvertResult,
    output: impl AsRef<Path>,
    target: RuleTarget,
    format: OutputFormat,
) -> Result<(Vec<OutputFile>, Vec<SkippedRule>)> {
    let skipped = result.skipped;
    let no_resolve = result.no_resolve;
    let output_behavior = result.output_behavior;
    if target == RuleTarget::SingBox
        && matches!(format, OutputFormat::Json | OutputFormat::Srs)
        && let Some(sing_box_rules) = result.sing_box_rules
    {
        let files = write_owned_sing_box_rule_set(
            sing_box_rules,
            OutputTarget::FilePath(output.as_ref()),
            format,
            output_behavior,
        )?;
        return Ok((files, skipped));
    }

    let files = write_rule_sets(
        &result.outputs,
        &result.mixed_rules,
        result.sing_box_rules.as_ref(),
        OutputTarget::FilePath(output.as_ref()),
        target,
        format,
        output_behavior,
        no_resolve,
    )?;
    Ok((files, skipped))
}

pub fn write_outputs_to_memory(
    result: &ConvertResult,
    target: RuleTarget,
    format: OutputFormat,
) -> Result<Vec<MemoryOutput>> {
    write_rule_sets_to_memory(
        &result.outputs,
        &result.mixed_rules,
        result.sing_box_rules.as_ref(),
        target,
        format,
        result.output_behavior,
        result.no_resolve,
    )
}

pub fn write_outputs_to_memory_owned(
    result: ConvertResult,
) -> Result<(Vec<MemoryOutput>, Vec<SkippedRule>)> {
    write_outputs_as_to_memory_owned(result, RuleTarget::Mihomo, OutputFormat::Mrs)
}

pub fn write_outputs_as_to_memory_owned(
    result: ConvertResult,
    target: RuleTarget,
    format: OutputFormat,
) -> Result<(Vec<MemoryOutput>, Vec<SkippedRule>)> {
    let skipped = result.skipped;
    let no_resolve = result.no_resolve;
    let output_behavior = result.output_behavior;
    if target == RuleTarget::SingBox
        && matches!(format, OutputFormat::Json | OutputFormat::Srs)
        && let Some(sing_box_rules) = result.sing_box_rules
    {
        let outputs =
            write_owned_sing_box_rule_set_to_memory(sing_box_rules, format, output_behavior)?;
        return Ok((outputs, skipped));
    }

    let outputs = write_rule_sets_to_memory(
        &result.outputs,
        &result.mixed_rules,
        result.sing_box_rules.as_ref(),
        target,
        format,
        output_behavior,
        no_resolve,
    )?;
    Ok((outputs, skipped))
}
