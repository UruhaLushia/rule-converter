use std::fs::File;
use std::path::PathBuf;

use anyhow::{Context, Result};

use super::options::resolve_output_behavior;
use super::types::{ConvertOptions, ConvertResult};
use crate::RuleTarget;
use crate::codec::mihomo::mrs::{Behavior, read_mrs_stream};
use crate::input::{DetectedInput, InputFormat};
use crate::output::{OutputFormat, RuleSetOutput};
use crate::rules::{BehaviorMode, InputBehaviorMode, RuleTextStore};

pub(super) fn convert_single_mrs_file_fast_path(
    paths: &[PathBuf],
    detected: &[DetectedInput],
    options: ConvertOptions,
) -> Result<Option<ConvertResult>> {
    if paths.len() != 1 {
        return Ok(None);
    }
    let Some(detected) = detected.first().copied() else {
        return Ok(None);
    };
    if detected.target != RuleTarget::Mihomo || detected.format != InputFormat::Mrs {
        return Ok(None);
    }

    let file = File::open(&paths[0])
        .with_context(|| format!("failed to read input {}", paths[0].display()))?;
    let rule_set = read_mrs_stream(file)?;
    let input_behavior = match rule_set.behavior() {
        Behavior::Domain => InputBehaviorMode::Domain,
        Behavior::Ipcidr => InputBehaviorMode::Ipcidr,
    };
    let output_behavior = resolve_output_behavior(options, input_behavior)?;
    if !can_reuse_mrs_rule_set(options, output_behavior) {
        return Ok(None);
    }
    if !rule_set_matches_behavior(&rule_set, output_behavior) {
        return Ok(None);
    }

    Ok(Some(ConvertResult {
        outputs: vec![rule_set],
        mixed_rules: RuleTextStore::default(),
        sing_box_rules: None,
        output_behavior,
        no_resolve: false,
        skipped: Vec::new(),
    }))
}

pub(super) fn estimate_file_input_bytes(paths: &[PathBuf]) -> usize {
    paths
        .iter()
        .filter_map(|path| path.metadata().ok())
        .map(|metadata| metadata.len() as usize)
        .sum()
}

pub(super) fn estimate_rule_count(input_bytes: usize) -> usize {
    if input_bytes < 1024 * 1024 {
        0
    } else {
        input_bytes / 34
    }
}

pub(super) fn estimate_rule_bytes(input_bytes: usize) -> usize {
    if input_bytes < 1024 * 1024 {
        0
    } else {
        input_bytes.saturating_mul(2) / 3
    }
}

fn can_reuse_mrs_rule_set(options: ConvertOptions, output_behavior: BehaviorMode) -> bool {
    if options.output_target == RuleTarget::SingBox {
        return false;
    }
    if options.output_target == RuleTarget::Mihomo
        && matches!(
            options.output_format,
            OutputFormat::Text | OutputFormat::Yaml
        )
        && output_behavior == BehaviorMode::Classical
    {
        return false;
    }
    matches!(
        output_behavior,
        BehaviorMode::Domain | BehaviorMode::Ipcidr | BehaviorMode::Classical
    )
}

fn rule_set_matches_behavior(rule_set: &RuleSetOutput, output_behavior: BehaviorMode) -> bool {
    matches!(
        (rule_set.behavior(), output_behavior),
        (
            Behavior::Domain,
            BehaviorMode::Domain | BehaviorMode::Classical
        ) | (
            Behavior::Ipcidr,
            BehaviorMode::Ipcidr | BehaviorMode::Classical
        )
    )
}
