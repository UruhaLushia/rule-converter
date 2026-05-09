use std::io::{self, BufRead};

use anyhow::{Context, Result};

use super::InputFormat;
use crate::RuleTarget;
use crate::codec::{egern, generic, mihomo, sing_box};

pub fn parse_input(raw: impl AsRef<[u8]>, format: InputFormat) -> Result<Vec<String>> {
    parse_input_as(raw, RuleTarget::Mihomo, format)
}

pub fn parse_input_as(
    raw: impl AsRef<[u8]>,
    target: RuleTarget,
    format: InputFormat,
) -> Result<Vec<String>> {
    match format {
        InputFormat::Yaml if target == RuleTarget::Mihomo => mihomo::parse_yaml(raw.as_ref()),
        InputFormat::Yaml if target == RuleTarget::Egern => egern::parse_ruleset(raw.as_ref()),
        InputFormat::Mrs => mihomo::mrs::read_mrs_rules(raw.as_ref()),
        InputFormat::Json if target == RuleTarget::SingBox => {
            sing_box::json::parse_json(raw.as_ref())
        }
        InputFormat::Srs if target == RuleTarget::SingBox => sing_box::srs::parse_srs(raw.as_ref()),
        InputFormat::Text => generic::text::parse_plain(raw.as_ref()),
        _ => anyhow::bail!("unsupported input target/format combination"),
    }
}

pub fn for_each_rule<R: BufRead>(
    reader: R,
    target: RuleTarget,
    format: InputFormat,
    f: impl FnMut(&str) -> Result<()>,
) -> Result<usize> {
    match format {
        InputFormat::Yaml if target == RuleTarget::Mihomo => mihomo::for_each_yaml_rule(reader, f),
        InputFormat::Yaml if target == RuleTarget::Egern => egern::for_each_ruleset_rule(reader, f),
        InputFormat::Mrs => for_each_mrs_rule(reader, f),
        InputFormat::Json if target == RuleTarget::SingBox => {
            for_each_sing_box_json_rule(reader, f)
        }
        InputFormat::Srs if target == RuleTarget::SingBox => for_each_sing_box_srs_rule(reader, f),
        InputFormat::Text => generic::text::for_each_plain_rule(reader, f),
        _ => anyhow::bail!("unsupported input target/format combination"),
    }
}

fn for_each_mrs_rule<R: BufRead>(
    mut reader: R,
    mut f: impl FnMut(&str) -> Result<()>,
) -> Result<usize> {
    let mut raw = Vec::new();
    reader.read_to_end(&mut raw)?;
    let rule_set = mihomo::mrs::read_mrs(&raw)?;
    let count = rule_set.count();
    let mut err = None;
    rule_set.for_each_rule(|rule| {
        if let Err(item_err) = f(rule) {
            err = Some(item_err);
            return Err(io::Error::other("failed to handle MRS rule"));
        }
        Ok(())
    })?;
    if let Some(err) = err {
        return Err(err);
    }
    Ok(count)
}

fn for_each_sing_box_json_rule<R: BufRead>(
    mut reader: R,
    mut f: impl FnMut(&str) -> Result<()>,
) -> Result<usize> {
    let mut raw = Vec::new();
    reader
        .read_to_end(&mut raw)
        .context("failed to read sing-box JSON input")?;
    sing_box::json::read_json(&raw)?.into_each_classical_rule(&mut f)
}

fn for_each_sing_box_srs_rule<R: BufRead>(
    mut reader: R,
    f: impl FnMut(&str) -> Result<()>,
) -> Result<usize> {
    let mut raw = Vec::new();
    reader
        .read_to_end(&mut raw)
        .context("failed to read sing-box SRS input")?;
    sing_box::srs::read_srs(&raw)?.into_each_classical_rule(f)
}
