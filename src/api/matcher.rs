use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use anyhow::Result;
use serde::Serialize;

use crate::codec::dat::{DatKind, detect_dat_kind};
use crate::codec::mihomo::mrs::{Behavior, read_mrs_stream};
use crate::input::{
    DetectedInput, InputSource, detect_path, detect_payload, expand_file_paths, for_each_rule,
};
use crate::rules::{BehaviorMode, InputBehaviorMode};
use crate::{FileInput, InputFormat, RuleTarget};

mod config;
mod provider;
mod rule;
mod state;

use config::{match_mihomo_config_path, match_mihomo_config_payload};
use state::MatchState;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchInputTarget {
    Rule(Option<RuleTarget>),
    Geoip,
    Geosite,
    Asn,
}

impl MatchInputTarget {
    pub fn parse_arg(arg: &str) -> Result<Self> {
        match arg {
            "geoip" => Ok(Self::Geoip),
            "geosite" => Ok(Self::Geosite),
            "asn" => Ok(Self::Asn),
            value => RuleTarget::parse_arg(value).map(|target| Self::Rule(Some(target))),
        }
    }
}

impl From<RuleTarget> for MatchInputTarget {
    fn from(value: RuleTarget) -> Self {
        Self::Rule(Some(value))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchInputFormat {
    Rule(Option<InputFormat>),
    Dat,
    Mmdb,
}

impl MatchInputFormat {
    pub fn parse_arg(arg: &str) -> Result<Self> {
        match arg {
            "dat" => Ok(Self::Dat),
            "mmdb" | "sing-db" | "metadb" => Ok(Self::Mmdb),
            value => InputFormat::parse_arg(value).map(|format| Self::Rule(Some(format))),
        }
    }
}

impl From<InputFormat> for MatchInputFormat {
    fn from(value: InputFormat) -> Self {
        Self::Rule(Some(value))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchOptions {
    pub input_target: Option<MatchInputTarget>,
    pub input_format: Option<MatchInputFormat>,
    pub input_behavior: InputBehaviorMode,
}

impl Default for MatchOptions {
    fn default() -> Self {
        Self {
            input_target: None,
            input_format: None,
            input_behavior: InputBehaviorMode::Auto,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchQueryKind {
    Domain,
    Ip,
}

impl MatchQueryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Ip => "ip",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MatchedRule {
    #[serde(serialize_with = "serialize_behavior")]
    pub behavior: Behavior,
    pub rule: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MatchResult {
    pub matched: bool,
    pub query: String,
    pub kind: MatchQueryKind,
    pub rules: Vec<MatchedRule>,
}

pub fn match_payload(
    payload: impl AsRef<[u8]>,
    query: &str,
    options: MatchOptions,
) -> Result<MatchResult> {
    let payload = payload.as_ref();
    if let Some(result) = match_db_payload(payload, query, options)? {
        return Ok(result);
    }
    let detected = apply_match_options(detect_payload(payload)?, options);
    if detected.target == RuleTarget::Mihomo
        && detected.format == InputFormat::Yaml
        && let Some(result) = match_mihomo_config_payload(payload, query)?
    {
        return Ok(result);
    }
    let mut state = MatchState::new(query);
    if detected.target == RuleTarget::Mihomo && detected.format == InputFormat::Mrs {
        let rule_set = crate::codec::mihomo::mrs::read_mrs(payload)?;
        let count = state.push_mrs_rule_set(&rule_set);
        if count == 0 {
            anyhow::bail!("input does not contain any rules in `rules` or `payload`");
        }
        return Ok(state.finish());
    }
    let count = for_each_rule(
        InputSource::Payload(payload),
        detected.target,
        detected.format,
        |rule| state.push_rule(rule, detected),
    )?;
    if count == 0 {
        anyhow::bail!("input does not contain any rules in `rules` or `payload`");
    }
    Ok(state.finish())
}

pub fn match_file(
    path: impl AsRef<Path>,
    query: &str,
    options: MatchOptions,
) -> Result<MatchResult> {
    match_file_inputs(
        [FileInput {
            path: path.as_ref().to_path_buf(),
            target: rule_input_target(options.input_target),
            format: rule_input_format(options.input_format),
            behavior: options.input_behavior,
        }],
        query,
        options,
    )
}

pub fn match_files<P, I>(paths: I, query: &str, options: MatchOptions) -> Result<MatchResult>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = P>,
{
    let inputs = paths
        .into_iter()
        .map(|path| FileInput {
            path: path.as_ref().to_path_buf(),
            target: rule_input_target(options.input_target),
            format: rule_input_format(options.input_format),
            behavior: options.input_behavior,
        })
        .collect::<Vec<_>>();
    match_file_inputs(inputs, query, options)
}

pub fn match_file_inputs<I>(inputs: I, query: &str, options: MatchOptions) -> Result<MatchResult>
where
    I: IntoIterator<Item = FileInput>,
{
    let mut state = MatchState::new(query);
    let mut total = 0usize;
    for input in inputs {
        let expanded = expand_file_paths([input.path])?;
        for path in expanded {
            let item_options = MatchOptions {
                input_target: input
                    .target
                    .map(MatchInputTarget::from)
                    .or(options.input_target),
                input_format: input
                    .format
                    .map(MatchInputFormat::from)
                    .or(options.input_format),
                input_behavior: if input.behavior == InputBehaviorMode::Auto {
                    options.input_behavior
                } else {
                    input.behavior
                },
            };
            if let Some(count) = match_db_file(&path, item_options, &mut state)? {
                total += count;
                continue;
            }
            let detected = detect_match_file_input(&path, item_options)?;
            if detected.target == RuleTarget::Mihomo
                && detected.format == InputFormat::Yaml
                && let Some(result) = match_mihomo_config_path(&path, &mut state)?
            {
                total += result;
                continue;
            }
            if detected.target == RuleTarget::Mihomo && detected.format == InputFormat::Mrs {
                let file = File::open(&path).map(BufReader::new).map_err(|err| {
                    anyhow::anyhow!("failed to read input {}: {err}", path.display())
                })?;
                let rule_set = read_mrs_stream(file)?;
                total += state.push_mrs_rule_set(&rule_set);
                continue;
            }
            total += for_each_rule(
                InputSource::FilePath(&path),
                detected.target,
                detected.format,
                |rule| state.push_rule(rule, detected),
            )?;
        }
    }
    if total == 0 {
        anyhow::bail!("input does not contain any rules in `rules` or `payload`");
    }
    Ok(state.finish())
}

fn detect_match_file_input(path: &Path, options: MatchOptions) -> Result<DetectedInput> {
    if let (Some(target), Some(format)) = (
        rule_input_target(options.input_target),
        rule_input_format(options.input_format),
    ) {
        return Ok(DetectedInput {
            target,
            format,
            behavior: input_behavior_to_output_mode(options.input_behavior),
        });
    }
    detect_path(path).map(|detected| apply_match_options(detected, options))
}

fn apply_match_options(mut detected: DetectedInput, options: MatchOptions) -> DetectedInput {
    if let Some(target) = rule_input_target(options.input_target) {
        detected.target = target;
    }
    if let Some(format) = rule_input_format(options.input_format) {
        detected.format = format;
    }
    if options.input_behavior != InputBehaviorMode::Auto {
        detected.behavior = input_behavior_to_output_mode(options.input_behavior);
    }
    detected
}

fn rule_input_target(target: Option<MatchInputTarget>) -> Option<RuleTarget> {
    match target {
        Some(MatchInputTarget::Rule(target)) => target,
        _ => None,
    }
}

fn rule_input_format(format: Option<MatchInputFormat>) -> Option<InputFormat> {
    match format {
        Some(MatchInputFormat::Rule(format)) => format,
        _ => None,
    }
}

fn match_db_payload(
    payload: &[u8],
    query: &str,
    options: MatchOptions,
) -> Result<Option<MatchResult>> {
    let Some(kind) = detect_db_input(payload, options) else {
        return Ok(None);
    };
    let mut state = MatchState::new(query);
    let count = push_db_payload(payload, kind, &mut state)?;
    if count == 0 {
        anyhow::bail!("input does not contain any rules in `rules` or `payload`");
    }
    Ok(Some(state.finish()))
}

fn match_db_file(
    path: &Path,
    options: MatchOptions,
    state: &mut MatchState,
) -> Result<Option<usize>> {
    let bytes = if should_read_file_for_db_detection(options) {
        Some(
            std::fs::read(path)
                .map_err(|err| anyhow::anyhow!("failed to read input {}: {err}", path.display()))?,
        )
    } else {
        None
    };
    let kind = if let Some(bytes) = bytes.as_deref() {
        detect_db_input(bytes, options)
    } else {
        explicit_db_input_kind(options)
    };
    let Some(kind) = kind else {
        return Ok(None);
    };
    let bytes = match bytes {
        Some(bytes) => bytes,
        None => std::fs::read(path)
            .map_err(|err| anyhow::anyhow!("failed to read input {}: {err}", path.display()))?,
    };
    push_db_payload(&bytes, kind, state).map(Some)
}

fn should_read_file_for_db_detection(options: MatchOptions) -> bool {
    explicit_db_input_kind(options).is_some()
        || (options.input_target.is_none()
            && matches!(options.input_format, None | Some(MatchInputFormat::Dat)))
}

fn detect_db_input(payload: &[u8], options: MatchOptions) -> Option<MatchInputTarget> {
    if let Some(kind) = explicit_db_input_kind(options) {
        return Some(kind);
    }
    if options.input_target.is_none()
        && matches!(options.input_format, None | Some(MatchInputFormat::Dat))
    {
        return match detect_dat_kind(payload) {
            Some(DatKind::Geoip) => Some(MatchInputTarget::Geoip),
            Some(DatKind::Geosite) => Some(MatchInputTarget::Geosite),
            None => None,
        };
    }
    None
}

fn explicit_db_input_kind(options: MatchOptions) -> Option<MatchInputTarget> {
    match (options.input_target, options.input_format) {
        (Some(MatchInputTarget::Geoip), _) => Some(MatchInputTarget::Geoip),
        (Some(MatchInputTarget::Geosite), _) => Some(MatchInputTarget::Geosite),
        (Some(MatchInputTarget::Asn), _) => Some(MatchInputTarget::Asn),
        _ => None,
    }
}

fn push_db_payload(
    payload: &[u8],
    kind: MatchInputTarget,
    state: &mut MatchState,
) -> Result<usize> {
    let rule_set = match kind {
        MatchInputTarget::Geoip => crate::codec::dat::collect_geoip_dat_rule_set(payload, &[])?,
        MatchInputTarget::Geosite => {
            return push_geosite_dat_payload(payload, state);
        }
        MatchInputTarget::Asn => {
            crate::codec::db::collect_asn_mmdb_rule_set_from_bytes(payload, &[])?
        }
        MatchInputTarget::Rule(_) => return Ok(0),
    };
    Ok(state.push_mrs_rule_set(&rule_set))
}

fn push_geosite_dat_payload(payload: &[u8], state: &mut MatchState) -> Result<usize> {
    let result = crate::codec::dat::collect_geosite_dat_rule_set(payload, &[])?;
    let mut total = 0usize;
    for output in result.outputs {
        total += state.push_mrs_rule_set(&output);
    }
    let detected = DetectedInput {
        target: RuleTarget::General,
        format: InputFormat::Text,
        behavior: BehaviorMode::Classical,
    };
    for rule in result.mixed_rules.iter() {
        total += 1;
        state.push_rule(rule, detected)?;
    }
    Ok(total)
}

fn input_behavior_to_output_mode(behavior: InputBehaviorMode) -> BehaviorMode {
    match behavior {
        InputBehaviorMode::Auto => BehaviorMode::Auto,
        InputBehaviorMode::Domain => BehaviorMode::Domain,
        InputBehaviorMode::Ipcidr => BehaviorMode::Ipcidr,
        InputBehaviorMode::Classical => BehaviorMode::Classical,
    }
}

fn serialize_behavior<S>(behavior: &Behavior, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(behavior.as_str())
}
