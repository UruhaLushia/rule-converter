use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use yaml_rust2::Yaml;

#[cfg(feature = "http")]
use super::apply_match_options;
use super::state::MatchState;
use super::{MatchInputFormat, MatchInputTarget, MatchOptions, detect_match_file_input};
use crate::codec::mihomo::mrs::read_mrs_stream;
#[cfg(feature = "http")]
use crate::input::detect_payload;
use crate::input::{InputSource, for_each_rule};
use crate::rules::InputBehaviorMode;
use crate::{InputFormat, RuleTarget};

#[derive(Clone)]
pub(super) struct MihomoProvider {
    path: Option<String>,
    url: Option<String>,
    target: Option<RuleTarget>,
    format: Option<InputFormat>,
    behavior: InputBehaviorMode,
}

pub(super) fn parse_mihomo_provider(value: &Yaml) -> Option<MihomoProvider> {
    let hash = value.as_hash()?;
    let path = yaml_get_merged_str(hash, "path").map(str::to_string);
    let url = yaml_get_merged_str(hash, "url").map(str::to_string);
    let format = yaml_get_merged_str(hash, "format").and_then(parse_input_format_name);
    let behavior = yaml_get_merged_str(hash, "behavior")
        .and_then(parse_input_behavior_name)
        .unwrap_or(InputBehaviorMode::Auto);
    let target = if format == Some(InputFormat::Mrs) {
        Some(RuleTarget::Mihomo)
    } else {
        yaml_get_merged_str(hash, "target").and_then(parse_rule_target_name)
    };
    Some(MihomoProvider {
        path,
        url,
        target,
        format,
        behavior,
    })
}

pub(super) fn match_mihomo_provider(
    provider: &MihomoProvider,
    base: Option<&Path>,
    state: &mut MatchState,
) -> Result<usize> {
    if let Some(path) = &provider.path {
        let path = resolve_provider_path(path, base);
        return match_provider_path(provider, &path, state);
    }
    if let Some(url) = &provider.url {
        if let Some(path) = local_path_from_file_url(url) {
            return match_provider_path(provider, &path, state);
        }
        #[cfg(feature = "http")]
        {
            let payload = download_provider_to_memory(url)?;
            return match_provider_payload(provider, &payload, state);
        }
        #[cfg(not(feature = "http"))]
        {
            anyhow::bail!("rule provider URL needs the `http` feature: {url}");
        }
    }
    anyhow::bail!("rule provider missing path or url")
}

fn match_provider_path(
    provider: &MihomoProvider,
    path: &Path,
    state: &mut MatchState,
) -> Result<usize> {
    let options = MatchOptions {
        input_target: provider.target.map(MatchInputTarget::from),
        input_format: provider.format.map(MatchInputFormat::from),
        input_behavior: provider.behavior,
    };
    let detected = detect_match_file_input(path, options)?;
    if detected.target == RuleTarget::Mihomo && detected.format == InputFormat::Mrs {
        let file = File::open(path)
            .map(BufReader::new)
            .with_context(|| format!("failed to read input {}", path.display()))?;
        let rule_set = read_mrs_stream(file)?;
        return Ok(state.push_mrs_rule_set(&rule_set));
    }
    for_each_rule(
        InputSource::FilePath(path),
        detected.target,
        detected.format,
        |rule| state.push_rule(rule, detected),
    )
}

#[cfg(feature = "http")]
fn match_provider_payload(
    provider: &MihomoProvider,
    payload: &[u8],
    state: &mut MatchState,
) -> Result<usize> {
    let options = MatchOptions {
        input_target: provider.target.map(MatchInputTarget::from),
        input_format: provider.format.map(MatchInputFormat::from),
        input_behavior: provider.behavior,
    };
    let detected = apply_match_options(detect_payload(payload)?, options);
    if detected.target == RuleTarget::Mihomo && detected.format == InputFormat::Mrs {
        let rule_set = crate::codec::mihomo::mrs::read_mrs(payload)?;
        return Ok(state.push_mrs_rule_set(&rule_set));
    }
    for_each_rule(
        InputSource::Payload(payload),
        detected.target,
        detected.format,
        |rule| state.push_rule(rule, detected),
    )
}

fn resolve_provider_path(path: &str, base: Option<&Path>) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else if let Some(base) = base {
        base.join(path)
    } else {
        path
    }
}

fn local_path_from_file_url(url: &str) -> Option<PathBuf> {
    url.strip_prefix("file://").map(PathBuf::from)
}

#[cfg(feature = "http")]
fn download_provider_to_memory(url: &str) -> Result<Vec<u8>> {
    let mut response = ureq::get(url)
        .call()
        .with_context(|| format!("failed to download rule provider: {url}"))?;
    response
        .body_mut()
        .with_config()
        .limit(64 * 1024 * 1024)
        .read_to_vec()
        .with_context(|| format!("failed to read rule provider response: {url}"))
}

pub(super) fn yaml_get<'a>(hash: &'a yaml_rust2::yaml::Hash, key: &str) -> Option<&'a Yaml> {
    hash.get(&Yaml::String(key.to_string()))
}

fn yaml_get_merged_str<'a>(hash: &'a yaml_rust2::yaml::Hash, key: &str) -> Option<&'a str> {
    yaml_get(hash, key).and_then(Yaml::as_str).or_else(|| {
        yaml_get(hash, "<<")?
            .as_hash()
            .and_then(|merged| yaml_get_merged_str(merged, key))
    })
}

fn parse_input_format_name(value: &str) -> Option<InputFormat> {
    match value {
        value if value.eq_ignore_ascii_case("mrs") => Some(InputFormat::Mrs),
        value if value.eq_ignore_ascii_case("yaml") || value.eq_ignore_ascii_case("yml") => {
            Some(InputFormat::Yaml)
        }
        value if value.eq_ignore_ascii_case("text") || value.eq_ignore_ascii_case("list") => {
            Some(InputFormat::Text)
        }
        value if value.eq_ignore_ascii_case("srs") => Some(InputFormat::Srs),
        value if value.eq_ignore_ascii_case("json") => Some(InputFormat::Json),
        _ => None,
    }
}

fn parse_input_behavior_name(value: &str) -> Option<InputBehaviorMode> {
    match value {
        value if value.eq_ignore_ascii_case("domain") => Some(InputBehaviorMode::Domain),
        value if value.eq_ignore_ascii_case("ip") || value.eq_ignore_ascii_case("ipcidr") => {
            Some(InputBehaviorMode::Ipcidr)
        }
        value if value.eq_ignore_ascii_case("classical") => Some(InputBehaviorMode::Classical),
        value if value.eq_ignore_ascii_case("auto") => Some(InputBehaviorMode::Auto),
        _ => None,
    }
}

fn parse_rule_target_name(value: &str) -> Option<RuleTarget> {
    match value {
        value if value.eq_ignore_ascii_case("mihomo") || value.eq_ignore_ascii_case("clash") => {
            Some(RuleTarget::Mihomo)
        }
        value if value.eq_ignore_ascii_case("general") => Some(RuleTarget::General),
        value if value.eq_ignore_ascii_case("egern") => Some(RuleTarget::Egern),
        value
            if value.eq_ignore_ascii_case("sing-box") || value.eq_ignore_ascii_case("sing_box") =>
        {
            Some(RuleTarget::SingBox)
        }
        _ => None,
    }
}
