use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor};
use std::path::Path;

use anyhow::{Context, Result};

use super::InputFormat;
use crate::RuleTarget;
use crate::codec::mihomo::for_each_simple_yaml_rule;
use crate::codec::mihomo::mrs::parse_prefix;
use crate::rules::{BehaviorMode, looks_classical};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DetectedInput {
    pub target: RuleTarget,
    pub format: InputFormat,
    pub behavior: BehaviorMode,
}

pub fn detect_path(path: &Path) -> Result<DetectedInput> {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        Some("mrs") => Ok(DetectedInput {
            target: RuleTarget::Mihomo,
            format: InputFormat::Mrs,
            behavior: BehaviorMode::Auto,
        }),
        Some("srs") => Ok(DetectedInput {
            target: RuleTarget::SingBox,
            format: InputFormat::Srs,
            behavior: BehaviorMode::Auto,
        }),
        Some("json") => {
            let raw = fs::read(path)
                .with_context(|| format!("failed to read input {}", path.display()))?;
            detect_json_or_text(&raw)
        }
        Some("yaml") => detect_yaml_or_text_path(path),
        Some("list") => detect_text_path(path),
        _ => {
            let raw = fs::read(path)
                .with_context(|| format!("failed to read input {}", path.display()))?;
            detect_payload(&raw)
        }
    }
}

pub fn detect_payload(raw: &[u8]) -> Result<DetectedInput> {
    if raw.starts_with(b"SRS") {
        return Ok(DetectedInput {
            target: RuleTarget::SingBox,
            format: InputFormat::Srs,
            behavior: BehaviorMode::Auto,
        });
    }
    if std::str::from_utf8(raw).is_err() {
        return Ok(DetectedInput {
            target: RuleTarget::Mihomo,
            format: InputFormat::Mrs,
            behavior: BehaviorMode::Auto,
        });
    }
    detect_yaml_or_text(raw)
}

fn detect_json_or_text(raw: &[u8]) -> Result<DetectedInput> {
    let text = std::str::from_utf8(raw).context("failed to detect JSON input as UTF-8")?;
    if looks_like_sing_box_json(text) {
        return Ok(DetectedInput {
            target: RuleTarget::SingBox,
            format: InputFormat::Json,
            behavior: BehaviorMode::Auto,
        });
    }
    detect_text(raw)
}

fn detect_yaml_or_text(raw: &[u8]) -> Result<DetectedInput> {
    let text = std::str::from_utf8(raw).context("failed to detect input as UTF-8")?;
    if looks_like_sing_box_json(text) {
        return Ok(DetectedInput {
            target: RuleTarget::SingBox,
            format: InputFormat::Json,
            behavior: BehaviorMode::Auto,
        });
    }
    if looks_like_egern_yaml(text) {
        return Ok(DetectedInput {
            target: RuleTarget::Egern,
            format: InputFormat::Yaml,
            behavior: BehaviorMode::Auto,
        });
    }
    if looks_like_mihomo_yaml(text) {
        return Ok(DetectedInput {
            target: RuleTarget::Mihomo,
            format: InputFormat::Yaml,
            behavior: detect_simple_mihomo_yaml_behavior(raw),
        });
    }
    detect_text(raw)
}

fn detect_simple_mihomo_yaml_behavior(raw: &[u8]) -> BehaviorMode {
    detect_simple_mihomo_yaml_behavior_reader(Cursor::new(raw))
}

fn detect_simple_mihomo_yaml_behavior_reader<R: BufRead>(reader: R) -> BehaviorMode {
    let mut behavior = None;
    let parsed = for_each_simple_yaml_rule(reader, |rule| {
        let rule_behavior = classify_rule_behavior(rule);
        behavior = match behavior {
            None => Some(rule_behavior),
            Some(current) if current == rule_behavior => Some(current),
            Some(_) => Some(BehaviorMode::Auto),
        };
        Ok(())
    });

    match parsed {
        Ok(Some(_)) => behavior.unwrap_or(BehaviorMode::Auto),
        _ => BehaviorMode::Auto,
    }
}

fn detect_yaml_or_text_path(path: &Path) -> Result<DetectedInput> {
    let file =
        File::open(path).with_context(|| format!("failed to read input {}", path.display()))?;
    let mut saw_egern = false;

    for line in BufReader::new(file).lines() {
        let line = line.with_context(|| format!("failed to read input {}", path.display()))?;
        let line = line.trim_start();
        if looks_like_mihomo_yaml_line(line) {
            let file = File::open(path)
                .with_context(|| format!("failed to read input {}", path.display()))?;
            return Ok(DetectedInput {
                target: RuleTarget::Mihomo,
                format: InputFormat::Yaml,
                behavior: detect_simple_mihomo_yaml_behavior_reader(BufReader::new(file)),
            });
        }
        saw_egern |= looks_like_egern_yaml_line(line);
    }

    if saw_egern {
        return Ok(DetectedInput {
            target: RuleTarget::Egern,
            format: InputFormat::Yaml,
            behavior: BehaviorMode::Auto,
        });
    }

    detect_text_path(path)
}

fn detect_text_path(path: &Path) -> Result<DetectedInput> {
    let file =
        File::open(path).with_context(|| format!("failed to read input {}", path.display()))?;
    detect_text_reader(BufReader::new(file))
}

fn detect_text_reader<R: BufRead>(reader: R) -> Result<DetectedInput> {
    let mut saw_rule = false;
    let mut saw_mixed_rule = false;

    for (index, line) in reader.lines().enumerate() {
        let line = line.context("failed to detect text input")?;
        let line = if index == 0 {
            line.trim_start_matches('\u{feff}')
        } else {
            line.as_str()
        };
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        saw_rule = true;
        if looks_classical(line) || parse_prefix(line).is_ok() {
            saw_mixed_rule = true;
            break;
        }
    }

    Ok(DetectedInput {
        target: RuleTarget::General,
        format: InputFormat::Text,
        behavior: if saw_rule && !saw_mixed_rule {
            BehaviorMode::Domain
        } else {
            BehaviorMode::Auto
        },
    })
}

fn classify_rule_behavior(rule: &str) -> BehaviorMode {
    if looks_classical(rule) {
        BehaviorMode::Classical
    } else if parse_prefix(rule).is_ok() {
        BehaviorMode::Ipcidr
    } else {
        BehaviorMode::Domain
    }
}

fn detect_text(raw: &[u8]) -> Result<DetectedInput> {
    let text = std::str::from_utf8(raw).context("failed to detect text input as UTF-8")?;
    detect_text_reader(Cursor::new(text))
}

fn looks_like_mihomo_yaml(text: &str) -> bool {
    text.lines()
        .map(str::trim_start)
        .any(looks_like_mihomo_yaml_line)
}

fn looks_like_mihomo_yaml_line(line: &str) -> bool {
    matches!(line, "payload:" | "rules:")
        || line.starts_with("payload: ")
        || line.starts_with("rules: ")
}

fn looks_like_egern_yaml(text: &str) -> bool {
    text.lines()
        .map(str::trim_start)
        .any(looks_like_egern_yaml_line)
}

fn looks_like_egern_yaml_line(line: &str) -> bool {
    matches!(
        line,
        "domain_set:"
            | "domain_suffix_set:"
            | "ip_cidr_set:"
            | "ip_cidr6_set:"
            | "domain_keyword_set:"
            | "domain_regex_set:"
    ) || line.starts_with("domain_set: ")
        || line.starts_with("domain_suffix_set: ")
        || line.starts_with("ip_cidr_set: ")
        || line.starts_with("ip_cidr6_set: ")
        || line.starts_with("domain_keyword_set: ")
        || line.starts_with("domain_regex_set: ")
}

fn looks_like_sing_box_json(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return false;
    };
    value
        .get("version")
        .is_some_and(|version| version.is_number())
        && value.get("rules").is_some_and(|rules| rules.is_array())
}
