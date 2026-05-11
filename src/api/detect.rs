use std::path::Path;

use anyhow::{Context, Result};
use maxminddb::Reader;
use serde::Serialize;

use crate::codec::dat::{DatKind, detect_dat_kind};
use crate::input::{DetectedInput, detect_payload};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DetectResult {
    pub kind: String,
    pub target: String,
    pub format: String,
    pub behavior: Option<String>,
}

pub fn detect_file_type(path: impl AsRef<Path>) -> Result<DetectResult> {
    let path = path.as_ref();
    let raw =
        std::fs::read(path).with_context(|| format!("failed to read input {}", path.display()))?;
    detect_payload_type(&raw)
}

pub fn detect_payload_type(payload: impl AsRef<[u8]>) -> Result<DetectResult> {
    let payload = payload.as_ref();
    if let Some(result) = detect_dat_payload(payload) {
        return Ok(result);
    }
    if let Some(result) = detect_mmdb_payload(payload) {
        return Ok(result);
    }
    detect_payload(payload).map(rule_detect_result)
}

pub fn detect_payload_target(payload: impl AsRef<[u8]>) -> Result<DetectTarget> {
    detect_payload_type(payload).map(|result| result.target.into())
}

fn detect_dat_payload(payload: &[u8]) -> Option<DetectResult> {
    if let Some(result) = match detect_dat_kind(payload) {
        Some(DatKind::Geoip) => Some(db_detect_result("geoip", "dat")),
        Some(DatKind::Geosite) => Some(db_detect_result("geosite", "dat")),
        None => None,
    } {
        return Some(result);
    }
    if crate::codec::db::list_sing_geosite_codes(payload).is_ok_and(|codes| !codes.is_empty()) {
        return Some(db_detect_result("geosite", "sing-geosite"));
    }
    None
}

fn detect_mmdb_payload(payload: &[u8]) -> Option<DetectResult> {
    let reader = Reader::from_source(payload).ok()?;
    let database_type = reader.metadata.database_type.as_str();
    match database_type {
        "GeoLite2-ASN" => Some(db_detect_result("asn", "mmdb")),
        "GeoLite2-Country" => Some(db_detect_result("geoip", "mmdb")),
        "sing-geoip" => Some(db_detect_result("geoip", "sing-db")),
        "Meta-geoip0" => Some(db_detect_result("geoip", "metadb")),
        value if value.to_ascii_lowercase().contains("asn") => {
            Some(db_detect_result("asn", "mmdb"))
        }
        value
            if value.to_ascii_lowercase().contains("country")
                || value.to_ascii_lowercase().contains("geoip") =>
        {
            Some(db_detect_result("geoip", "mmdb"))
        }
        _ => None,
    }
}

fn rule_detect_result(input: DetectedInput) -> DetectResult {
    DetectResult {
        kind: "rules".to_string(),
        target: input.target.as_str().to_string(),
        format: input.format.as_str().to_string(),
        behavior: Some(input.behavior.as_str().to_string()),
    }
}

fn db_detect_result(target: &str, format: &str) -> DetectResult {
    DetectResult {
        kind: "db".to_string(),
        target: target.to_string(),
        format: format.to_string(),
        behavior: None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DetectTarget {
    Rule(Option<crate::RuleTarget>),
    Geoip,
    Geosite,
    Asn,
}

impl From<String> for DetectTarget {
    fn from(value: String) -> Self {
        match value.as_str() {
            "geoip" => Self::Geoip,
            "geosite" => Self::Geosite,
            "asn" => Self::Asn,
            _ => Self::Rule(crate::RuleTarget::parse_arg(&value).ok()),
        }
    }
}
