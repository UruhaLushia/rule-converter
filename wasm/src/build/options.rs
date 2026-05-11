use rule_converter::{MmdbFormat, detect_payload_type};
use wasm_bindgen::JsValue;

use crate::error::to_js_error;
use crate::types::{BuildDbEntry, BuildDbOptions};

pub(super) struct BuildDefaults {
    pub input_format: Option<String>,
    pub input_behavior: Option<String>,
}

impl Default for BuildDefaults {
    fn default() -> Self {
        Self {
            input_format: None,
            input_behavior: None,
        }
    }
}

impl BuildDefaults {
    pub(super) fn from_options(options: &BuildDbOptions) -> Self {
        Self {
            input_format: options.input_format.clone(),
            input_behavior: options.input_behavior.clone(),
        }
    }
}

pub(super) struct DetectedDbEntry {
    pub target: Option<String>,
    pub format: Option<String>,
}

pub(super) fn detect_db_entry(entry: &BuildDbEntry) -> DetectedDbEntry {
    if let Some(target @ ("geoip" | "geosite" | "asn")) = entry.input_target.as_deref() {
        return DetectedDbEntry {
            target: Some(target.to_string()),
            format: entry.input_format.clone(),
        };
    }
    detect_payload_type(&entry.payload)
        .ok()
        .filter(|detected| detected.kind == "db")
        .map(|detected| DetectedDbEntry {
            target: Some(detected.target),
            format: Some(detected.format),
        })
        .unwrap_or(DetectedDbEntry {
            target: None,
            format: None,
        })
}

pub(super) fn is_database_entry(entry: &BuildDbEntry) -> bool {
    detect_db_entry(entry).target.is_some()
}

pub(super) fn entry_keys(entry: &BuildDbEntry) -> Vec<String> {
    entry
        .keys
        .as_ref()
        .filter(|keys| !keys.is_empty())
        .cloned()
        .unwrap_or_else(|| vec![entry.key.clone()])
}

pub(super) fn parse_db_format(
    value: Option<&str>,
    default: MmdbFormat,
) -> Result<MmdbFormat, JsValue> {
    value
        .map(MmdbFormat::parse)
        .transpose()
        .map_err(to_js_error)
        .map(|format| format.unwrap_or(default))
}

pub(super) fn db_input_format(
    entry: &BuildDbEntry,
    defaults: &BuildDefaults,
    default: MmdbFormat,
) -> Result<MmdbFormat, JsValue> {
    let detected = detect_db_entry(entry);
    parse_db_format(
        entry
            .input_format
            .as_deref()
            .or(detected.format.as_deref())
            .or(defaults.input_format.as_deref()),
        default,
    )
}

pub(super) fn normalize_key(value: &str) -> Result<String, JsValue> {
    let key = value.trim().to_ascii_lowercase();
    if key.is_empty() {
        return Err(to_js_error("DB entry key is empty"));
    }
    Ok(key)
}

pub(super) fn parse_asn(value: &str) -> Result<u32, JsValue> {
    let asn = value
        .trim()
        .trim_start_matches(['A', 'a'])
        .trim_start_matches(['S', 's']);
    asn.parse::<u32>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| to_js_error(format!("invalid ASN entry key: {value}")))
}
