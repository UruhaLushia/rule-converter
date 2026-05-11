use rule_converter::{
    BehaviorMode, ConvertOptions as CoreConvertOptions, InputBehaviorMode, InputFormat, MmdbFormat,
    OutputFormat, RuleSetOutput, RuleTarget, convert_payload, export_asn_mmdb_to_memory,
    export_geoip_db_to_memory, export_geosite_db_to_memory,
};
use wasm_bindgen::JsValue;

use super::options::{BuildDefaults, db_input_format, detect_db_entry, normalize_key, parse_asn};
use crate::error::to_js_error;
use crate::types::BuildDbEntry;

pub(super) fn convert_to_classical(
    entry: BuildDbEntry,
    defaults: &BuildDefaults,
) -> Result<rule_converter::ConvertResult, JsValue> {
    let detected = detect_db_entry(&entry);
    if detected.target.as_deref() == Some("geosite") {
        let input_format = db_input_format(&entry, defaults, MmdbFormat::Dat)?;
        return db_geosite_payload_to_classical(&entry.payload, input_format, &entry.key);
    }
    convert_payload(
        &entry.payload,
        convert_options(
            &entry,
            defaults,
            OutputFormat::RuleSet,
            BehaviorMode::Classical,
        )?,
    )
    .map_err(to_js_error)
}

pub(super) fn collect_ip_rule_set(
    entry: BuildDbEntry,
    defaults: &BuildDefaults,
) -> Result<RuleSetOutput, JsValue> {
    let detected = detect_db_entry(&entry);
    match detected.target.as_deref() {
        Some("geoip") => {
            let input_format = db_input_format(&entry, defaults, MmdbFormat::Mmdb)?;
            return db_geoip_payload_to_rule_set(&entry.payload, input_format, &entry.key);
        }
        Some("asn") => return db_asn_payload_to_rule_set(&entry.payload, &entry.key),
        _ => {}
    }
    let result = convert_payload(
        &entry.payload,
        convert_options(&entry, defaults, OutputFormat::IpSet, BehaviorMode::Ipcidr)?,
    )
    .map_err(to_js_error)?;
    result
        .outputs
        .into_iter()
        .find(|output| matches!(output, RuleSetOutput::Ipcidr(_)))
        .ok_or_else(|| to_js_error("DB build input does not contain any IP CIDR rules"))
}

pub(super) fn db_geosite_payload_to_classical(
    payload: &[u8],
    input_format: MmdbFormat,
    key: &str,
) -> Result<rule_converter::ConvertResult, JsValue> {
    let codes = vec![normalize_key(key)?];
    let outputs = export_geosite_db_to_memory(
        payload,
        input_format,
        &codes,
        false,
        RuleTarget::General,
        OutputFormat::RuleSet,
        BehaviorMode::Classical,
    )
    .map_err(to_js_error)?;
    let output = outputs
        .into_iter()
        .next()
        .ok_or_else(|| to_js_error("geosite DB entry did not match the requested code"))?;
    convert_payload(
        &output.bytes,
        CoreConvertOptions {
            input_target: Some(RuleTarget::General),
            input_format: Some(InputFormat::Text),
            input_behavior: InputBehaviorMode::Classical,
            output_target: RuleTarget::General,
            output_format: OutputFormat::RuleSet,
            output_behavior: BehaviorMode::Classical,
        },
    )
    .map_err(to_js_error)
}

pub(super) fn db_geoip_payload_to_rule_set(
    payload: &[u8],
    input_format: MmdbFormat,
    key: &str,
) -> Result<RuleSetOutput, JsValue> {
    let countries = vec![normalize_key(key)?];
    let outputs = export_geoip_db_to_memory(
        payload,
        input_format,
        &countries,
        false,
        RuleTarget::General,
        OutputFormat::IpSet,
        BehaviorMode::Ipcidr,
    )
    .map_err(to_js_error)?;
    let output = outputs
        .into_iter()
        .next()
        .ok_or_else(|| to_js_error("geoip DB entry did not match the requested country"))?;
    collect_ip_rule_set(
        general_ipset_entry(key, output.bytes),
        &BuildDefaults::default(),
    )
}

pub(super) fn db_asn_payload_to_rule_set(
    payload: &[u8],
    key: &str,
) -> Result<RuleSetOutput, JsValue> {
    let asns = vec![parse_asn(key)?];
    let outputs = export_asn_mmdb_to_memory(
        payload,
        &asns,
        false,
        RuleTarget::General,
        OutputFormat::IpSet,
        BehaviorMode::Ipcidr,
    )
    .map_err(to_js_error)?;
    let output = outputs
        .into_iter()
        .next()
        .ok_or_else(|| to_js_error("ASN DB entry did not match the requested ASN"))?;
    collect_ip_rule_set(
        general_ipset_entry(key, output.bytes),
        &BuildDefaults::default(),
    )
}

fn convert_options(
    entry: &BuildDbEntry,
    defaults: &BuildDefaults,
    output_format: OutputFormat,
    output_behavior: BehaviorMode,
) -> Result<CoreConvertOptions, JsValue> {
    Ok(CoreConvertOptions {
        input_target: entry
            .input_target
            .as_deref()
            .map(RuleTarget::parse_arg)
            .transpose()
            .map_err(to_js_error)?,
        input_format: entry
            .input_format
            .as_ref()
            .or(defaults.input_format.as_ref())
            .map(|value| InputFormat::parse_arg(value))
            .transpose()
            .map_err(to_js_error)?,
        input_behavior: entry
            .input_behavior
            .as_ref()
            .or(defaults.input_behavior.as_ref())
            .map(|value| InputBehaviorMode::parse_arg(value))
            .transpose()
            .map_err(to_js_error)?
            .unwrap_or(InputBehaviorMode::Auto),
        output_target: RuleTarget::General,
        output_format,
        output_behavior,
    })
}

fn general_ipset_entry(key: &str, payload: Vec<u8>) -> BuildDbEntry {
    BuildDbEntry {
        key: key.to_string(),
        keys: None,
        input_target: Some("general".to_string()),
        input_format: Some("ipset".to_string()),
        input_behavior: Some("ip".to_string()),
        payload,
    }
}
