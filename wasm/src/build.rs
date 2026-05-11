use rule_converter::{
    BehaviorMode, ConvertOptions as CoreConvertOptions, InputBehaviorMode, InputFormat, MmdbFormat,
    OutputFormat, RuleSetOutput, RuleTarget, build_asn_mmdb_to_memory, build_geoip_db_to_memory,
    build_geosite_db_to_memory, convert_payload,
};
use wasm_bindgen::prelude::*;

use crate::error::to_js_error;
use crate::result::any_db_to_js;
use crate::types::{BuildDbEntry, BuildDbOptions};

#[wasm_bindgen(js_name = buildDb)]
pub fn build_db_wasm(options: JsValue) -> Result<JsValue, JsValue> {
    let options: BuildDbOptions = serde_wasm_bindgen::from_value(options).map_err(to_js_error)?;
    if options.entries.is_empty() {
        return Err(to_js_error("DB build needs at least one input"));
    }
    match options.output_target.as_str() {
        "geoip" => build_geoip(options),
        "geosite" => build_geosite(options),
        "asn" => build_asn(options),
        value => Err(to_js_error(format!(
            "unsupported DB output target: {value}"
        ))),
    }
}

fn build_geoip(options: BuildDbOptions) -> Result<JsValue, JsValue> {
    let output_format = parse_db_format(options.output_format.as_deref(), MmdbFormat::Mmdb)?;
    let defaults = BuildDefaults::from_options(&options);
    let entries = options
        .entries
        .into_iter()
        .map(|entry| {
            Ok((
                normalize_key(&entry.key)?,
                collect_ip_rule_set(entry, &defaults)?,
            ))
        })
        .collect::<Result<Vec<_>, JsValue>>()?;
    any_db_to_js(build_geoip_db_to_memory(entries, output_format).map_err(to_js_error)?)
}

fn build_geosite(options: BuildDbOptions) -> Result<JsValue, JsValue> {
    let output_format = parse_db_format(options.output_format.as_deref(), MmdbFormat::Dat)?;
    let defaults = BuildDefaults::from_options(&options);
    let entries = options
        .entries
        .into_iter()
        .map(|entry| {
            Ok((
                normalize_key(&entry.key)?,
                convert_to_classical(entry, &defaults)?,
            ))
        })
        .collect::<Result<Vec<_>, JsValue>>()?;
    any_db_to_js(build_geosite_db_to_memory(entries, output_format).map_err(to_js_error)?)
}

fn build_asn(options: BuildDbOptions) -> Result<JsValue, JsValue> {
    let defaults = BuildDefaults::from_options(&options);
    let entries = options
        .entries
        .into_iter()
        .map(|entry| {
            let asn = parse_asn(&entry.key)?;
            Ok((asn, collect_ip_rule_set(entry, &defaults)?))
        })
        .collect::<Result<Vec<_>, JsValue>>()?;
    any_db_to_js(build_asn_mmdb_to_memory(entries).map_err(to_js_error)?)
}

fn convert_to_classical(
    entry: BuildDbEntry,
    defaults: &BuildDefaults,
) -> Result<rule_converter::ConvertResult, JsValue> {
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

fn collect_ip_rule_set(
    entry: BuildDbEntry,
    defaults: &BuildDefaults,
) -> Result<RuleSetOutput, JsValue> {
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

struct BuildDefaults {
    input_format: Option<String>,
    input_behavior: Option<String>,
}

impl BuildDefaults {
    fn from_options(options: &BuildDbOptions) -> Self {
        Self {
            input_format: options.input_format.clone(),
            input_behavior: options.input_behavior.clone(),
        }
    }
}

fn parse_db_format(value: Option<&str>, default: MmdbFormat) -> Result<MmdbFormat, JsValue> {
    value
        .map(MmdbFormat::parse)
        .transpose()
        .map_err(to_js_error)
        .map(|format| format.unwrap_or(default))
}

fn normalize_key(value: &str) -> Result<String, JsValue> {
    let key = value.trim().to_ascii_lowercase();
    if key.is_empty() {
        return Err(to_js_error("DB entry key is empty"));
    }
    Ok(key)
}

fn parse_asn(value: &str) -> Result<u32, JsValue> {
    let asn = value
        .trim()
        .trim_start_matches(['A', 'a'])
        .trim_start_matches(['S', 's']);
    asn.parse::<u32>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| to_js_error(format!("invalid ASN entry key: {value}")))
}
