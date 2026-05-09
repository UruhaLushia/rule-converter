use std::collections::BTreeMap;

use js_sys::{Object, Reflect, Uint8Array};
use rule_converter::{
    BehaviorMode, ConvertOptions as CoreConvertOptions, InputBehaviorMode, InputFormat, MmdbFormat,
    OutputFormat, RuleSetOutput, RuleTarget, build_asn_mmdb_to_memory, build_geoip_db_to_memory,
    build_geosite_dat_to_memory, convert_asn_mmdb_to_memory_filtered,
    convert_geoip_db_to_memory_filtered, convert_geosite_dat_to_memory_filtered, convert_payload,
    default_output_behavior, export_asn_mmdb_to_ipset_string, export_asn_mmdb_to_memory,
    export_geoip_db_to_memory, export_geoip_mmdb_to_ipset_string, export_geosite_dat_to_memory,
    list_asn_mmdb_asns_from_bytes, list_geoip_dat_countries, list_geoip_mmdb_countries_from_bytes,
    list_geosite_dat_codes, write_outputs_as_to_memory_owned,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnyConvertOptions {
    pub input_target: Option<String>,
    pub input_format: Option<String>,
    pub input_behavior: Option<String>,
    pub output_target: Option<String>,
    pub output_format: Option<String>,
    pub output_behavior: Option<String>,
    pub countries: Option<Vec<String>>,
    pub codes: Option<Vec<String>>,
    pub asns: Option<Vec<u32>>,
    pub split: Option<bool>,
    pub country: Option<String>,
    pub code: Option<String>,
    pub asn: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AnyTarget {
    Rule(Option<RuleTarget>),
    Geoip,
    Geosite,
    Asn,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SkippedRule {
    rule: String,
    reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DbRuleOutput {
    name: String,
    behavior: String,
    format: String,
    count: usize,
    bytes: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AnyOutputInfo {
    behavior: Option<String>,
    format: String,
    count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AnyStringResult {
    kind: String,
    outputs: BTreeMap<String, String>,
    info: BTreeMap<String, AnyOutputInfo>,
    skipped: Vec<SkippedRule>,
}

#[wasm_bindgen(js_name = bufToBuf)]
pub fn buf_to_buf_wasm(payload: &[u8], options: JsValue) -> Result<JsValue, JsValue> {
    let options = parse_any_options(options)?;
    convert_any_payload_to_js(payload, options)
}

#[wasm_bindgen(js_name = strToBuf)]
pub fn str_to_buf_wasm(payload: &str, options: JsValue) -> Result<JsValue, JsValue> {
    buf_to_buf_wasm(payload.as_bytes(), options)
}

#[wasm_bindgen(js_name = bufToStr)]
pub fn buf_to_str_wasm(payload: &[u8], options: JsValue) -> Result<JsValue, JsValue> {
    let options = parse_any_options(options)?;
    convert_any_payload_to_string_js(payload, options)
}

#[wasm_bindgen(js_name = strToStr)]
pub fn str_to_str_wasm(payload: &str, options: JsValue) -> Result<JsValue, JsValue> {
    let options = parse_any_options(options)?;
    convert_any_payload_to_string_js(payload.as_bytes(), options)
}

#[wasm_bindgen(js_name = listGeoipCountries)]
pub fn list_geoip_countries_wasm(payload: &[u8]) -> Result<JsValue, JsValue> {
    let countries = list_geoip_mmdb_countries_from_bytes(payload).map_err(to_js_error)?;
    serde_wasm_bindgen::to_value(&countries).map_err(to_js_error)
}

#[wasm_bindgen(js_name = listGeoipDatCountries)]
pub fn list_geoip_dat_countries_wasm(payload: &[u8]) -> Result<JsValue, JsValue> {
    let countries = list_geoip_dat_countries(payload).map_err(to_js_error)?;
    serde_wasm_bindgen::to_value(&countries).map_err(to_js_error)
}

#[wasm_bindgen(js_name = listGeositeCodes)]
pub fn list_geosite_codes_wasm(payload: &[u8]) -> Result<JsValue, JsValue> {
    let codes = list_geosite_dat_codes(payload).map_err(to_js_error)?;
    serde_wasm_bindgen::to_value(&codes).map_err(to_js_error)
}

#[wasm_bindgen(js_name = listAsnNumbers)]
pub fn list_asn_numbers_wasm(payload: &[u8]) -> Result<JsValue, JsValue> {
    let asns = list_asn_mmdb_asns_from_bytes(payload).map_err(to_js_error)?;
    serde_wasm_bindgen::to_value(&asns).map_err(to_js_error)
}

fn parse_any_options(value: JsValue) -> Result<AnyConvertOptions, JsValue> {
    if value.is_undefined() || value.is_null() {
        return Ok(AnyConvertOptions::default());
    }
    serde_wasm_bindgen::from_value(value).map_err(to_js_error)
}

fn convert_any_payload_to_js(
    payload: &[u8],
    options: AnyConvertOptions,
) -> Result<JsValue, JsValue> {
    match parse_any_target(options.input_target.as_deref(), true)? {
        AnyTarget::Rule(input_target) => {
            convert_rule_payload_any_to_js(payload, input_target, options)
        }
        AnyTarget::Geoip => convert_geoip_payload_any_to_js(payload, options),
        AnyTarget::Geosite => convert_geosite_payload_any_to_js(payload, options),
        AnyTarget::Asn => convert_asn_payload_any_to_js(payload, options),
    }
}

fn convert_any_payload_to_string_js(
    payload: &[u8],
    options: AnyConvertOptions,
) -> Result<JsValue, JsValue> {
    match parse_any_target(options.input_target.as_deref(), true)? {
        AnyTarget::Rule(input_target) => any_js_to_string(convert_rule_payload_any_to_js(
            payload,
            input_target,
            options,
        )?),
        AnyTarget::Geoip => convert_geoip_payload_any_to_string_js(payload, options),
        AnyTarget::Geosite => {
            any_js_to_string(convert_geosite_payload_any_to_js(payload, options)?)
        }
        AnyTarget::Asn => convert_asn_payload_any_to_string_js(payload, options),
    }
}

fn convert_rule_payload_any_to_js(
    payload: &[u8],
    input_target: Option<RuleTarget>,
    options: AnyConvertOptions,
) -> Result<JsValue, JsValue> {
    match parse_any_target(options.output_target.as_deref(), false)? {
        AnyTarget::Rule(output_target) => {
            let output_target = output_target.unwrap_or(RuleTarget::Mihomo);
            let output_format = options
                .output_format
                .as_deref()
                .map(OutputFormat::parse_arg)
                .transpose()
                .map_err(to_js_error)?
                .unwrap_or(OutputFormat::Mrs);
            let output_behavior = options
                .output_behavior
                .as_deref()
                .map(BehaviorMode::parse_arg)
                .transpose()
                .map_err(to_js_error)?
                .unwrap_or_else(|| default_output_behavior(output_target, output_format));
            let result = convert_payload(
                payload,
                CoreConvertOptions {
                    input_target,
                    input_format: options
                        .input_format
                        .as_deref()
                        .map(InputFormat::parse_arg)
                        .transpose()
                        .map_err(to_js_error)?,
                    input_behavior: options
                        .input_behavior
                        .as_deref()
                        .map(InputBehaviorMode::parse_arg)
                        .transpose()
                        .map_err(to_js_error)?
                        .unwrap_or(InputBehaviorMode::Auto),
                    output_target,
                    output_format,
                    output_behavior,
                },
            )
            .map_err(to_js_error)?;
            let (outputs, skipped) =
                write_outputs_as_to_memory_owned(result, output_target, output_format)
                    .map_err(to_js_error)?;
            any_rules_to_js(
                outputs
                    .into_iter()
                    .map(|output| DbRuleOutput {
                        name: output.behavior.as_str().to_string(),
                        behavior: output.behavior.as_str().to_string(),
                        format: output.format.as_str().to_string(),
                        count: output.count,
                        bytes: output.bytes,
                    })
                    .collect(),
                skipped,
            )
        }
        AnyTarget::Geoip => {
            let country = options
                .country
                .ok_or_else(|| to_js_error("geoip DB output needs country"))?;
            let rule_set = collect_ip_rule_set_from_payload(
                payload,
                input_target.map(|target| target.as_str().to_string()),
                options.input_format,
                options.input_behavior,
            )?;
            let output_format = parse_optional_db_format(options.output_format.as_deref())?
                .unwrap_or(MmdbFormat::Mmdb);
            let output = build_geoip_db_to_memory([(country, rule_set)], output_format)
                .map_err(to_js_error)?;
            any_db_to_js(output)
        }
        AnyTarget::Geosite => {
            let code = options
                .code
                .or(options.country)
                .ok_or_else(|| to_js_error("geosite dat output needs code"))?;
            validate_geosite_db_format(options.output_format.as_deref())?;
            let result = convert_rule_payload_to_classical(
                payload,
                input_target.map(|target| target.as_str().to_string()),
                options.input_format,
                options.input_behavior,
            )?;
            let output = build_geosite_dat_to_memory([(code, result)]).map_err(to_js_error)?;
            any_db_to_js(output)
        }
        AnyTarget::Asn => {
            let asn = options
                .asn
                .ok_or_else(|| to_js_error("asn DB output needs asn"))?;
            validate_asn_db_format(options.output_format.as_deref())?;
            let rule_set = collect_ip_rule_set_from_payload(
                payload,
                input_target.map(|target| target.as_str().to_string()),
                options.input_format,
                options.input_behavior,
            )?;
            let output = build_asn_mmdb_to_memory([(asn, rule_set)]).map_err(to_js_error)?;
            any_db_to_js(output)
        }
    }
}

fn convert_geoip_payload_any_to_js(
    payload: &[u8],
    options: AnyConvertOptions,
) -> Result<JsValue, JsValue> {
    match parse_any_target(options.output_target.as_deref(), false)? {
        AnyTarget::Rule(output_target) => {
            let output_target = output_target.unwrap_or(RuleTarget::General);
            let output_format = options
                .output_format
                .as_deref()
                .map(OutputFormat::parse_arg)
                .transpose()
                .map_err(to_js_error)?
                .unwrap_or(OutputFormat::IpSet);
            let output_behavior = options
                .output_behavior
                .as_deref()
                .map(BehaviorMode::parse_arg)
                .transpose()
                .map_err(to_js_error)?
                .unwrap_or_else(|| default_output_behavior(output_target, output_format));
            let input_format = parse_optional_db_format(options.input_format.as_deref())?
                .unwrap_or(MmdbFormat::Mmdb);
            let countries = one_or_many_string(options.country, options.countries);
            let split = options.split.unwrap_or(true);
            let outputs = export_geoip_db_to_memory(
                payload,
                input_format,
                &countries,
                split,
                output_target,
                output_format,
                output_behavior,
            )
            .map_err(to_js_error)?;
            any_db_rules_to_js(outputs)
        }
        AnyTarget::Geoip => {
            let input_format = parse_optional_db_format(options.input_format.as_deref())?
                .unwrap_or(MmdbFormat::Mmdb);
            let output_format = parse_optional_db_format(options.output_format.as_deref())?
                .unwrap_or(MmdbFormat::Mmdb);
            let countries = one_or_many_string(options.country, options.countries);
            let output = convert_geoip_db_to_memory_filtered(
                payload,
                input_format,
                &countries,
                output_format,
            )
            .map_err(to_js_error)?;
            any_db_to_js(output)
        }
        AnyTarget::Geosite => Err(to_js_error("cannot convert geoip DB to geosite DB")),
        AnyTarget::Asn => Err(to_js_error("cannot convert geoip DB to asn DB")),
    }
}

fn convert_geoip_payload_any_to_string_js(
    payload: &[u8],
    options: AnyConvertOptions,
) -> Result<JsValue, JsValue> {
    if can_use_db_ipset_string_fast_path(&options)? {
        let countries = one_or_many_string(options.country, options.countries);
        let output = export_geoip_mmdb_to_ipset_string(payload, &countries).map_err(to_js_error)?;
        return any_db_string_to_js(output);
    }
    any_js_to_string(convert_geoip_payload_any_to_js(payload, options)?)
}

fn convert_geosite_payload_any_to_js(
    payload: &[u8],
    options: AnyConvertOptions,
) -> Result<JsValue, JsValue> {
    validate_geosite_db_format(options.input_format.as_deref())?;
    match parse_any_target(options.output_target.as_deref(), false)? {
        AnyTarget::Rule(output_target) => {
            let output_target = output_target.unwrap_or(RuleTarget::General);
            let output_format = options
                .output_format
                .as_deref()
                .map(OutputFormat::parse_arg)
                .transpose()
                .map_err(to_js_error)?
                .unwrap_or(OutputFormat::RuleSet);
            let output_behavior = options
                .output_behavior
                .as_deref()
                .map(BehaviorMode::parse_arg)
                .transpose()
                .map_err(to_js_error)?
                .unwrap_or_else(|| default_output_behavior(output_target, output_format));
            let codes = one_or_many_string(
                options.code.or(options.country),
                options.codes.or(options.countries),
            );
            let split = options.split.unwrap_or(true);
            let outputs = export_geosite_dat_to_memory(
                payload,
                &codes,
                split,
                output_target,
                output_format,
                output_behavior,
            )
            .map_err(to_js_error)?;
            any_db_rules_to_js(outputs)
        }
        AnyTarget::Geosite => {
            validate_geosite_db_format(options.output_format.as_deref())?;
            let codes = one_or_many_string(
                options.code.or(options.country),
                options.codes.or(options.countries),
            );
            let output =
                convert_geosite_dat_to_memory_filtered(payload, &codes).map_err(to_js_error)?;
            any_db_to_js(output)
        }
        AnyTarget::Geoip => Err(to_js_error("cannot convert geosite DB to geoip DB")),
        AnyTarget::Asn => Err(to_js_error("cannot convert geosite DB to asn DB")),
    }
}

fn convert_asn_payload_any_to_js(
    payload: &[u8],
    options: AnyConvertOptions,
) -> Result<JsValue, JsValue> {
    match parse_any_target(options.output_target.as_deref(), false)? {
        AnyTarget::Rule(output_target) => {
            let output_target = output_target.unwrap_or(RuleTarget::General);
            let output_format = options
                .output_format
                .as_deref()
                .map(OutputFormat::parse_arg)
                .transpose()
                .map_err(to_js_error)?
                .unwrap_or(OutputFormat::IpSet);
            let output_behavior = options
                .output_behavior
                .as_deref()
                .map(BehaviorMode::parse_arg)
                .transpose()
                .map_err(to_js_error)?
                .unwrap_or_else(|| default_output_behavior(output_target, output_format));
            let asns = one_or_many_u32(options.asn, options.asns);
            let split = options.split.unwrap_or(true);
            let outputs = export_asn_mmdb_to_memory(
                payload,
                &asns,
                split,
                output_target,
                output_format,
                output_behavior,
            )
            .map_err(to_js_error)?;
            any_db_rules_to_js(outputs)
        }
        AnyTarget::Asn => {
            validate_asn_db_format(options.output_format.as_deref())?;
            let asns = one_or_many_u32(options.asn, options.asns);
            let output =
                convert_asn_mmdb_to_memory_filtered(payload, &asns).map_err(to_js_error)?;
            any_db_to_js(output)
        }
        AnyTarget::Geoip => Err(to_js_error("cannot convert asn DB to geoip DB")),
        AnyTarget::Geosite => Err(to_js_error("cannot convert asn DB to geosite DB")),
    }
}

fn convert_asn_payload_any_to_string_js(
    payload: &[u8],
    options: AnyConvertOptions,
) -> Result<JsValue, JsValue> {
    if can_use_db_ipset_string_fast_path(&options)? {
        let asns = one_or_many_u32(options.asn, options.asns);
        let output = export_asn_mmdb_to_ipset_string(payload, &asns).map_err(to_js_error)?;
        return any_db_string_to_js(output);
    }
    any_js_to_string(convert_asn_payload_any_to_js(payload, options)?)
}

fn one_or_many_string(one: Option<String>, many: Option<Vec<String>>) -> Vec<String> {
    let mut values = many.unwrap_or_default();
    if let Some(one) = one {
        values.push(one);
    }
    values
}

fn one_or_many_u32(one: Option<u32>, many: Option<Vec<u32>>) -> Vec<u32> {
    let mut values = many.unwrap_or_default();
    if let Some(one) = one {
        values.push(one);
    }
    values
}

fn parse_any_target(
    value: Option<&str>,
    allow_auto_rule_input: bool,
) -> Result<AnyTarget, JsValue> {
    match value {
        Some("geoip") => Ok(AnyTarget::Geoip),
        Some("geosite") => Ok(AnyTarget::Geosite),
        Some("asn") => Ok(AnyTarget::Asn),
        Some(value) => Ok(AnyTarget::Rule(Some(
            RuleTarget::parse_arg(value).map_err(to_js_error)?,
        ))),
        None if allow_auto_rule_input => Ok(AnyTarget::Rule(None)),
        None => Ok(AnyTarget::Rule(Some(RuleTarget::Mihomo))),
    }
}

fn parse_optional_db_format(value: Option<&str>) -> Result<Option<MmdbFormat>, JsValue> {
    value
        .map(MmdbFormat::parse)
        .transpose()
        .map_err(to_js_error)
}

fn validate_asn_db_format(value: Option<&str>) -> Result<(), JsValue> {
    if let Some(format) = parse_optional_db_format(value)? {
        if format != MmdbFormat::Mmdb {
            return Err(to_js_error("ASN target only supports mmdb format"));
        }
    }
    Ok(())
}

fn validate_geosite_db_format(value: Option<&str>) -> Result<(), JsValue> {
    if let Some(format) = parse_optional_db_format(value)? {
        if format != MmdbFormat::Dat {
            return Err(to_js_error("geosite target only supports dat format"));
        }
    }
    Ok(())
}

fn any_db_rules_to_js(outputs: Vec<rule_converter::DbMemoryOutput>) -> Result<JsValue, JsValue> {
    let mut values = BTreeMap::new();
    let mut info = BTreeMap::new();
    for output in outputs {
        let name = output.name;
        info.insert(
            name.clone(),
            AnyOutputInfo {
                behavior: Some(output.behavior.as_str().to_string()),
                format: output.format.as_str().to_string(),
                count: output.count,
            },
        );
        values.insert(name, output.bytes);
    }
    any_parts_to_js("rules", values, info, Vec::new())
}

fn any_rules_to_js(
    outputs: Vec<DbRuleOutput>,
    skipped: Vec<rule_converter::SkippedRule>,
) -> Result<JsValue, JsValue> {
    let mut values = BTreeMap::new();
    let mut info = BTreeMap::new();
    for output in outputs {
        let name = output.name;
        info.insert(
            name.clone(),
            AnyOutputInfo {
                behavior: Some(output.behavior),
                format: output.format,
                count: output.count,
            },
        );
        values.insert(name, output.bytes);
    }
    any_parts_to_js("rules", values, info, skipped)
}

fn any_db_to_js(output: rule_converter::DbBytesOutput) -> Result<JsValue, JsValue> {
    any_parts_to_js(
        "db",
        BTreeMap::from([("db".to_string(), output.bytes)]),
        BTreeMap::from([(
            "db".to_string(),
            AnyOutputInfo {
                behavior: None,
                format: output.format.as_str().to_string(),
                count: output.count,
            },
        )]),
        Vec::new(),
    )
}

fn any_db_string_to_js(output: rule_converter::DbStringOutput) -> Result<JsValue, JsValue> {
    let name = output.name;
    any_to_value(&AnyStringResult {
        kind: "rules".to_string(),
        outputs: BTreeMap::from([(name.clone(), output.text)]),
        info: BTreeMap::from([(
            name,
            AnyOutputInfo {
                behavior: Some(output.behavior.as_str().to_string()),
                format: output.format.as_str().to_string(),
                count: output.count,
            },
        )]),
        skipped: Vec::new(),
    })
}

fn any_parts_to_js(
    kind: &str,
    outputs: BTreeMap<String, Vec<u8>>,
    info: BTreeMap<String, AnyOutputInfo>,
    skipped: Vec<rule_converter::SkippedRule>,
) -> Result<JsValue, JsValue> {
    let result = Object::new();
    set_prop(&result, "kind", &JsValue::from_str(kind))?;

    let output_object = Object::new();
    for (name, bytes) in outputs {
        let bytes_value = Uint8Array::new_with_length(bytes.len() as u32);
        bytes_value.copy_from(&bytes);
        set_prop(&output_object, &name, bytes_value.as_ref())?;
    }
    set_prop(&result, "outputs", output_object.as_ref())?;

    set_prop(&result, "info", &any_to_value(&info)?)?;
    set_prop(
        &result,
        "skipped",
        &any_to_value(
            &skipped
                .into_iter()
                .map(|item| SkippedRule {
                    rule: item.rule,
                    reason: item.reason,
                })
                .collect::<Vec<_>>(),
        )?,
    )?;
    Ok(result.into())
}

fn can_use_db_ipset_string_fast_path(options: &AnyConvertOptions) -> Result<bool, JsValue> {
    if options.split.unwrap_or(true) {
        return Ok(false);
    }
    if matches!(
        parse_optional_db_format(options.input_format.as_deref())?,
        Some(MmdbFormat::Dat)
    ) {
        return Ok(false);
    }
    let AnyTarget::Rule(output_target) = parse_any_target(options.output_target.as_deref(), false)?
    else {
        return Ok(false);
    };
    let output_target = output_target.unwrap_or(RuleTarget::General);
    let output_format = options
        .output_format
        .as_deref()
        .map(OutputFormat::parse_arg)
        .transpose()
        .map_err(to_js_error)?
        .unwrap_or(OutputFormat::IpSet);
    let output_behavior = options
        .output_behavior
        .as_deref()
        .map(BehaviorMode::parse_arg)
        .transpose()
        .map_err(to_js_error)?
        .unwrap_or_else(|| default_output_behavior(output_target, output_format));
    Ok(output_target == RuleTarget::General
        && output_format == OutputFormat::IpSet
        && output_behavior == BehaviorMode::Ipcidr)
}

fn any_js_to_string(value: JsValue) -> Result<JsValue, JsValue> {
    let kind = Reflect::get(&value, &JsValue::from_str("kind"))?
        .as_string()
        .ok_or_else(|| to_js_error("missing result kind"))?;
    let outputs_value = Reflect::get(&value, &JsValue::from_str("outputs"))?;
    let info: BTreeMap<String, AnyOutputInfo> =
        serde_wasm_bindgen::from_value(Reflect::get(&value, &JsValue::from_str("info"))?)
            .map_err(to_js_error)?;
    let skipped: Vec<SkippedRule> =
        serde_wasm_bindgen::from_value(Reflect::get(&value, &JsValue::from_str("skipped"))?)
            .map_err(to_js_error)?;

    let output_object = Object::from(outputs_value);
    let names = Object::keys(&output_object);
    let mut outputs = BTreeMap::new();
    for index in 0..names.length() {
        let name = names
            .get(index)
            .as_string()
            .ok_or_else(|| to_js_error("output key is not a string"))?;
        let bytes =
            Uint8Array::new(&Reflect::get(&output_object, &JsValue::from_str(&name))?).to_vec();
        let text = String::from_utf8(bytes)
            .map_err(|err| to_js_error(format!("output {name} is not valid UTF-8: {err}")))?;
        outputs.insert(name, text);
    }
    any_to_value(&AnyStringResult {
        kind,
        outputs,
        info,
        skipped,
    })
}

fn set_prop(target: &Object, key: &str, value: &JsValue) -> Result<(), JsValue> {
    Reflect::set(target, &JsValue::from_str(key), value).map(|_| ())
}

fn convert_rule_payload_to_classical(
    payload: &[u8],
    input_target: Option<String>,
    input_format: Option<String>,
    input_behavior: Option<String>,
) -> Result<rule_converter::ConvertResult, JsValue> {
    let options = CoreConvertOptions {
        input_target: input_target
            .as_deref()
            .map(RuleTarget::parse_arg)
            .transpose()
            .map_err(to_js_error)?,
        input_format: input_format
            .as_deref()
            .map(InputFormat::parse_arg)
            .transpose()
            .map_err(to_js_error)?,
        input_behavior: input_behavior
            .as_deref()
            .map(InputBehaviorMode::parse_arg)
            .transpose()
            .map_err(to_js_error)?
            .unwrap_or(InputBehaviorMode::Auto),
        output_target: RuleTarget::General,
        output_format: OutputFormat::RuleSet,
        output_behavior: BehaviorMode::Classical,
    };
    convert_payload(payload, options).map_err(to_js_error)
}

fn collect_ip_rule_set_from_payload(
    payload: &[u8],
    input_target: Option<String>,
    input_format: Option<String>,
    input_behavior: Option<String>,
) -> Result<RuleSetOutput, JsValue> {
    let options = CoreConvertOptions {
        input_target: input_target
            .as_deref()
            .map(RuleTarget::parse_arg)
            .transpose()
            .map_err(to_js_error)?,
        input_format: input_format
            .as_deref()
            .map(InputFormat::parse_arg)
            .transpose()
            .map_err(to_js_error)?,
        input_behavior: input_behavior
            .as_deref()
            .map(InputBehaviorMode::parse_arg)
            .transpose()
            .map_err(to_js_error)?
            .unwrap_or(InputBehaviorMode::Auto),
        output_target: RuleTarget::General,
        output_format: OutputFormat::IpSet,
        output_behavior: BehaviorMode::Ipcidr,
    };
    let result = convert_payload(payload, options).map_err(to_js_error)?;
    for output in result.outputs {
        if matches!(output, RuleSetOutput::Ipcidr(_)) {
            return Ok(output);
        }
    }
    Err(to_js_error(
        "DB build input does not contain any IP CIDR rules",
    ))
}

fn any_to_value<T: Serialize + ?Sized>(value: &T) -> Result<JsValue, JsValue> {
    value
        .serialize(
            &serde_wasm_bindgen::Serializer::new()
                .serialize_maps_as_objects(true)
                .serialize_missing_as_null(true),
        )
        .map_err(to_js_error)
}

fn to_js_error(err: impl std::fmt::Display) -> JsValue {
    js_sys::Error::new(&err.to_string()).into()
}
