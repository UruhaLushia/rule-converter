use rule_converter::{
    BehaviorMode, ConvertOptions as CoreConvertOptions, InputBehaviorMode, InputFormat,
    OutputFormat, RuleTarget, convert_payload, default_output_behavior,
    write_outputs_as_to_memory_owned,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConvertOptions {
    pub input_target: Option<String>,
    pub input_format: Option<String>,
    pub input_behavior: Option<String>,
    pub output_target: Option<String>,
    pub output_format: Option<String>,
    pub output_behavior: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConvertOutput {
    behavior: String,
    format: String,
    count: usize,
    bytes: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SkippedRule {
    rule: String,
    reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConvertResult {
    outputs: Vec<ConvertOutput>,
    skipped: Vec<SkippedRule>,
}

#[wasm_bindgen(js_name = convertPayload)]
pub fn convert_payload_wasm(payload: &[u8], options: JsValue) -> Result<JsValue, JsValue> {
    let options = parse_options(options)?;
    let output_target = options.output_target;
    let output_format = options.output_format;
    let result = convert_payload(payload, options).map_err(to_js_error)?;
    let (outputs, skipped) = write_outputs_as_to_memory_owned(result, output_target, output_format)
        .map_err(to_js_error)?;
    let result = ConvertResult {
        outputs: outputs
            .into_iter()
            .map(|output| ConvertOutput {
                behavior: output.behavior.as_str().to_string(),
                format: output.format.as_str().to_string(),
                count: output.count,
                bytes: output.bytes,
            })
            .collect(),
        skipped: skipped
            .into_iter()
            .map(|item| SkippedRule {
                rule: item.rule,
                reason: item.reason,
            })
            .collect(),
    };
    serde_wasm_bindgen::to_value(&result).map_err(to_js_error)
}

#[wasm_bindgen(js_name = convertPayloadString)]
pub fn convert_payload_string_wasm(payload: &str, options: JsValue) -> Result<JsValue, JsValue> {
    convert_payload_wasm(payload.as_bytes(), options)
}

fn parse_options(value: JsValue) -> Result<CoreConvertOptions, JsValue> {
    if value.is_undefined() || value.is_null() {
        return Ok(CoreConvertOptions::default());
    }

    let options: ConvertOptions = serde_wasm_bindgen::from_value(value).map_err(to_js_error)?;
    let output_target = options
        .output_target
        .as_deref()
        .map(RuleTarget::parse_arg)
        .transpose()
        .map_err(to_js_error)?
        .unwrap_or(RuleTarget::Mihomo);
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

    Ok(CoreConvertOptions {
        input_target: options
            .input_target
            .as_deref()
            .map(RuleTarget::parse_arg)
            .transpose()
            .map_err(to_js_error)?,
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
    })
}

fn to_js_error(err: impl std::fmt::Display) -> JsValue {
    js_sys::Error::new(&err.to_string()).into()
}
