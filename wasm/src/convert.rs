mod asn;
mod geoip;
mod geosite;
mod options;
mod rules;

use wasm_bindgen::prelude::*;

use self::asn::{convert_asn_payload_any_to_js, convert_asn_payload_any_to_string_js};
use self::geoip::{convert_geoip_payload_any_to_js, convert_geoip_payload_any_to_string_js};
use self::geosite::convert_geosite_payload_any_to_js;
use self::options::{any_target_from_detect_target, parse_any_target};
use self::rules::convert_rule_payload_any_to_js;
use crate::error::to_js_error;
use crate::result::any_js_to_string;
use crate::types::{AnyConvertOptions, AnyTarget};

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
    match parse_payload_input_target(payload, &options)? {
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
    match parse_payload_input_target(payload, &options)? {
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

fn parse_payload_input_target(
    payload: &[u8],
    options: &AnyConvertOptions,
) -> Result<AnyTarget, JsValue> {
    if options.input_target.is_some() {
        return parse_any_target(options.input_target.as_deref(), true);
    }
    any_target_from_detect_target(
        rule_converter::detect_payload_target(payload).map_err(to_js_error)?,
    )
}
