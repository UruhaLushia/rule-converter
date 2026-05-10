mod asn;
mod geoip;
mod geosite;
mod options;
mod result;
mod rules;

use napi::bindgen_prelude::{Result, Uint8Array};
use napi_derive::napi;

use self::asn::{
    convert_asn_file_any_to_buffer, convert_asn_file_any_to_string,
    convert_asn_payload_any_to_buffer, convert_asn_payload_any_to_string,
};
use self::geoip::{
    convert_geoip_file_any_to_buffer, convert_geoip_file_any_to_string,
    convert_geoip_payload_any_to_buffer, convert_geoip_payload_any_to_string,
};
use self::geosite::{convert_geosite_file_any_to_buffer, convert_geosite_payload_any_to_buffer};
use self::options::parse_any_input_target;
use self::result::any_buffer_result_to_string;
use self::rules::{convert_rule_file_any_to_buffer, convert_rule_payload_any_to_buffer};
use crate::types::{AnyBufferResult, AnyConvertOptions, AnyStringResult, AnyTarget};

#[napi]
pub fn buf_to_buf(
    input: Uint8Array,
    options: Option<AnyConvertOptions>,
) -> Result<AnyBufferResult> {
    convert_any_payload_to_buffer(input.as_ref(), options)
}

#[napi]
pub fn str_to_buf(input: String, options: Option<AnyConvertOptions>) -> Result<AnyBufferResult> {
    convert_any_payload_to_buffer(input.as_bytes(), options)
}

#[napi]
pub fn file_to_buf(input: String, options: Option<AnyConvertOptions>) -> Result<AnyBufferResult> {
    convert_any_file_to_buffer(input, options)
}

#[napi]
pub fn buf_to_str(
    input: Uint8Array,
    options: Option<AnyConvertOptions>,
) -> Result<AnyStringResult> {
    convert_any_payload_to_string(input.as_ref(), options)
}

#[napi]
pub fn str_to_str(input: String, options: Option<AnyConvertOptions>) -> Result<AnyStringResult> {
    convert_any_payload_to_string(input.as_bytes(), options)
}

#[napi]
pub fn file_to_str(input: String, options: Option<AnyConvertOptions>) -> Result<AnyStringResult> {
    convert_any_file_to_string(input, options)
}

fn convert_any_file_to_buffer(
    input: String,
    options: Option<AnyConvertOptions>,
) -> Result<AnyBufferResult> {
    let options = options.unwrap_or_default();
    let input_target = parse_file_input_target(&input, &options)?;
    match input_target {
        AnyTarget::Rule(input_target) => {
            convert_rule_file_any_to_buffer(input, input_target, options)
        }
        AnyTarget::Geoip => convert_geoip_file_any_to_buffer(input, options),
        AnyTarget::Geosite => convert_geosite_file_any_to_buffer(input, options),
        AnyTarget::Asn => convert_asn_file_any_to_buffer(input, options),
    }
}

fn convert_any_payload_to_buffer(
    payload: &[u8],
    options: Option<AnyConvertOptions>,
) -> Result<AnyBufferResult> {
    convert_any_payload_to_buffer_with_options(payload, options.unwrap_or_default())
}

fn convert_any_payload_to_buffer_with_options(
    payload: &[u8],
    options: AnyConvertOptions,
) -> Result<AnyBufferResult> {
    match parse_payload_input_target(payload, &options)? {
        AnyTarget::Rule(input_target) => {
            convert_rule_payload_any_to_buffer(payload, input_target, options)
        }
        AnyTarget::Geoip => convert_geoip_payload_any_to_buffer(payload, options),
        AnyTarget::Geosite => convert_geosite_payload_any_to_buffer(payload, options),
        AnyTarget::Asn => convert_asn_payload_any_to_buffer(payload, options),
    }
}

fn convert_any_file_to_string(
    input: String,
    options: Option<AnyConvertOptions>,
) -> Result<AnyStringResult> {
    let options = options.unwrap_or_default();
    let input_target = parse_file_input_target(&input, &options)?;
    match input_target {
        AnyTarget::Geoip => convert_geoip_file_any_to_string(input, options),
        AnyTarget::Geosite => {
            any_buffer_result_to_string(convert_geosite_file_any_to_buffer(input, options)?)
        }
        AnyTarget::Asn => convert_asn_file_any_to_string(input, options),
        AnyTarget::Rule(input_target) => any_buffer_result_to_string(
            convert_rule_file_any_to_buffer(input, input_target, options)?,
        ),
    }
}

fn convert_any_payload_to_string(
    payload: &[u8],
    options: Option<AnyConvertOptions>,
) -> Result<AnyStringResult> {
    let options = options.unwrap_or_default();
    match parse_payload_input_target(payload, &options)? {
        AnyTarget::Geoip => convert_geoip_payload_any_to_string(payload, options),
        AnyTarget::Geosite => {
            any_buffer_result_to_string(convert_geosite_payload_any_to_buffer(payload, options)?)
        }
        AnyTarget::Asn => convert_asn_payload_any_to_string(payload, options),
        AnyTarget::Rule(input_target) => any_buffer_result_to_string(
            convert_rule_payload_any_to_buffer(payload, input_target, options)?,
        ),
    }
}

fn parse_file_input_target(input: &str, options: &AnyConvertOptions) -> Result<AnyTarget> {
    if options.input_target.is_some() {
        return parse_any_input_target(options.input_target.as_deref());
    }
    let bytes = std::fs::read(input).map_err(|err| napi::Error::from_reason(err.to_string()))?;
    parse_payload_input_target(&bytes, options)
}

fn parse_payload_input_target(payload: &[u8], options: &AnyConvertOptions) -> Result<AnyTarget> {
    if options.input_target.is_some() {
        return parse_any_input_target(options.input_target.as_deref());
    }
    if matches!(options.input_format.as_deref(), None | Some("dat")) {
        match rule_converter::codec::dat::detect_dat_kind(payload) {
            Some(rule_converter::codec::dat::DatKind::Geoip) => return Ok(AnyTarget::Geoip),
            Some(rule_converter::codec::dat::DatKind::Geosite) => return Ok(AnyTarget::Geosite),
            None => {}
        }
    }
    parse_any_input_target(None)
}
