use rule_converter::{
    BehaviorMode, MmdbFormat, OutputFormat, RuleTarget, convert_geosite_db_to_memory_filtered,
    default_output_behavior, export_geosite_db_to_memory,
};
use wasm_bindgen::prelude::*;

use super::options::{
    one_or_many_string, parse_any_target, parse_optional_db_format, validate_geosite_db_format,
};
use crate::error::to_js_error;
use crate::result::{any_db_rules_to_js, any_db_to_js};
use crate::types::{AnyConvertOptions, AnyTarget};

pub(super) fn convert_geosite_payload_any_to_js(
    payload: &[u8],
    options: AnyConvertOptions,
) -> Result<JsValue, JsValue> {
    let input_format = geosite_input_format(payload, options.input_format.as_deref())?;
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
            let outputs = export_geosite_db_to_memory(
                payload,
                input_format,
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
            let output_format = parse_optional_db_format(options.output_format.as_deref())?
                .unwrap_or(MmdbFormat::Dat);
            let codes = one_or_many_string(
                options.code.or(options.country),
                options.codes.or(options.countries),
            );
            let output =
                convert_geosite_db_to_memory_filtered(payload, input_format, &codes, output_format)
                    .map_err(to_js_error)?;
            any_db_to_js(output)
        }
        AnyTarget::Geoip => Err(to_js_error("cannot convert geosite DB to geoip DB")),
        AnyTarget::Asn => Err(to_js_error("cannot convert geosite DB to asn DB")),
    }
}

fn geosite_input_format(payload: &[u8], value: Option<&str>) -> Result<MmdbFormat, JsValue> {
    validate_geosite_db_format(value)?;
    if let Some(format) = parse_optional_db_format(value)? {
        return Ok(format);
    }
    let detected = rule_converter::detect_payload_type(payload).map_err(to_js_error)?;
    parse_optional_db_format(Some(&detected.format))?
        .ok_or_else(|| to_js_error(format!("unsupported geosite format: {}", detected.format)))
}
