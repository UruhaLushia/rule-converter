use napi::bindgen_prelude::Result;
use rule_converter::{
    MmdbFormat, OutputFormat, RuleTarget, convert_geosite_db_to_memory_filtered,
    default_output_behavior, export_geosite_db_to_memory,
};

use super::options::{
    one_or_many_string, parse_any_output_target, parse_db_format_value, parse_output_behavior,
    parse_rule_output_format, validate_geosite_input_format, validate_geosite_output_format,
};
use super::result::{any_db_result, any_db_rules_result};
use crate::error::to_napi_error;
use crate::types::{AnyBufferResult, AnyConvertOptions, AnyTarget};

pub(super) fn convert_geosite_file_any_to_buffer(
    input: String,
    options: AnyConvertOptions,
) -> Result<AnyBufferResult> {
    let bytes = std::fs::read(input).map_err(|err| napi::Error::from_reason(err.to_string()))?;
    let input_format = geosite_input_format(&bytes, options.input_format.as_deref())?;
    convert_geosite_bytes_any_to_buffer(&bytes, input_format, options)
}

pub(super) fn convert_geosite_payload_any_to_buffer(
    payload: &[u8],
    options: AnyConvertOptions,
) -> Result<AnyBufferResult> {
    let input_format = geosite_input_format(payload, options.input_format.as_deref())?;
    convert_geosite_bytes_any_to_buffer(payload, input_format, options)
}

fn convert_geosite_bytes_any_to_buffer(
    payload: &[u8],
    input_format: MmdbFormat,
    options: AnyConvertOptions,
) -> Result<AnyBufferResult> {
    match parse_any_output_target(options.output_target.as_deref())? {
        AnyTarget::Rule(output_target) => {
            let output_target = output_target.unwrap_or(RuleTarget::General);
            let output_format = parse_rule_output_format(options.output_format.as_deref())?
                .unwrap_or(OutputFormat::RuleSet);
            let output_behavior = parse_output_behavior(options.output_behavior.as_deref())?
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
            .map_err(to_napi_error)?;
            Ok(any_db_rules_result(outputs))
        }
        AnyTarget::Geosite => {
            validate_geosite_output_format(options.output_format.as_deref())?;
            let output_format =
                parse_db_format_value(options.output_format.as_deref())?.unwrap_or(MmdbFormat::Dat);
            let codes = one_or_many_string(
                options.code.or(options.country),
                options.codes.or(options.countries),
            );
            let output =
                convert_geosite_db_to_memory_filtered(payload, input_format, &codes, output_format)
                    .map_err(to_napi_error)?;
            Ok(any_db_result(output))
        }
        AnyTarget::Geoip => Err(napi::Error::from_reason(
            "cannot convert geosite DB to geoip DB",
        )),
        AnyTarget::Asn => Err(napi::Error::from_reason(
            "cannot convert geosite DB to asn DB",
        )),
    }
}

fn geosite_input_format(payload: &[u8], value: Option<&str>) -> Result<MmdbFormat> {
    validate_geosite_input_format(value)?;
    if let Some(format) = parse_db_format_value(value)? {
        return Ok(format);
    }
    let detected = rule_converter::detect_payload_type(payload).map_err(to_napi_error)?;
    parse_db_format_value(Some(&detected.format))?.ok_or_else(|| {
        napi::Error::from_reason(format!("unsupported geosite format: {}", detected.format))
    })
}
