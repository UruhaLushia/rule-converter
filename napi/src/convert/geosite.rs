use napi::bindgen_prelude::Result;
use rule_converter::{
    OutputFormat, RuleTarget, default_output_behavior, export_geosite_dat_to_memory,
};

use super::options::{
    one_or_many_string, parse_any_output_target, parse_output_behavior, parse_rule_output_format,
    validate_geosite_input_format, validate_geosite_output_format,
};
use super::result::{any_db_result, any_db_rules_result};
use crate::error::to_napi_error;
use crate::types::{AnyBufferResult, AnyConvertOptions, AnyTarget};

pub(super) fn convert_geosite_file_any_to_buffer(
    input: String,
    options: AnyConvertOptions,
) -> Result<AnyBufferResult> {
    validate_geosite_input_format(options.input_format.as_deref())?;
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
            let bytes =
                std::fs::read(input).map_err(|err| napi::Error::from_reason(err.to_string()))?;
            let outputs = export_geosite_dat_to_memory(
                &bytes,
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
            let codes = one_or_many_string(
                options.code.or(options.country),
                options.codes.or(options.countries),
            );
            let bytes =
                std::fs::read(input).map_err(|err| napi::Error::from_reason(err.to_string()))?;
            let output = rule_converter::convert_geosite_dat_to_memory_filtered(&bytes, &codes)
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

pub(super) fn convert_geosite_payload_any_to_buffer(
    payload: &[u8],
    options: AnyConvertOptions,
) -> Result<AnyBufferResult> {
    validate_geosite_input_format(options.input_format.as_deref())?;
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
            let outputs = export_geosite_dat_to_memory(
                payload,
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
            let codes = one_or_many_string(
                options.code.or(options.country),
                options.codes.or(options.countries),
            );
            let output = rule_converter::convert_geosite_dat_to_memory_filtered(payload, &codes)
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
