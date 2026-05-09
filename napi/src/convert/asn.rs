use napi::bindgen_prelude::Result;
use rule_converter::{
    OutputFormat, RuleTarget, convert_asn_mmdb_file_to_memory_filtered,
    convert_asn_mmdb_to_memory_filtered, default_output_behavior,
    export_asn_mmdb_file_to_ipset_string, export_asn_mmdb_file_to_memory,
    export_asn_mmdb_to_ipset_string, export_asn_mmdb_to_memory,
};

use super::options::{
    can_use_db_ipset_string_fast_path, one_or_many_u32, parse_any_output_target,
    parse_output_behavior, parse_rule_output_format, validate_asn_output_format,
};
use super::result::{
    any_buffer_result_to_string, any_db_result, any_db_rules_result, any_db_string_result,
};
use crate::error::to_napi_error;
use crate::types::{AnyBufferResult, AnyConvertOptions, AnyStringResult, AnyTarget};

pub(super) fn convert_asn_file_any_to_buffer(
    input: String,
    options: AnyConvertOptions,
) -> Result<AnyBufferResult> {
    match parse_any_output_target(options.output_target.as_deref())? {
        AnyTarget::Rule(output_target) => {
            let output_target = output_target.unwrap_or(RuleTarget::General);
            let output_format = parse_rule_output_format(options.output_format.as_deref())?
                .unwrap_or(OutputFormat::IpSet);
            let output_behavior = parse_output_behavior(options.output_behavior.as_deref())?
                .unwrap_or_else(|| default_output_behavior(output_target, output_format));
            let asns = one_or_many_u32(options.asn, options.asns);
            let split = options.split.unwrap_or(true);
            let outputs = export_asn_mmdb_file_to_memory(
                input,
                &asns,
                split,
                output_target,
                output_format,
                output_behavior,
            )
            .map_err(to_napi_error)?;
            Ok(any_db_rules_result(outputs))
        }
        AnyTarget::Asn => {
            validate_asn_output_format(options.output_format.as_deref())?;
            let asns = one_or_many_u32(options.asn, options.asns);
            let output =
                convert_asn_mmdb_file_to_memory_filtered(input, &asns).map_err(to_napi_error)?;
            Ok(any_db_result(output))
        }
        AnyTarget::Geoip => Err(napi::Error::from_reason(
            "cannot convert asn DB to geoip DB",
        )),
        AnyTarget::Geosite => Err(napi::Error::from_reason(
            "cannot convert asn DB to geosite DB",
        )),
    }
}
pub(super) fn convert_asn_file_any_to_string(
    input: String,
    options: AnyConvertOptions,
) -> Result<AnyStringResult> {
    if can_use_db_ipset_string_fast_path(&options)? {
        let asns = one_or_many_u32(options.asn, options.asns);
        let output = export_asn_mmdb_file_to_ipset_string(input, &asns).map_err(to_napi_error)?;
        return Ok(any_db_string_result(output));
    }
    any_buffer_result_to_string(convert_asn_file_any_to_buffer(input, options)?)
}
pub(super) fn convert_asn_payload_any_to_buffer(
    payload: &[u8],
    options: AnyConvertOptions,
) -> Result<AnyBufferResult> {
    match parse_any_output_target(options.output_target.as_deref())? {
        AnyTarget::Rule(output_target) => {
            let output_target = output_target.unwrap_or(RuleTarget::General);
            let output_format = parse_rule_output_format(options.output_format.as_deref())?
                .unwrap_or(OutputFormat::IpSet);
            let output_behavior = parse_output_behavior(options.output_behavior.as_deref())?
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
            .map_err(to_napi_error)?;
            Ok(any_db_rules_result(outputs))
        }
        AnyTarget::Asn => {
            validate_asn_output_format(options.output_format.as_deref())?;
            let asns = one_or_many_u32(options.asn, options.asns);
            let output =
                convert_asn_mmdb_to_memory_filtered(payload, &asns).map_err(to_napi_error)?;
            Ok(any_db_result(output))
        }
        AnyTarget::Geoip => Err(napi::Error::from_reason(
            "cannot convert asn DB to geoip DB",
        )),
        AnyTarget::Geosite => Err(napi::Error::from_reason(
            "cannot convert asn DB to geosite DB",
        )),
    }
}
pub(super) fn convert_asn_payload_any_to_string(
    payload: &[u8],
    options: AnyConvertOptions,
) -> Result<AnyStringResult> {
    if can_use_db_ipset_string_fast_path(&options)? {
        let asns = one_or_many_u32(options.asn, options.asns);
        let output = export_asn_mmdb_to_ipset_string(payload, &asns).map_err(to_napi_error)?;
        return Ok(any_db_string_result(output));
    }
    any_buffer_result_to_string(convert_asn_payload_any_to_buffer(payload, options)?)
}
