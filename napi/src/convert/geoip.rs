use napi::bindgen_prelude::Result;
use rule_converter::{
    MmdbFormat, OutputFormat, RuleTarget, convert_geoip_db_to_memory_filtered,
    default_output_behavior, export_geoip_db_to_memory, export_geoip_mmdb_file_to_ipset_string,
    export_geoip_mmdb_to_ipset_string,
};

use super::options::{
    can_use_db_ipset_string_fast_path, one_or_many_string, parse_any_output_target,
    parse_db_format_value, parse_output_behavior, parse_rule_output_format,
};
use super::result::{
    any_buffer_result_to_string, any_db_result, any_db_rules_result, any_db_string_result,
};
use crate::error::to_napi_error;
use crate::types::{AnyBufferResult, AnyConvertOptions, AnyStringResult, AnyTarget};

pub(super) fn convert_geoip_file_any_to_buffer(
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
            let input_format =
                parse_db_format_value(options.input_format.as_deref())?.unwrap_or(MmdbFormat::Mmdb);
            let countries = one_or_many_string(options.country, options.countries);
            let split = options.split.unwrap_or(true);
            let bytes =
                std::fs::read(input).map_err(|err| napi::Error::from_reason(err.to_string()))?;
            let outputs = export_geoip_db_to_memory(
                &bytes,
                input_format,
                &countries,
                split,
                output_target,
                output_format,
                output_behavior,
            )
            .map_err(to_napi_error)?;
            Ok(any_db_rules_result(outputs))
        }
        AnyTarget::Geoip => {
            let input_format =
                parse_db_format_value(options.input_format.as_deref())?.unwrap_or(MmdbFormat::Mmdb);
            let output_format = parse_db_format_value(options.output_format.as_deref())?
                .unwrap_or(MmdbFormat::Mmdb);
            let countries = one_or_many_string(options.country, options.countries);
            let bytes =
                std::fs::read(input).map_err(|err| napi::Error::from_reason(err.to_string()))?;
            let output = convert_geoip_db_to_memory_filtered(
                &bytes,
                input_format,
                &countries,
                output_format,
            )
            .map_err(to_napi_error)?;
            Ok(any_db_result(output))
        }
        AnyTarget::Geosite => Err(napi::Error::from_reason(
            "cannot convert geoip DB to geosite DB",
        )),
        AnyTarget::Asn => Err(napi::Error::from_reason(
            "cannot convert geoip DB to asn DB",
        )),
    }
}
pub(super) fn convert_geoip_file_any_to_string(
    input: String,
    options: AnyConvertOptions,
) -> Result<AnyStringResult> {
    if can_use_db_ipset_string_fast_path(&options)? {
        let countries = one_or_many_string(options.country, options.countries);
        let output =
            export_geoip_mmdb_file_to_ipset_string(input, &countries).map_err(to_napi_error)?;
        return Ok(any_db_string_result(output));
    }
    any_buffer_result_to_string(convert_geoip_file_any_to_buffer(input, options)?)
}

pub(super) fn convert_geoip_payload_any_to_buffer(
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
            let input_format =
                parse_db_format_value(options.input_format.as_deref())?.unwrap_or(MmdbFormat::Mmdb);
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
            .map_err(to_napi_error)?;
            Ok(any_db_rules_result(outputs))
        }
        AnyTarget::Geoip => {
            let input_format =
                parse_db_format_value(options.input_format.as_deref())?.unwrap_or(MmdbFormat::Mmdb);
            let output_format = parse_db_format_value(options.output_format.as_deref())?
                .unwrap_or(MmdbFormat::Mmdb);
            let countries = one_or_many_string(options.country, options.countries);
            let output = convert_geoip_db_to_memory_filtered(
                payload,
                input_format,
                &countries,
                output_format,
            )
            .map_err(to_napi_error)?;
            Ok(any_db_result(output))
        }
        AnyTarget::Geosite => Err(napi::Error::from_reason(
            "cannot convert geoip DB to geosite DB",
        )),
        AnyTarget::Asn => Err(napi::Error::from_reason(
            "cannot convert geoip DB to asn DB",
        )),
    }
}
pub(super) fn convert_geoip_payload_any_to_string(
    payload: &[u8],
    options: AnyConvertOptions,
) -> Result<AnyStringResult> {
    if can_use_db_ipset_string_fast_path(&options)? {
        let countries = one_or_many_string(options.country, options.countries);
        let output =
            export_geoip_mmdb_to_ipset_string(payload, &countries).map_err(to_napi_error)?;
        return Ok(any_db_string_result(output));
    }
    any_buffer_result_to_string(convert_geoip_payload_any_to_buffer(payload, options)?)
}
