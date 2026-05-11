use napi::bindgen_prelude::Result;
use rule_converter::{
    BehaviorMode, ConvertOptions as CoreConvertOptions, FileInput as CoreFileInput,
    InputBehaviorMode, MmdbFormat, OutputFormat, RuleSetOutput, RuleTarget,
    build_asn_mmdb_to_memory, build_geoip_db_to_memory, build_geosite_db_to_memory,
    convert_file_inputs, convert_payload, default_output_behavior,
    write_outputs_as_to_memory_owned,
};

use super::options::{
    parse_any_output_target, parse_db_format_value, parse_input_behavior,
    parse_optional_input_format, parse_optional_rule_target, parse_output_behavior,
    parse_rule_input_format, parse_rule_output_format, validate_asn_output_format,
    validate_geosite_output_format,
};
use super::result::{any_db_result, any_rules_result};
use crate::error::to_napi_error;
use crate::types::{AnyBufferResult, AnyConvertOptions, AnyTarget};

pub(super) fn convert_rule_payload_any_to_buffer(
    payload: &[u8],
    input_target: Option<RuleTarget>,
    options: AnyConvertOptions,
) -> Result<AnyBufferResult> {
    match parse_any_output_target(options.output_target.as_deref())? {
        AnyTarget::Rule(output_target) => {
            let output_target = output_target.unwrap_or(RuleTarget::Mihomo);
            let output_format = parse_rule_output_format(options.output_format.as_deref())?
                .unwrap_or(OutputFormat::Mrs);
            let output_behavior = parse_output_behavior(options.output_behavior.as_deref())?
                .unwrap_or_else(|| default_output_behavior(output_target, output_format));
            let input_format = parse_rule_input_format(options.input_format.as_deref())?;
            let input_behavior = parse_input_behavior(options.input_behavior)?;
            let result = convert_payload(
                payload,
                CoreConvertOptions {
                    input_target,
                    input_format,
                    input_behavior,
                    output_target,
                    output_format,
                    output_behavior,
                },
            )
            .map_err(to_napi_error)?;
            let (outputs, skipped) =
                write_outputs_as_to_memory_owned(result, output_target, output_format)
                    .map_err(to_napi_error)?;
            Ok(any_rules_result(outputs, skipped))
        }
        AnyTarget::Geoip => {
            let country = options
                .country
                .ok_or_else(|| napi::Error::from_reason("geoip DB output needs country"))?;
            let output_format = parse_db_format_value(options.output_format.as_deref())?
                .unwrap_or(MmdbFormat::Mmdb);
            let rule_set = collect_ip_rule_set_from_payload(
                payload,
                input_target.map(|target| target.as_str().to_string()),
                options.input_format,
                options.input_behavior,
            )?;
            let output = build_geoip_db_to_memory([(country, rule_set)], output_format)
                .map_err(to_napi_error)?;
            Ok(any_db_result(output))
        }
        AnyTarget::Geosite => {
            let code = options
                .code
                .or(options.country)
                .ok_or_else(|| napi::Error::from_reason("geosite DB output needs code"))?;
            validate_geosite_output_format(options.output_format.as_deref())?;
            let output_format =
                parse_db_format_value(options.output_format.as_deref())?.unwrap_or(MmdbFormat::Dat);
            let result = convert_rule_payload_to_classical(
                payload,
                input_target.map(|target| target.as_str().to_string()),
                options.input_format,
                options.input_behavior,
            )?;
            let output = build_geosite_db_to_memory([(code, result)], output_format)
                .map_err(to_napi_error)?;
            Ok(any_db_result(output))
        }
        AnyTarget::Asn => {
            let asn = options
                .asn
                .ok_or_else(|| napi::Error::from_reason("asn DB output needs asn"))?;
            validate_asn_output_format(options.output_format.as_deref())?;
            let rule_set = collect_ip_rule_set_from_payload(
                payload,
                input_target.map(|target| target.as_str().to_string()),
                options.input_format,
                options.input_behavior,
            )?;
            let output = build_asn_mmdb_to_memory([(asn, rule_set)]).map_err(to_napi_error)?;
            Ok(any_db_result(output))
        }
    }
}

pub(super) fn convert_rule_file_any_to_buffer(
    input: String,
    input_target: Option<RuleTarget>,
    options: AnyConvertOptions,
) -> Result<AnyBufferResult> {
    match parse_any_output_target(options.output_target.as_deref())? {
        AnyTarget::Rule(output_target) => {
            let output_target = output_target.unwrap_or(RuleTarget::Mihomo);
            let output_format = parse_rule_output_format(options.output_format.as_deref())?
                .unwrap_or(OutputFormat::Mrs);
            let output_behavior = parse_output_behavior(options.output_behavior.as_deref())?
                .unwrap_or_else(|| default_output_behavior(output_target, output_format));
            let input_format = parse_rule_input_format(options.input_format.as_deref())?;
            let input_behavior = parse_input_behavior(options.input_behavior)?;
            let result = convert_file_inputs(
                [CoreFileInput {
                    path: input.into(),
                    target: input_target,
                    format: input_format,
                    behavior: input_behavior,
                }],
                CoreConvertOptions {
                    input_target,
                    input_format,
                    input_behavior,
                    output_target,
                    output_format,
                    output_behavior,
                },
            )
            .map_err(to_napi_error)?;
            let (outputs, skipped) =
                write_outputs_as_to_memory_owned(result, output_target, output_format)
                    .map_err(to_napi_error)?;
            Ok(any_rules_result(outputs, skipped))
        }
        AnyTarget::Geoip => {
            let country = options
                .country
                .ok_or_else(|| napi::Error::from_reason("geoip DB output needs country"))?;
            let output_format = parse_db_format_value(options.output_format.as_deref())?
                .unwrap_or(MmdbFormat::Mmdb);
            let rule_set = collect_ip_rule_set_from_file(
                input,
                input_target.map(|target| target.as_str().to_string()),
                options.input_format,
                options.input_behavior,
            )?;
            let output = build_geoip_db_to_memory([(country, rule_set)], output_format)
                .map_err(to_napi_error)?;
            Ok(any_db_result(output))
        }
        AnyTarget::Geosite => {
            let code = options
                .code
                .or(options.country)
                .ok_or_else(|| napi::Error::from_reason("geosite DB output needs code"))?;
            validate_geosite_output_format(options.output_format.as_deref())?;
            let output_format =
                parse_db_format_value(options.output_format.as_deref())?.unwrap_or(MmdbFormat::Dat);
            let result = convert_rule_file_to_classical(
                input,
                input_target.map(|target| target.as_str().to_string()),
                options.input_format,
                options.input_behavior,
            )?;
            let output = build_geosite_db_to_memory([(code, result)], output_format)
                .map_err(to_napi_error)?;
            Ok(any_db_result(output))
        }
        AnyTarget::Asn => {
            let asn = options
                .asn
                .ok_or_else(|| napi::Error::from_reason("asn DB output needs asn"))?;
            validate_asn_output_format(options.output_format.as_deref())?;
            let rule_set = collect_ip_rule_set_from_file(
                input,
                input_target.map(|target| target.as_str().to_string()),
                options.input_format,
                options.input_behavior,
            )?;
            let output = build_asn_mmdb_to_memory([(asn, rule_set)]).map_err(to_napi_error)?;
            Ok(any_db_result(output))
        }
    }
}

pub(super) fn convert_rule_file_to_classical(
    path: String,
    input_target: Option<String>,
    input_format: Option<String>,
    input_behavior: Option<String>,
) -> Result<rule_converter::ConvertResult> {
    convert_file_inputs(
        [CoreFileInput {
            path: path.into(),
            target: parse_optional_rule_target(input_target)?,
            format: parse_optional_input_format(input_format)?,
            behavior: parse_input_behavior(input_behavior)?,
        }],
        classical_convert_options(),
    )
    .map_err(to_napi_error)
}

pub(super) fn convert_rule_payload_to_classical(
    payload: &[u8],
    input_target: Option<String>,
    input_format: Option<String>,
    input_behavior: Option<String>,
) -> Result<rule_converter::ConvertResult> {
    let mut options = classical_convert_options();
    options.input_target = parse_optional_rule_target(input_target)?;
    options.input_format = parse_optional_input_format(input_format)?;
    options.input_behavior = parse_input_behavior(input_behavior)?;
    convert_payload(payload, options).map_err(to_napi_error)
}

fn classical_convert_options() -> CoreConvertOptions {
    CoreConvertOptions {
        input_target: None,
        input_format: None,
        input_behavior: InputBehaviorMode::Auto,
        output_target: RuleTarget::General,
        output_format: OutputFormat::RuleSet,
        output_behavior: BehaviorMode::Classical,
    }
}

pub(super) fn collect_ip_rule_set_from_file(
    path: String,
    input_target: Option<String>,
    input_format: Option<String>,
    input_behavior: Option<String>,
) -> Result<RuleSetOutput> {
    let result = convert_file_inputs(
        [CoreFileInput {
            path: path.into(),
            target: parse_optional_rule_target(input_target)?,
            format: parse_optional_input_format(input_format)?,
            behavior: parse_input_behavior(input_behavior)?,
        }],
        ipset_convert_options(),
    )
    .map_err(to_napi_error)?;
    extract_ip_rule_set(result)
}

pub(super) fn collect_ip_rule_set_from_payload(
    payload: &[u8],
    input_target: Option<String>,
    input_format: Option<String>,
    input_behavior: Option<String>,
) -> Result<RuleSetOutput> {
    let mut options = ipset_convert_options();
    options.input_target = parse_optional_rule_target(input_target)?;
    options.input_format = parse_optional_input_format(input_format)?;
    options.input_behavior = parse_input_behavior(input_behavior)?;
    let result = convert_payload(payload, options).map_err(to_napi_error)?;
    extract_ip_rule_set(result)
}

fn ipset_convert_options() -> CoreConvertOptions {
    CoreConvertOptions {
        input_target: None,
        input_format: None,
        input_behavior: InputBehaviorMode::Auto,
        output_target: RuleTarget::General,
        output_format: OutputFormat::IpSet,
        output_behavior: BehaviorMode::Ipcidr,
    }
}

fn extract_ip_rule_set(result: rule_converter::ConvertResult) -> Result<RuleSetOutput> {
    for output in result.outputs {
        if matches!(output, RuleSetOutput::Ipcidr(_)) {
            return Ok(output);
        }
    }
    Err(napi::Error::from_reason(
        "DB build input does not contain any IP CIDR rules",
    ))
}
