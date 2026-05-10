use napi::bindgen_prelude::Result;
use rule_converter::{
    BehaviorMode, InputBehaviorMode, InputFormat, MmdbFormat, OutputFormat, RuleTarget,
    default_output_behavior,
};

use crate::error::to_napi_error;
use crate::types::{AnyConvertOptions, AnyTarget};

pub(super) fn can_use_db_ipset_string_fast_path(options: &AnyConvertOptions) -> Result<bool> {
    if options.split.unwrap_or(true) {
        return Ok(false);
    }
    if matches!(
        parse_db_format_value(options.input_format.as_deref())?,
        Some(MmdbFormat::Dat)
    ) {
        return Ok(false);
    }
    let AnyTarget::Rule(output_target) = parse_any_output_target(options.output_target.as_deref())?
    else {
        return Ok(false);
    };
    let output_target = output_target.unwrap_or(RuleTarget::General);
    let output_format =
        parse_rule_output_format(options.output_format.as_deref())?.unwrap_or(OutputFormat::IpSet);
    let output_behavior = parse_output_behavior(options.output_behavior.as_deref())?
        .unwrap_or_else(|| default_output_behavior(output_target, output_format));
    Ok(output_target == RuleTarget::General
        && output_format == OutputFormat::IpSet
        && output_behavior == BehaviorMode::Ipcidr)
}

pub(super) fn one_or_many_string(one: Option<String>, many: Option<Vec<String>>) -> Vec<String> {
    let mut values = many.unwrap_or_default();
    if let Some(one) = one {
        values.push(one);
    }
    values
}

pub(super) fn one_or_many_u32(one: Option<u32>, many: Option<Vec<u32>>) -> Vec<u32> {
    let mut values = many.unwrap_or_default();
    if let Some(one) = one {
        values.push(one);
    }
    values
}

pub(super) fn parse_any_input_target(value: Option<&str>) -> Result<AnyTarget> {
    parse_any_target(value, true)
}

pub(super) fn parse_any_output_target(value: Option<&str>) -> Result<AnyTarget> {
    parse_any_target(value, false)
}

pub(super) fn any_target_from_detect_target(
    value: rule_converter::DetectTarget,
) -> Result<AnyTarget> {
    match value {
        rule_converter::DetectTarget::Rule(target) => Ok(AnyTarget::Rule(target)),
        rule_converter::DetectTarget::Geoip => Ok(AnyTarget::Geoip),
        rule_converter::DetectTarget::Geosite => Ok(AnyTarget::Geosite),
        rule_converter::DetectTarget::Asn => Ok(AnyTarget::Asn),
    }
}

pub(super) fn parse_any_target(
    value: Option<&str>,
    allow_auto_rule_input: bool,
) -> Result<AnyTarget> {
    match value {
        Some("geoip") => Ok(AnyTarget::Geoip),
        Some("geosite") => Ok(AnyTarget::Geosite),
        Some("asn") => Ok(AnyTarget::Asn),
        Some(value) => Ok(AnyTarget::Rule(Some(
            RuleTarget::parse_arg(value).map_err(to_napi_error)?,
        ))),
        None if allow_auto_rule_input => Ok(AnyTarget::Rule(None)),
        None => Ok(AnyTarget::Rule(Some(RuleTarget::Mihomo))),
    }
}

pub(super) fn parse_rule_input_format(value: Option<&str>) -> Result<Option<InputFormat>> {
    value
        .map(InputFormat::parse_arg)
        .transpose()
        .map_err(to_napi_error)
}

pub(super) fn parse_rule_output_format(value: Option<&str>) -> Result<Option<OutputFormat>> {
    value
        .map(OutputFormat::parse_arg)
        .transpose()
        .map_err(to_napi_error)
}

pub(super) fn parse_output_behavior(value: Option<&str>) -> Result<Option<BehaviorMode>> {
    value
        .map(BehaviorMode::parse_arg)
        .transpose()
        .map_err(to_napi_error)
}

pub(super) fn parse_db_format_value(value: Option<&str>) -> Result<Option<MmdbFormat>> {
    value
        .map(MmdbFormat::parse)
        .transpose()
        .map_err(to_napi_error)
}

pub(super) fn validate_asn_output_format(value: Option<&str>) -> Result<()> {
    if let Some(format) = parse_db_format_value(value)?
        && format != MmdbFormat::Mmdb
    {
        return Err(napi::Error::from_reason(
            "ASN target only supports mmdb format",
        ));
    }
    Ok(())
}

pub(super) fn validate_geosite_input_format(value: Option<&str>) -> Result<()> {
    validate_geosite_output_format(value)
}

pub(super) fn validate_geosite_output_format(value: Option<&str>) -> Result<()> {
    if let Some(format) = parse_db_format_value(value)?
        && format != MmdbFormat::Dat
    {
        return Err(napi::Error::from_reason(
            "geosite target only supports dat format",
        ));
    }
    Ok(())
}

pub(super) fn parse_optional_rule_target(value: Option<String>) -> Result<Option<RuleTarget>> {
    value
        .as_deref()
        .map(RuleTarget::parse_arg)
        .transpose()
        .map_err(to_napi_error)
}

pub(super) fn parse_optional_input_format(value: Option<String>) -> Result<Option<InputFormat>> {
    value
        .as_deref()
        .map(InputFormat::parse_arg)
        .transpose()
        .map_err(to_napi_error)
}

pub(super) fn parse_input_behavior(value: Option<String>) -> Result<InputBehaviorMode> {
    value
        .as_deref()
        .map(InputBehaviorMode::parse_arg)
        .transpose()
        .map_err(to_napi_error)
        .map(|value| value.unwrap_or(InputBehaviorMode::Auto))
}
