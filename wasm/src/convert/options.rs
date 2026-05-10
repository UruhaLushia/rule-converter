use rule_converter::{BehaviorMode, MmdbFormat, OutputFormat, RuleTarget, default_output_behavior};
use wasm_bindgen::prelude::*;

use crate::error::to_js_error;
use crate::types::{AnyConvertOptions, AnyTarget};

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

pub(super) fn parse_any_target(
    value: Option<&str>,
    allow_auto_rule_input: bool,
) -> Result<AnyTarget, JsValue> {
    match value {
        Some("geoip") => Ok(AnyTarget::Geoip),
        Some("geosite") => Ok(AnyTarget::Geosite),
        Some("asn") => Ok(AnyTarget::Asn),
        Some(value) => Ok(AnyTarget::Rule(Some(
            RuleTarget::parse_arg(value).map_err(to_js_error)?,
        ))),
        None if allow_auto_rule_input => Ok(AnyTarget::Rule(None)),
        None => Ok(AnyTarget::Rule(Some(RuleTarget::Mihomo))),
    }
}

pub(super) fn any_target_from_detect_target(
    value: rule_converter::DetectTarget,
) -> Result<AnyTarget, JsValue> {
    match value {
        rule_converter::DetectTarget::Rule(target) => Ok(AnyTarget::Rule(target)),
        rule_converter::DetectTarget::Geoip => Ok(AnyTarget::Geoip),
        rule_converter::DetectTarget::Geosite => Ok(AnyTarget::Geosite),
        rule_converter::DetectTarget::Asn => Ok(AnyTarget::Asn),
    }
}

pub(super) fn parse_optional_db_format(value: Option<&str>) -> Result<Option<MmdbFormat>, JsValue> {
    value
        .map(MmdbFormat::parse)
        .transpose()
        .map_err(to_js_error)
}

pub(super) fn validate_asn_db_format(value: Option<&str>) -> Result<(), JsValue> {
    if let Some(format) = parse_optional_db_format(value)?
        && format != MmdbFormat::Mmdb
    {
        return Err(to_js_error("ASN target only supports mmdb format"));
    }
    Ok(())
}

pub(super) fn validate_geosite_db_format(value: Option<&str>) -> Result<(), JsValue> {
    if let Some(format) = parse_optional_db_format(value)?
        && format != MmdbFormat::Dat
    {
        return Err(to_js_error("geosite target only supports dat format"));
    }
    Ok(())
}
pub(super) fn can_use_db_ipset_string_fast_path(
    options: &AnyConvertOptions,
) -> Result<bool, JsValue> {
    if options.split.unwrap_or(true) {
        return Ok(false);
    }
    if matches!(
        parse_optional_db_format(options.input_format.as_deref())?,
        Some(MmdbFormat::Dat)
    ) {
        return Ok(false);
    }
    let AnyTarget::Rule(output_target) = parse_any_target(options.output_target.as_deref(), false)?
    else {
        return Ok(false);
    };
    let output_target = output_target.unwrap_or(RuleTarget::General);
    let output_format = options
        .output_format
        .as_deref()
        .map(OutputFormat::parse_arg)
        .transpose()
        .map_err(to_js_error)?
        .unwrap_or(OutputFormat::IpSet);
    let output_behavior = options
        .output_behavior
        .as_deref()
        .map(BehaviorMode::parse_arg)
        .transpose()
        .map_err(to_js_error)?
        .unwrap_or_else(|| default_output_behavior(output_target, output_format));
    Ok(output_target == RuleTarget::General
        && output_format == OutputFormat::IpSet
        && output_behavior == BehaviorMode::Ipcidr)
}
