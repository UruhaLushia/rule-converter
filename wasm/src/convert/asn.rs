use rule_converter::{
    BehaviorMode, OutputFormat, RuleTarget, convert_asn_mmdb_to_memory_filtered,
    default_output_behavior, export_asn_mmdb_to_ipset_string, export_asn_mmdb_to_memory,
};
use wasm_bindgen::prelude::*;

use super::options::{
    can_use_db_ipset_string_fast_path, one_or_many_u32, parse_any_target, validate_asn_db_format,
};
use crate::error::to_js_error;
use crate::result::{any_db_rules_to_js, any_db_string_to_js, any_db_to_js, any_js_to_string};
use crate::types::{AnyConvertOptions, AnyTarget};

pub(super) fn convert_asn_payload_any_to_js(
    payload: &[u8],
    options: AnyConvertOptions,
) -> Result<JsValue, JsValue> {
    match parse_any_target(options.output_target.as_deref(), false)? {
        AnyTarget::Rule(output_target) => {
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
            .map_err(to_js_error)?;
            any_db_rules_to_js(outputs)
        }
        AnyTarget::Asn => {
            validate_asn_db_format(options.output_format.as_deref())?;
            let asns = one_or_many_u32(options.asn, options.asns);
            let output =
                convert_asn_mmdb_to_memory_filtered(payload, &asns).map_err(to_js_error)?;
            any_db_to_js(output)
        }
        AnyTarget::Geoip => Err(to_js_error("cannot convert asn DB to geoip DB")),
        AnyTarget::Geosite => Err(to_js_error("cannot convert asn DB to geosite DB")),
    }
}

pub(super) fn convert_asn_payload_any_to_string_js(
    payload: &[u8],
    options: AnyConvertOptions,
) -> Result<JsValue, JsValue> {
    if can_use_db_ipset_string_fast_path(&options)? {
        let asns = one_or_many_u32(options.asn, options.asns);
        let output = export_asn_mmdb_to_ipset_string(payload, &asns).map_err(to_js_error)?;
        return any_db_string_to_js(output);
    }
    any_js_to_string(convert_asn_payload_any_to_js(payload, options)?)
}
