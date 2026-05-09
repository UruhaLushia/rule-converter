use rule_converter::{
    BehaviorMode, MmdbFormat, OutputFormat, RuleTarget, convert_geoip_db_to_memory_filtered,
    default_output_behavior, export_geoip_db_to_memory, export_geoip_mmdb_to_ipset_string,
};
use wasm_bindgen::prelude::*;

use super::options::{
    can_use_db_ipset_string_fast_path, one_or_many_string, parse_any_target,
    parse_optional_db_format,
};
use crate::error::to_js_error;
use crate::result::{any_db_rules_to_js, any_db_string_to_js, any_db_to_js, any_js_to_string};
use crate::types::{AnyConvertOptions, AnyTarget};

pub(super) fn convert_geoip_payload_any_to_js(
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
            let input_format = parse_optional_db_format(options.input_format.as_deref())?
                .unwrap_or(MmdbFormat::Mmdb);
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
            .map_err(to_js_error)?;
            any_db_rules_to_js(outputs)
        }
        AnyTarget::Geoip => {
            let input_format = parse_optional_db_format(options.input_format.as_deref())?
                .unwrap_or(MmdbFormat::Mmdb);
            let output_format = parse_optional_db_format(options.output_format.as_deref())?
                .unwrap_or(MmdbFormat::Mmdb);
            let countries = one_or_many_string(options.country, options.countries);
            let output = convert_geoip_db_to_memory_filtered(
                payload,
                input_format,
                &countries,
                output_format,
            )
            .map_err(to_js_error)?;
            any_db_to_js(output)
        }
        AnyTarget::Geosite => Err(to_js_error("cannot convert geoip DB to geosite DB")),
        AnyTarget::Asn => Err(to_js_error("cannot convert geoip DB to asn DB")),
    }
}

pub(super) fn convert_geoip_payload_any_to_string_js(
    payload: &[u8],
    options: AnyConvertOptions,
) -> Result<JsValue, JsValue> {
    if can_use_db_ipset_string_fast_path(&options)? {
        let countries = one_or_many_string(options.country, options.countries);
        let output = export_geoip_mmdb_to_ipset_string(payload, &countries).map_err(to_js_error)?;
        return any_db_string_to_js(output);
    }
    any_js_to_string(convert_geoip_payload_any_to_js(payload, options)?)
}
