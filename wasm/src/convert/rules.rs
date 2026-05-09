use rule_converter::{
    BehaviorMode, ConvertOptions as CoreConvertOptions, InputBehaviorMode, InputFormat, MmdbFormat,
    OutputFormat, RuleSetOutput, RuleTarget, build_asn_mmdb_to_memory, build_geoip_db_to_memory,
    build_geosite_dat_to_memory, convert_payload, default_output_behavior,
    write_outputs_as_to_memory_owned,
};
use wasm_bindgen::prelude::*;

use super::options::{
    parse_any_target, parse_optional_db_format, validate_asn_db_format, validate_geosite_db_format,
};
use crate::error::to_js_error;
use crate::result::{any_db_to_js, any_rules_to_js};
use crate::types::{AnyConvertOptions, AnyTarget, DbRuleOutput};

pub(super) fn convert_rule_payload_any_to_js(
    payload: &[u8],
    input_target: Option<RuleTarget>,
    options: AnyConvertOptions,
) -> Result<JsValue, JsValue> {
    match parse_any_target(options.output_target.as_deref(), false)? {
        AnyTarget::Rule(output_target) => {
            let output_target = output_target.unwrap_or(RuleTarget::Mihomo);
            let output_format = options
                .output_format
                .as_deref()
                .map(OutputFormat::parse_arg)
                .transpose()
                .map_err(to_js_error)?
                .unwrap_or(OutputFormat::Mrs);
            let output_behavior = options
                .output_behavior
                .as_deref()
                .map(BehaviorMode::parse_arg)
                .transpose()
                .map_err(to_js_error)?
                .unwrap_or_else(|| default_output_behavior(output_target, output_format));
            let result = convert_payload(
                payload,
                CoreConvertOptions {
                    input_target,
                    input_format: options
                        .input_format
                        .as_deref()
                        .map(InputFormat::parse_arg)
                        .transpose()
                        .map_err(to_js_error)?,
                    input_behavior: options
                        .input_behavior
                        .as_deref()
                        .map(InputBehaviorMode::parse_arg)
                        .transpose()
                        .map_err(to_js_error)?
                        .unwrap_or(InputBehaviorMode::Auto),
                    output_target,
                    output_format,
                    output_behavior,
                },
            )
            .map_err(to_js_error)?;
            let (outputs, skipped) =
                write_outputs_as_to_memory_owned(result, output_target, output_format)
                    .map_err(to_js_error)?;
            any_rules_to_js(
                outputs
                    .into_iter()
                    .map(|output| DbRuleOutput {
                        name: output.behavior.as_str().to_string(),
                        behavior: output.behavior.as_str().to_string(),
                        format: output.format.as_str().to_string(),
                        count: output.count,
                        bytes: output.bytes,
                    })
                    .collect(),
                skipped,
            )
        }
        AnyTarget::Geoip => {
            let country = options
                .country
                .ok_or_else(|| to_js_error("geoip DB output needs country"))?;
            let rule_set = collect_ip_rule_set_from_payload(
                payload,
                input_target.map(|target| target.as_str().to_string()),
                options.input_format,
                options.input_behavior,
            )?;
            let output_format = parse_optional_db_format(options.output_format.as_deref())?
                .unwrap_or(MmdbFormat::Mmdb);
            let output = build_geoip_db_to_memory([(country, rule_set)], output_format)
                .map_err(to_js_error)?;
            any_db_to_js(output)
        }
        AnyTarget::Geosite => {
            let code = options
                .code
                .or(options.country)
                .ok_or_else(|| to_js_error("geosite dat output needs code"))?;
            validate_geosite_db_format(options.output_format.as_deref())?;
            let result = convert_rule_payload_to_classical(
                payload,
                input_target.map(|target| target.as_str().to_string()),
                options.input_format,
                options.input_behavior,
            )?;
            let output = build_geosite_dat_to_memory([(code, result)]).map_err(to_js_error)?;
            any_db_to_js(output)
        }
        AnyTarget::Asn => {
            let asn = options
                .asn
                .ok_or_else(|| to_js_error("asn DB output needs asn"))?;
            validate_asn_db_format(options.output_format.as_deref())?;
            let rule_set = collect_ip_rule_set_from_payload(
                payload,
                input_target.map(|target| target.as_str().to_string()),
                options.input_format,
                options.input_behavior,
            )?;
            let output = build_asn_mmdb_to_memory([(asn, rule_set)]).map_err(to_js_error)?;
            any_db_to_js(output)
        }
    }
}
fn convert_rule_payload_to_classical(
    payload: &[u8],
    input_target: Option<String>,
    input_format: Option<String>,
    input_behavior: Option<String>,
) -> Result<rule_converter::ConvertResult, JsValue> {
    let options = CoreConvertOptions {
        input_target: input_target
            .as_deref()
            .map(RuleTarget::parse_arg)
            .transpose()
            .map_err(to_js_error)?,
        input_format: input_format
            .as_deref()
            .map(InputFormat::parse_arg)
            .transpose()
            .map_err(to_js_error)?,
        input_behavior: input_behavior
            .as_deref()
            .map(InputBehaviorMode::parse_arg)
            .transpose()
            .map_err(to_js_error)?
            .unwrap_or(InputBehaviorMode::Auto),
        output_target: RuleTarget::General,
        output_format: OutputFormat::RuleSet,
        output_behavior: BehaviorMode::Classical,
    };
    convert_payload(payload, options).map_err(to_js_error)
}

fn collect_ip_rule_set_from_payload(
    payload: &[u8],
    input_target: Option<String>,
    input_format: Option<String>,
    input_behavior: Option<String>,
) -> Result<RuleSetOutput, JsValue> {
    let options = CoreConvertOptions {
        input_target: input_target
            .as_deref()
            .map(RuleTarget::parse_arg)
            .transpose()
            .map_err(to_js_error)?,
        input_format: input_format
            .as_deref()
            .map(InputFormat::parse_arg)
            .transpose()
            .map_err(to_js_error)?,
        input_behavior: input_behavior
            .as_deref()
            .map(InputBehaviorMode::parse_arg)
            .transpose()
            .map_err(to_js_error)?
            .unwrap_or(InputBehaviorMode::Auto),
        output_target: RuleTarget::General,
        output_format: OutputFormat::IpSet,
        output_behavior: BehaviorMode::Ipcidr,
    };
    let result = convert_payload(payload, options).map_err(to_js_error)?;
    for output in result.outputs {
        if matches!(output, RuleSetOutput::Ipcidr(_)) {
            return Ok(output);
        }
    }
    Err(to_js_error(
        "DB build input does not contain any IP CIDR rules",
    ))
}
