use napi::bindgen_prelude::{Result, Uint8Array};
use napi_derive::napi;
use rule_converter::{
    InputBehaviorMode, MatchInputFormat, MatchInputTarget, MatchOptions as CoreMatchOptions,
    MatchResult as CoreMatchResult,
};

use crate::error::to_napi_error;
use crate::types::{AnyFormatOption, AnyTargetOption, BehaviorOption};

#[allow(dead_code)]
#[napi(object)]
pub struct MatchOptions {
    #[napi(ts_type = "'mihomo' | 'general' | 'egern' | 'sing-box' | 'geoip' | 'geosite' | 'asn'")]
    pub input_target: Option<AnyTargetOption>,
    #[napi(
        ts_type = "'yaml' | 'mrs' | 'text' | 'json' | 'srs' | 'domainset' | 'ruleset' | 'ipset' | 'dat' | 'mmdb' | 'sing-db' | 'metadb'"
    )]
    pub input_format: Option<AnyFormatOption>,
    #[napi(ts_type = "'auto' | 'domain' | 'ip' | 'classical'")]
    pub input_behavior: Option<BehaviorOption>,
}

#[allow(dead_code)]
#[napi(object)]
pub struct MatchRule {
    pub behavior: String,
    pub rule: String,
    pub source: Option<String>,
    pub entry: Option<String>,
    pub set: Option<String>,
}

#[allow(dead_code)]
#[napi(object)]
pub struct MatchResult {
    pub matched: bool,
    pub query: String,
    pub kind: String,
    pub rules: Vec<MatchRule>,
}

#[napi]
pub fn match_buf(
    input: Uint8Array,
    query: String,
    options: Option<MatchOptions>,
) -> Result<MatchResult> {
    rule_converter::match_payload(input.as_ref(), &query, core_match_options(options)?)
        .map(map_match_result)
        .map_err(to_napi_error)
}

#[napi]
pub fn match_str(
    input: String,
    query: String,
    options: Option<MatchOptions>,
) -> Result<MatchResult> {
    rule_converter::match_payload(input.as_bytes(), &query, core_match_options(options)?)
        .map(map_match_result)
        .map_err(to_napi_error)
}

#[napi]
pub fn match_file(
    input: String,
    query: String,
    options: Option<MatchOptions>,
) -> Result<MatchResult> {
    rule_converter::match_file(input, &query, core_match_options(options)?)
        .map(map_match_result)
        .map_err(to_napi_error)
}

fn core_match_options(options: Option<MatchOptions>) -> Result<CoreMatchOptions> {
    let options = options.unwrap_or(MatchOptions {
        input_target: None,
        input_format: None,
        input_behavior: None,
    });
    Ok(CoreMatchOptions {
        input_target: options
            .input_target
            .as_deref()
            .map(MatchInputTarget::parse_arg)
            .transpose()
            .map_err(to_napi_error)?,
        input_format: options
            .input_format
            .as_deref()
            .map(MatchInputFormat::parse_arg)
            .transpose()
            .map_err(to_napi_error)?,
        input_behavior: options
            .input_behavior
            .as_deref()
            .map(InputBehaviorMode::parse_arg)
            .transpose()
            .map_err(to_napi_error)?
            .unwrap_or(InputBehaviorMode::Auto),
    })
}

fn map_match_result(result: CoreMatchResult) -> MatchResult {
    MatchResult {
        matched: result.matched,
        query: result.query,
        kind: result.kind.as_str().to_string(),
        rules: result
            .rules
            .into_iter()
            .map(|rule| MatchRule {
                behavior: rule.behavior.as_str().to_string(),
                rule: rule.rule,
                source: rule.source,
                entry: rule.entry,
                set: rule.set,
            })
            .collect(),
    }
}
