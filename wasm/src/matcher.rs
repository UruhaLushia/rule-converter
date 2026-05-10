use rule_converter::{
    InputBehaviorMode, MatchInputFormat, MatchInputTarget, MatchOptions as CoreMatchOptions,
    MatchResult as CoreMatchResult,
};
use wasm_bindgen::prelude::*;

use crate::error::to_js_error;
use crate::result::any_to_value;
use crate::types::{MatchOptions, MatchResult, MatchRule};

#[wasm_bindgen(js_name = matchBuf)]
pub fn match_buf_wasm(payload: &[u8], query: &str, options: JsValue) -> Result<JsValue, JsValue> {
    let options = parse_match_options(options)?;
    let result = rule_converter::match_payload(payload, query, options).map_err(to_js_error)?;
    any_to_value(&map_match_result(result))
}

#[wasm_bindgen(js_name = matchStr)]
pub fn match_str_wasm(payload: &str, query: &str, options: JsValue) -> Result<JsValue, JsValue> {
    match_buf_wasm(payload.as_bytes(), query, options)
}

fn parse_match_options(value: JsValue) -> Result<CoreMatchOptions, JsValue> {
    let options: MatchOptions = if value.is_undefined() || value.is_null() {
        MatchOptions::default()
    } else {
        serde_wasm_bindgen::from_value(value).map_err(to_js_error)?
    };
    Ok(CoreMatchOptions {
        input_target: options
            .input_target
            .as_deref()
            .map(MatchInputTarget::parse_arg)
            .transpose()
            .map_err(to_js_error)?,
        input_format: options
            .input_format
            .as_deref()
            .map(MatchInputFormat::parse_arg)
            .transpose()
            .map_err(to_js_error)?,
        input_behavior: options
            .input_behavior
            .as_deref()
            .map(InputBehaviorMode::parse_arg)
            .transpose()
            .map_err(to_js_error)?
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
