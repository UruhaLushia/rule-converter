use wasm_bindgen::prelude::*;

use crate::error::to_js_error;
use crate::result::any_to_value;
use crate::types::DetectResult;

#[wasm_bindgen(js_name = detectBuf)]
pub fn detect_buf_wasm(input: &[u8]) -> Result<JsValue, JsValue> {
    let result = rule_converter::detect_payload_type(input).map_err(to_js_error)?;
    any_to_value(&map_detect_result(result))
}

#[wasm_bindgen(js_name = detectStr)]
pub fn detect_str_wasm(input: &str) -> Result<JsValue, JsValue> {
    detect_buf_wasm(input.as_bytes())
}

fn map_detect_result(result: rule_converter::DetectResult) -> DetectResult {
    DetectResult {
        kind: result.kind,
        target: result.target,
        format: result.format,
        behavior: result.behavior,
    }
}
