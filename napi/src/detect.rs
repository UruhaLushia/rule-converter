use napi::bindgen_prelude::{Result, Uint8Array};
use napi_derive::napi;

use crate::error::to_napi_error;
use crate::types::DetectResult;

#[napi]
pub fn detect_buf(input: Uint8Array) -> Result<DetectResult> {
    rule_converter::detect_payload_type(input.as_ref())
        .map(map_detect_result)
        .map_err(to_napi_error)
}

#[napi]
pub fn detect_str(input: String) -> Result<DetectResult> {
    rule_converter::detect_payload_type(input.as_bytes())
        .map(map_detect_result)
        .map_err(to_napi_error)
}

#[napi]
pub fn detect_file(input: String) -> Result<DetectResult> {
    rule_converter::detect_file_type(input)
        .map(map_detect_result)
        .map_err(to_napi_error)
}

fn map_detect_result(result: rule_converter::DetectResult) -> DetectResult {
    DetectResult {
        kind: result.kind,
        target: result.target,
        format: result.format,
        behavior: result.behavior,
    }
}
