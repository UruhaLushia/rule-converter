use std::collections::HashMap;

use napi::bindgen_prelude::Buffer;
use napi_derive::napi;
use rule_converter::RuleTarget;

pub(crate) type AnyFormatOption = String;
pub(crate) type AnyTargetOption = String;
pub(crate) type BehaviorOption = String;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AnyTarget {
    Rule(Option<RuleTarget>),
    Geoip,
    Geosite,
    Asn,
}

#[derive(Default)]
#[napi(object)]
pub struct AnyConvertOptions {
    #[napi(ts_type = "'mihomo' | 'general' | 'egern' | 'sing-box' | 'geoip' | 'geosite' | 'asn'")]
    pub input_target: Option<AnyTargetOption>,
    #[napi(
        ts_type = "'yaml' | 'mrs' | 'text' | 'json' | 'srs' | 'domainset' | 'ruleset' | 'ipset' | 'mmdb' | 'sing-db' | 'metadb' | 'dat' | 'sing-geosite'"
    )]
    pub input_format: Option<AnyFormatOption>,
    #[napi(ts_type = "'auto' | 'domain' | 'ip' | 'classical'")]
    pub input_behavior: Option<BehaviorOption>,
    #[napi(ts_type = "'mihomo' | 'general' | 'egern' | 'sing-box' | 'geoip' | 'geosite' | 'asn'")]
    pub output_target: Option<AnyTargetOption>,
    #[napi(
        ts_type = "'mrs' | 'text' | 'yaml' | 'json' | 'srs' | 'domainset' | 'ruleset' | 'ipset' | 'mmdb' | 'sing-db' | 'metadb' | 'dat' | 'sing-geosite'"
    )]
    pub output_format: Option<AnyFormatOption>,
    #[napi(ts_type = "'auto' | 'domain' | 'ip' | 'classical'")]
    pub output_behavior: Option<BehaviorOption>,
    pub countries: Option<Vec<String>>,
    pub codes: Option<Vec<String>>,
    pub asns: Option<Vec<u32>>,
    pub split: Option<bool>,
    pub country: Option<String>,
    pub code: Option<String>,
    pub asn: Option<u32>,
}

#[napi(object)]
pub struct AnyOutputInfo {
    pub behavior: Option<String>,
    pub format: String,
    pub count: u32,
}

#[napi(object)]
pub struct SkippedRule {
    pub rule: String,
    pub reason: String,
}

#[napi(object)]
pub struct AnyBufferResult {
    #[napi(ts_type = "'rules' | 'db'")]
    pub kind: String,
    #[napi(ts_type = "Record<string, Uint8Array>")]
    pub outputs: HashMap<String, Buffer>,
    pub info: HashMap<String, AnyOutputInfo>,
    pub skipped: Vec<SkippedRule>,
}

#[napi(object)]
pub struct AnyStringResult {
    #[napi(ts_type = "'rules' | 'db'")]
    pub kind: String,
    pub outputs: HashMap<String, String>,
    pub info: HashMap<String, AnyOutputInfo>,
    pub skipped: Vec<SkippedRule>,
}

#[napi(object)]
pub struct DetectResult {
    #[napi(ts_type = "'rules' | 'db'")]
    pub kind: String,
    #[napi(ts_type = "'mihomo' | 'general' | 'egern' | 'sing-box' | 'geoip' | 'geosite' | 'asn'")]
    pub target: String,
    pub format: String,
    pub behavior: Option<String>,
}
