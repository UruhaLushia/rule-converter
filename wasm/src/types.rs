use std::collections::BTreeMap;

use rule_converter::RuleTarget;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AnyConvertOptions {
    pub input_target: Option<String>,
    pub input_format: Option<String>,
    pub input_behavior: Option<String>,
    pub output_target: Option<String>,
    pub output_format: Option<String>,
    pub output_behavior: Option<String>,
    pub countries: Option<Vec<String>>,
    pub codes: Option<Vec<String>>,
    pub asns: Option<Vec<u32>>,
    pub split: Option<bool>,
    pub country: Option<String>,
    pub code: Option<String>,
    pub asn: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MatchOptions {
    pub input_target: Option<String>,
    pub input_format: Option<String>,
    pub input_behavior: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MatchRule {
    pub behavior: String,
    pub rule: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MatchResult {
    pub matched: bool,
    pub query: String,
    pub kind: String,
    pub rules: Vec<MatchRule>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AnyTarget {
    Rule(Option<RuleTarget>),
    Geoip,
    Geosite,
    Asn,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SkippedRule {
    pub rule: String,
    pub reason: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DbRuleOutput {
    pub name: String,
    pub behavior: String,
    pub format: String,
    pub count: usize,
    pub bytes: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AnyOutputInfo {
    pub behavior: Option<String>,
    pub format: String,
    pub count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AnyStringResult {
    pub kind: String,
    pub outputs: BTreeMap<String, String>,
    pub info: BTreeMap<String, AnyOutputInfo>,
    pub skipped: Vec<SkippedRule>,
}
