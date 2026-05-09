mod list;
mod rule_item;
mod rule_set;
mod store;
mod string_list;

use serde::{Deserialize, Serialize};

pub const VERSION_CURRENT: u8 = 5;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RuleSet {
    #[serde(default = "default_version")]
    pub version: u8,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Clone, Debug, Default)]
pub struct RuleStore {
    pub(crate) domain: RuleList,
    pub(crate) domain_suffix: RuleList,
    pub(crate) domain_keyword: RuleList,
    pub(crate) domain_regex: RuleList,
    pub(crate) source_ip_cidr: RuleList,
    pub(crate) ip_cidr: RuleList,
    pub(crate) network: RuleList,
    pub(crate) source_port_range: RuleList,
    pub(crate) port_range: RuleList,
    pub(crate) process_name: RuleList,
    pub(crate) process_path: RuleList,
    pub(crate) process_path_regex: RuleList,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RuleList {
    bytes: Vec<u8>,
    items: Vec<RuleTextRef>,
}

#[derive(Clone, Copy, Debug)]
struct RuleTextRef {
    offset: u32,
    len: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Rule {
    #[serde(rename = "type", default, skip_serializing_if = "String::is_empty")]
    pub rule_type: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub domain: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub domain_suffix: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub domain_keyword: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub domain_regex: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub source_ip_cidr: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub ip_cidr: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub network: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub source_port_range: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub port_range: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub process_name: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub process_path: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub process_path_regex: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub package_name: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub package_name_regex: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub invert: bool,
}

fn default_version() -> u8 {
    VERSION_CURRENT
}

fn is_false(value: &bool) -> bool {
    !*value
}
