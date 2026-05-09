mod build;
mod collect;
mod common;
mod convert;
mod export;

use std::path::PathBuf;

use crate::codec::mihomo::mrs::RuleSetOutput;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeoipOutputFile {
    pub country: String,
    pub count: usize,
    pub path: PathBuf,
}

pub struct GeoipRuleSet {
    pub country: String,
    pub output: RuleSetOutput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeoipCidrSet {
    pub country: String,
    pub cidrs: Vec<String>,
}

pub use build::{
    build_geoip_mmdb_from_cidrs, build_geoip_mmdb_from_file_names, build_geoip_mmdb_from_paths,
    build_geoip_mmdb_from_rule_sets, build_geoip_mmdb_from_rule_sets_to_bytes,
};
pub use collect::{
    collect_geoip_mmdb_cidrs, collect_geoip_mmdb_rule_set, collect_geoip_mmdb_rule_set_from_bytes,
    collect_geoip_mmdb_rule_sets, collect_geoip_mmdb_rule_sets_from_bytes,
    list_geoip_mmdb_countries, list_geoip_mmdb_countries_from_bytes,
};
pub use convert::{
    convert_geoip_mmdb, convert_geoip_mmdb_file_to_bytes,
    convert_geoip_mmdb_file_to_bytes_filtered, convert_geoip_mmdb_filtered,
    convert_geoip_mmdb_to_bytes, convert_geoip_mmdb_to_bytes_filtered,
};
pub use export::{
    export_geoip_mmdb_file_ipset_to_bytes, export_geoip_mmdb_file_ipset_to_string,
    export_geoip_mmdb_ipset_to_bytes, export_geoip_mmdb_ipset_to_path,
    export_geoip_mmdb_ipset_to_string, export_geoip_mmdb_mrs_to_path, export_geoip_mmdb_to_dir,
};
