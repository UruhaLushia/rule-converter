mod build;
mod collect;
mod common;
mod convert;
mod export;

use std::path::PathBuf;

use crate::codec::mihomo::mrs::RuleSetOutput;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsnOutputFile {
    pub asn: u32,
    pub count: usize,
    pub path: PathBuf,
}

pub struct AsnRuleSet {
    pub asn: u32,
    pub output: RuleSetOutput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsnCidrSet {
    pub asn: u32,
    pub cidrs: Vec<String>,
}

pub use build::{
    build_asn_mmdb_from_cidrs, build_asn_mmdb_from_paths, build_asn_mmdb_from_rule_sets,
    build_asn_mmdb_from_rule_sets_to_bytes,
};
pub use collect::{
    collect_asn_mmdb_cidrs, collect_asn_mmdb_rule_set, collect_asn_mmdb_rule_set_from_bytes,
    collect_asn_mmdb_rule_sets, collect_asn_mmdb_rule_sets_from_bytes, list_asn_mmdb_asns,
    list_asn_mmdb_asns_from_bytes,
};
pub use convert::{convert_asn_mmdb, convert_asn_mmdb_file_to_bytes, convert_asn_mmdb_to_bytes};
pub use export::{
    export_asn_mmdb_file_ipset_to_bytes, export_asn_mmdb_file_ipset_to_string,
    export_asn_mmdb_ipset_to_bytes, export_asn_mmdb_ipset_to_path, export_asn_mmdb_ipset_to_string,
    export_asn_mmdb_mrs_to_path, export_asn_mmdb_to_dir,
};
