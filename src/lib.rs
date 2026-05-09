mod api;
pub mod codec;
#[cfg(feature = "config")]
mod config;
mod input;
mod output;
mod rules;
mod target;

pub use api::{
    ConvertOptions, ConvertResult, DbBytesOutput, DbMemoryOutput, DbStringOutput, FileInput,
    SkippedRule, build_asn_mmdb_to_memory, build_geoip_dat_to_memory, build_geoip_db_to_memory,
    build_geoip_mmdb_to_memory, build_geosite_dat_to_memory, convert_asn_mmdb_file_to_memory,
    convert_asn_mmdb_file_to_memory_filtered, convert_asn_mmdb_to_memory,
    convert_asn_mmdb_to_memory_filtered, convert_file, convert_file_inputs,
    convert_file_inputs_to_path_streaming, convert_files, convert_files_to_path_streaming,
    convert_geoip_db_to_memory_filtered, convert_geoip_mmdb_file_to_memory,
    convert_geoip_mmdb_file_to_memory_filtered, convert_geoip_mmdb_to_memory,
    convert_geoip_mmdb_to_memory_filtered, convert_geosite_dat_to_memory_filtered, convert_payload,
    convert_rule_set_output, convert_rules, default_output_behavior,
    export_asn_mmdb_file_to_ipset_string, export_asn_mmdb_file_to_memory,
    export_asn_mmdb_to_ipset_string, export_asn_mmdb_to_memory, export_geoip_dat_to_memory,
    export_geoip_db_to_memory, export_geoip_mmdb_file_to_ipset_string,
    export_geoip_mmdb_file_to_memory, export_geoip_mmdb_to_ipset_string,
    export_geoip_mmdb_to_memory, export_geosite_dat_to_memory, write_outputs, write_outputs_as,
    write_outputs_as_owned, write_outputs_as_to_memory_owned, write_outputs_owned,
    write_outputs_to_memory, write_outputs_to_memory_owned,
};
pub use codec::dat::{
    GeoipDatRuleSet, GeositeDatRuleSet, build_geoip_dat_from_rule_sets,
    build_geosite_dat_from_rule_sets, collect_geoip_dat_rule_set, collect_geoip_dat_rule_sets,
    collect_geosite_dat_rule_set, collect_geosite_dat_rule_sets, export_geoip_dat_ipset_to_memory,
    export_geosite_dat_general_ruleset_to_memory, filter_geoip_dat, filter_geosite_dat,
    list_geoip_dat_countries, list_geosite_dat_codes,
};
#[cfg(not(target_arch = "wasm32"))]
pub use codec::dat::{
    export_geoip_dat_ipset_to_dir, export_geoip_dat_ipset_to_dir_writer,
    export_geosite_dat_general_ruleset_to_dir, export_geosite_dat_general_ruleset_to_dir_writer,
    export_geosite_dat_general_ruleset_to_path, export_geosite_dat_general_ruleset_to_writer,
    filter_geoip_dat_to_path, filter_geoip_dat_to_writer, filter_geosite_dat_to_path,
    filter_geosite_dat_to_writer,
};
pub use codec::db::{
    AsnCidrSet, AsnOutputFile, AsnRuleSet, GeoipCidrSet, GeoipOutputFile, GeoipRuleSet, MmdbFormat,
    build_asn_mmdb_from_cidrs, build_asn_mmdb_from_paths, build_asn_mmdb_from_rule_sets,
    build_asn_mmdb_from_rule_sets_to_bytes, build_geoip_mmdb_from_cidrs,
    build_geoip_mmdb_from_file_names, build_geoip_mmdb_from_paths, build_geoip_mmdb_from_rule_sets,
    build_geoip_mmdb_from_rule_sets_to_bytes, collect_asn_mmdb_cidrs, collect_asn_mmdb_rule_set,
    collect_asn_mmdb_rule_set_from_bytes, collect_asn_mmdb_rule_sets,
    collect_asn_mmdb_rule_sets_from_bytes, collect_geoip_mmdb_cidrs, collect_geoip_mmdb_rule_set,
    collect_geoip_mmdb_rule_set_from_bytes, collect_geoip_mmdb_rule_sets,
    collect_geoip_mmdb_rule_sets_from_bytes, convert_asn_mmdb, convert_asn_mmdb_file_to_bytes,
    convert_asn_mmdb_to_bytes, convert_geoip_mmdb, convert_geoip_mmdb_file_to_bytes,
    convert_geoip_mmdb_file_to_bytes_filtered, convert_geoip_mmdb_filtered,
    convert_geoip_mmdb_to_bytes, convert_geoip_mmdb_to_bytes_filtered,
    export_asn_mmdb_file_ipset_to_bytes, export_asn_mmdb_file_ipset_to_string,
    export_asn_mmdb_ipset_to_bytes, export_asn_mmdb_ipset_to_path, export_asn_mmdb_ipset_to_string,
    export_asn_mmdb_mrs_to_path, export_asn_mmdb_to_dir, export_geoip_mmdb_file_ipset_to_bytes,
    export_geoip_mmdb_file_ipset_to_string, export_geoip_mmdb_ipset_to_bytes,
    export_geoip_mmdb_ipset_to_path, export_geoip_mmdb_ipset_to_string,
    export_geoip_mmdb_mrs_to_path, export_geoip_mmdb_to_dir, list_asn_mmdb_asns,
    list_asn_mmdb_asns_from_bytes, list_geoip_mmdb_countries, list_geoip_mmdb_countries_from_bytes,
};
#[cfg(feature = "config")]
pub use config::{
    ConfigJob, DbConfigJob, DbExportOutput, DbInputPath, DbTarget, RuleConfigJob, load_config,
};
pub use input::{InputFormat, InputSource, load_rules, load_rules_as, parse_input};
pub use output::{
    Behavior, MemoryOutput, OutputFile, OutputFormat, OutputTarget, RuleSetOutput,
    resolve_output_path, write_owned_sing_box_rule_set, write_owned_sing_box_rule_set_to_memory,
    write_rule_sets, write_rule_sets_to_memory,
};
pub use rules::{BehaviorMode, InputBehaviorMode};
pub use target::RuleTarget;

pub type Result<T> = anyhow::Result<T>;
