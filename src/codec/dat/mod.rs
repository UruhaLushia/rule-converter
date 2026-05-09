mod geoip;
mod geosite;
mod proto;

pub use geoip::{
    GeoipDatRuleSet, build_geoip_dat_from_rule_sets, collect_geoip_dat_rule_set,
    collect_geoip_dat_rule_sets, export_geoip_dat_ipset_to_memory, filter_geoip_dat,
    list_geoip_dat_countries,
};
#[cfg(not(target_arch = "wasm32"))]
pub use geoip::{
    export_geoip_dat_ipset_to_dir, export_geoip_dat_ipset_to_dir_writer, filter_geoip_dat_to_path,
    filter_geoip_dat_to_writer,
};
pub use geosite::{
    GeositeDatRuleSet, build_geosite_dat_from_rule_sets, collect_geosite_dat_rule_set,
    collect_geosite_dat_rule_sets, export_geosite_dat_general_ruleset_to_memory,
    filter_geosite_dat, list_geosite_dat_codes,
};
#[cfg(not(target_arch = "wasm32"))]
pub use geosite::{
    export_geosite_dat_general_ruleset_to_dir, export_geosite_dat_general_ruleset_to_dir_writer,
    export_geosite_dat_general_ruleset_to_path, export_geosite_dat_general_ruleset_to_writer,
    filter_geosite_dat_to_path, filter_geosite_dat_to_writer,
};
