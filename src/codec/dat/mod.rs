mod geoip;
mod geosite;
mod proto;

use prost::Message;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatKind {
    Geoip,
    Geosite,
}

pub fn detect_dat_kind(input: &[u8]) -> Option<DatKind> {
    let entry = proto::first_raw_message_field(input, 1, "V2Ray dat").ok()??;
    if proto::GeoSite::decode(entry)
        .ok()
        .is_some_and(|site| !site.country_code.is_empty() && !site.domain.is_empty())
    {
        return Some(DatKind::Geosite);
    }
    if proto::GeoIp::decode(entry)
        .ok()
        .is_some_and(|geoip| !geoip.country_code.is_empty() && !geoip.cidr.is_empty())
    {
        return Some(DatKind::Geoip);
    }
    None
}

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
