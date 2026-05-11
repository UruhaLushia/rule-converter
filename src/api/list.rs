use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InputIndexSection {
    pub title: String,
    pub items: Vec<String>,
}

pub fn list_input_indexes(path: impl AsRef<Path>) -> Result<Vec<InputIndexSection>> {
    let path = path.as_ref();
    let payload =
        std::fs::read(path).with_context(|| format!("failed to read input {}", path.display()))?;
    list_input_indexes_from_bytes(&payload)
}

pub fn list_input_indexes_from_bytes(payload: impl AsRef<[u8]>) -> Result<Vec<InputIndexSection>> {
    let payload = payload.as_ref();
    let detected = crate::detect_payload_type(payload)?;
    match (detected.target.as_str(), detected.format.as_str()) {
        ("geosite", _) => Ok(section(
            "Geosite Codes",
            crate::codec::dat::list_geosite_dat_codes(payload)
                .or_else(|_| crate::codec::db::list_sing_geosite_codes(payload))?,
        )),
        ("geoip", "dat") => Ok(section(
            "GeoIP DAT Countries",
            crate::codec::dat::list_geoip_dat_countries(payload)?,
        )),
        ("geoip", _) => Ok(section(
            "GeoIP Countries",
            crate::codec::db::list_geoip_mmdb_countries_from_bytes(payload)?,
        )),
        ("asn", _) => Ok(section(
            "ASN Numbers",
            crate::codec::db::list_asn_mmdb_asns_from_bytes(payload)?
                .into_iter()
                .map(|asn| format!("AS{asn}"))
                .collect(),
        )),
        _ => Ok(Vec::new()),
    }
}

fn section(title: &str, items: Vec<String>) -> Vec<InputIndexSection> {
    if items.is_empty() {
        Vec::new()
    } else {
        vec![InputIndexSection {
            title: title.to_string(),
            items,
        }]
    }
}
