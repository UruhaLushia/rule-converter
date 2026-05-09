use anyhow::Result;

use crate::codec::dat::proto::{decode_varint, for_each_raw_message_field, scan_field};

use super::filter::normalize_country_code;

pub(super) struct GeoipEntryMeta {
    pub(super) country: String,
    pub(super) cidr_count: usize,
    pub(super) reverse_match: bool,
}

pub(super) fn for_each_raw_geoip_entry(
    input: &[u8],
    f: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    for_each_raw_message_field(input, 1, "V2Ray geoip dat", f)
}

pub(super) fn scan_geoip_entry_meta(input: &[u8]) -> Result<GeoipEntryMeta> {
    let mut pos = 0usize;
    let mut country = String::new();
    let mut cidr_count = 0usize;
    let mut reverse_match = false;
    while pos < input.len() {
        let (tag, wire_type, value_start, value_end) =
            scan_field(input, &mut pos, "V2Ray geoip dat entry")?;
        match (tag, wire_type) {
            (1, 2) => {
                let mut len_pos = value_start;
                let len = decode_varint(&input[value_start..value_end])? as usize;
                while input.get(len_pos).is_some_and(|byte| byte & 0x80 != 0) {
                    len_pos += 1;
                }
                len_pos += 1;
                let end = len_pos
                    .checked_add(len)
                    .filter(|end| *end <= value_end)
                    .ok_or_else(|| anyhow::anyhow!("invalid V2Ray geoip dat country length"))?;
                country = normalize_country_code(std::str::from_utf8(&input[len_pos..end])?);
            }
            (2, 2) => cidr_count += 1,
            (3, 0) => reverse_match = decode_varint(&input[value_start..value_end])? != 0,
            _ => {}
        }
    }
    Ok(GeoipEntryMeta {
        country,
        cidr_count,
        reverse_match,
    })
}
