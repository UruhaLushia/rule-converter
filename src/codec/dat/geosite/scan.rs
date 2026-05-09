use anyhow::Result;

use crate::codec::dat::proto::{decode_varint, for_each_raw_message_field, scan_field};

use super::filter::normalize_code;

pub(super) struct GeositeEntryMeta {
    pub(super) code: String,
    pub(super) domain_count: usize,
}

pub(super) fn for_each_raw_geosite_entry(
    input: &[u8],
    f: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    for_each_raw_message_field(input, 1, "V2Ray geosite dat", f)
}

pub(super) fn scan_geosite_entry_meta(input: &[u8]) -> Result<GeositeEntryMeta> {
    let mut pos = 0usize;
    let mut code = String::new();
    let mut domain_count = 0usize;
    while pos < input.len() {
        let (tag, wire_type, value_start, value_end) =
            scan_field(input, &mut pos, "V2Ray geosite dat entry")?;
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
                    .ok_or_else(|| anyhow::anyhow!("invalid V2Ray geosite dat code length"))?;
                code = normalize_code(std::str::from_utf8(&input[len_pos..end])?);
            }
            (2, 2) => domain_count += 1,
            _ => {}
        }
    }
    Ok(GeositeEntryMeta { code, domain_count })
}
