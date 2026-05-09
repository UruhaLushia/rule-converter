use std::io::Write;

use anyhow::Result;

use crate::codec::dat::proto::{DomainType, decode_varint, scan_field};

pub(super) fn write_geosite_entry_ruleset<W: Write>(
    input: &[u8],
    writer: &mut W,
    count: &mut usize,
) -> Result<()> {
    let mut pos = 0usize;
    while pos < input.len() {
        let (tag, wire_type, value_start, value_end) =
            scan_field(input, &mut pos, "V2Ray geosite dat entry")?;
        if (tag, wire_type) != (2, 2) {
            continue;
        }
        let payload_start = length_delimited_payload_start(input, value_start, value_end)?;
        let raw = &input[payload_start..value_end];
        if let Some((kind, value)) = scan_domain_rule(raw)? {
            match kind {
                DomainType::RootDomain => writeln!(writer, "DOMAIN-SUFFIX,{value}")?,
                DomainType::Full => writeln!(writer, "DOMAIN,{value}")?,
                DomainType::Plain => writeln!(writer, "DOMAIN-KEYWORD,{value}")?,
                DomainType::Regex => writeln!(writer, "DOMAIN-REGEX,{value}")?,
            }
            *count += 1;
        }
    }
    Ok(())
}

fn scan_domain_rule(input: &[u8]) -> Result<Option<(DomainType, &str)>> {
    let mut pos = 0usize;
    let mut kind = DomainType::Plain;
    let mut value = None;
    while pos < input.len() {
        let (tag, wire_type, value_start, value_end) =
            scan_field(input, &mut pos, "V2Ray geosite domain")?;
        match (tag, wire_type) {
            (1, 0) => {
                kind = DomainType::try_from(decode_varint(&input[value_start..value_end])? as i32)
                    .unwrap_or(DomainType::Plain);
            }
            (2, 2) => {
                let start = length_delimited_payload_start(input, value_start, value_end)?;
                let text = std::str::from_utf8(&input[start..value_end])?.trim();
                if !text.is_empty() {
                    value = Some(text);
                }
            }
            _ => {}
        }
    }
    Ok(value.map(|value| (kind, value)))
}

fn length_delimited_payload_start(
    input: &[u8],
    value_start: usize,
    value_end: usize,
) -> Result<usize> {
    let len = decode_varint(&input[value_start..value_end])? as usize;
    let mut start = value_start;
    while input.get(start).is_some_and(|byte| byte & 0x80 != 0) {
        start += 1;
    }
    start += 1;
    start
        .checked_add(len)
        .filter(|end| *end == value_end)
        .ok_or_else(|| anyhow::anyhow!("invalid V2Ray geosite length-delimited field"))?;
    Ok(start)
}
