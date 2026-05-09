use std::io::Write;
use std::net::IpAddr;

use anyhow::Result;

use crate::codec::dat::proto::{decode_varint, scan_field};

use super::address::addr_from_raw;

pub(super) fn write_geoip_entry_ipset<W: Write>(
    input: &[u8],
    writer: &mut W,
    count: &mut usize,
) -> Result<()> {
    let mut pos = 0usize;
    while pos < input.len() {
        let (tag, wire_type, value_start, value_end) =
            scan_field(input, &mut pos, "V2Ray geoip dat entry")?;
        if (tag, wire_type) != (2, 2) {
            continue;
        }
        let payload_start = length_delimited_payload_start(input, value_start, value_end)?;
        if let Some((addr, prefix)) = scan_cidr_rule(&input[payload_start..value_end])? {
            writeln!(writer, "{addr}/{prefix}")?;
            *count += 1;
        }
    }
    Ok(())
}

fn scan_cidr_rule(input: &[u8]) -> Result<Option<(IpAddr, u8)>> {
    let mut pos = 0usize;
    let mut addr = None;
    let mut prefix = None;
    while pos < input.len() {
        let (tag, wire_type, value_start, value_end) =
            scan_field(input, &mut pos, "V2Ray geoip CIDR")?;
        match (tag, wire_type) {
            (1, 2) => {
                let start = length_delimited_payload_start(input, value_start, value_end)?;
                addr = Some(addr_from_raw(&input[start..value_end])?);
            }
            (2, 0) => {
                prefix = Some(u8::try_from(decode_varint(
                    &input[value_start..value_end],
                )?)?);
            }
            _ => {}
        }
    }
    Ok(match (addr, prefix) {
        (Some(addr), Some(prefix)) => Some((addr, prefix)),
        _ => None,
    })
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
        .ok_or_else(|| anyhow::anyhow!("invalid V2Ray geoip length-delimited field"))?;
    Ok(start)
}
