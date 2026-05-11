use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};

use super::{SingGeositeItem, SingGeositeRuleType};

#[derive(Clone, Debug)]
pub(super) struct MetadataItem {
    pub(super) code: String,
    pub(super) index: usize,
    pub(super) len: usize,
}

pub(super) fn read_metadata(input: &[u8]) -> Result<Vec<MetadataItem>> {
    let mut pos = 0usize;
    let version = read_byte(input, &mut pos)?;
    if version != 0 {
        bail!("unknown sing-geosite version: {version}");
    }
    let len = read_uvarint(input, &mut pos)? as usize;
    let mut metadata = Vec::with_capacity(len);
    for _ in 0..len {
        let code = read_string(input, &mut pos)?.to_ascii_lowercase();
        let index = read_uvarint(input, &mut pos)? as usize;
        let len = read_uvarint(input, &mut pos)? as usize;
        metadata.push(MetadataItem { code, index, len });
    }
    let base = pos;
    for item in &mut metadata {
        item.index = base
            .checked_add(item.index)
            .filter(|index| *index <= input.len())
            .context("invalid sing-geosite entry offset")?;
    }
    Ok(metadata)
}

pub(super) fn read_items(input: &[u8], index: usize, len: usize) -> Result<Vec<SingGeositeItem>> {
    let mut pos = index;
    let mut items = Vec::with_capacity(len);
    for _ in 0..len {
        let kind = match read_byte(input, &mut pos)? {
            0 => SingGeositeRuleType::Domain,
            1 => SingGeositeRuleType::DomainSuffix,
            2 => SingGeositeRuleType::DomainKeyword,
            3 => SingGeositeRuleType::DomainRegex,
            other => bail!("unsupported sing-geosite rule type: {other}"),
        };
        let value = read_string(input, &mut pos)?;
        items.push(SingGeositeItem { kind, value });
    }
    Ok(items)
}

pub(super) fn write_sing_geosite(
    map: BTreeMap<String, Vec<SingGeositeItem>>,
    count: usize,
) -> Result<(usize, Vec<u8>)> {
    let mut content = Vec::new();
    let mut metadata = Vec::with_capacity(map.len());
    for (code, items) in map {
        let index = content.len();
        for item in &items {
            content.push(item.kind.clone() as u8);
            write_string(&mut content, &item.value)?;
        }
        metadata.push((code, index, items.len()));
    }

    let mut output = Vec::new();
    output.push(0);
    write_uvarint(&mut output, metadata.len() as u64)?;
    for (code, index, len) in metadata {
        write_string(&mut output, &code)?;
        write_uvarint(&mut output, index as u64)?;
        write_uvarint(&mut output, len as u64)?;
    }
    output.extend_from_slice(&content);
    Ok((count, output))
}

fn read_byte(input: &[u8], pos: &mut usize) -> Result<u8> {
    let byte = *input.get(*pos).context("truncated sing-geosite input")?;
    *pos += 1;
    Ok(byte)
}

fn read_string(input: &[u8], pos: &mut usize) -> Result<String> {
    let len = read_uvarint(input, pos)? as usize;
    let end = pos
        .checked_add(len)
        .filter(|end| *end <= input.len())
        .context("invalid sing-geosite string length")?;
    let value = std::str::from_utf8(&input[*pos..end])?.to_string();
    *pos = end;
    Ok(value)
}

fn read_uvarint(input: &[u8], pos: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = read_byte(input, pos)?;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("sing-geosite uvarint overflow")
}

fn write_string(output: &mut Vec<u8>, value: &str) -> Result<()> {
    write_uvarint(output, value.len() as u64)?;
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn write_uvarint(output: &mut Vec<u8>, mut value: u64) -> Result<()> {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
    Ok(())
}
