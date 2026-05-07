use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, anyhow, bail};

use crate::codec::sing_box::rule::RuleList;
use crate::rules::{ClassicalKind, ClassicalRule, RuleTextStore};

use super::binary::{read_byte, read_uvarint, write_uvarint};

pub(super) fn write_ip_set_item<W, S>(writer: &mut W, item: u8, cidrs: &[S]) -> Result<()>
where
    W: Write,
    S: AsRef<str>,
{
    writer.write_all(&[item])?;
    let mut ranges = Vec::with_capacity(cidrs.len());
    for cidr in cidrs {
        ranges.push(parse_ip_range(cidr.as_ref())?);
    }
    ranges.sort_by_key(|range| (range.family, range.from));

    writer.write_all(&[1])?;
    writer.write_all(&(ranges.len() as u64).to_be_bytes())?;
    for range in ranges {
        write_addr_bytes(writer, range.family, range.from)?;
        write_addr_bytes(writer, range.family, range.to)?;
    }
    Ok(())
}

pub(super) fn write_ip_set_item_list<W: Write>(
    writer: &mut W,
    item: u8,
    cidrs: &RuleList,
) -> Result<()> {
    writer.write_all(&[item])?;
    let mut ranges = Vec::with_capacity(cidrs.len());
    for cidr in cidrs.iter() {
        ranges.push(parse_ip_range(cidr)?);
    }
    ranges.sort_by_key(|range| (range.family, range.from));

    writer.write_all(&[1])?;
    writer.write_all(&(ranges.len() as u64).to_be_bytes())?;
    for range in ranges {
        write_addr_bytes(writer, range.family, range.from)?;
        write_addr_bytes(writer, range.family, range.to)?;
    }
    Ok(())
}

pub(super) fn write_ip_set_item_from_rules<W, F>(
    writer: &mut W,
    item: u8,
    rules: &RuleTextStore,
    count: usize,
    matches_kind: F,
) -> Result<()>
where
    W: Write,
    F: Fn(ClassicalKind) -> bool,
{
    writer.write_all(&[item])?;
    let mut ranges = Vec::with_capacity(count);
    for rule in rules.iter() {
        let Ok(parsed) = ClassicalRule::parse(rule) else {
            continue;
        };
        if !matches_kind(parsed.kind) {
            continue;
        }
        ranges.push(parse_ip_range(parsed.payload.unwrap_or_default())?);
    }
    ranges.sort_by_key(|range| (range.family, range.from));

    writer.write_all(&[1])?;
    writer.write_all(&(ranges.len() as u64).to_be_bytes())?;
    for range in ranges {
        write_addr_bytes(writer, range.family, range.from)?;
        write_addr_bytes(writer, range.family, range.to)?;
    }
    Ok(())
}

pub(super) fn read_ip_set<R: Read>(reader: &mut R) -> Result<Vec<String>> {
    let version = read_byte(reader)?;
    if version != 1 {
        bail!("invalid sing-box SRS IP set version");
    }
    let mut len = [0; 8];
    reader.read_exact(&mut len)?;
    let len = u64::from_be_bytes(len);
    let mut rules = Vec::new();
    for _ in 0..len {
        let from = read_addr_bytes(reader)?;
        let to = read_addr_bytes(reader)?;
        if from.family != to.family {
            bail!("mixed address families in sing-box SRS IP range");
        }
        for (addr, prefix_len) in range_to_prefixes(from.value, to.value, from.family.bits()) {
            rules.push(format_addr_prefix(from.family, addr, prefix_len));
        }
    }
    Ok(rules)
}

fn write_addr_bytes<W: Write>(writer: &mut W, family: IpFamily, value: u128) -> Result<()> {
    match family {
        IpFamily::V4 => {
            write_uvarint(writer, 4)?;
            writer.write_all(&(value as u32).to_be_bytes())?;
        }
        IpFamily::V6 => {
            write_uvarint(writer, 16)?;
            writer.write_all(&value.to_be_bytes())?;
        }
    }
    Ok(())
}

fn read_addr_bytes<R: Read>(reader: &mut R) -> Result<ParsedIp> {
    let len = read_uvarint(reader)?;
    match len {
        4 => {
            let mut bytes = [0; 4];
            reader.read_exact(&mut bytes)?;
            Ok(ParsedIp {
                family: IpFamily::V4,
                value: u32::from_be_bytes(bytes) as u128,
            })
        }
        16 => {
            let mut bytes = [0; 16];
            reader.read_exact(&mut bytes)?;
            Ok(ParsedIp {
                family: IpFamily::V6,
                value: u128::from_be_bytes(bytes),
            })
        }
        other => bail!("invalid IP byte length in sing-box SRS: {other}"),
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    fn bits(self) -> u8 {
        match self {
            Self::V4 => 32,
            Self::V6 => 128,
        }
    }
}

#[derive(Clone, Copy)]
struct ParsedIp {
    family: IpFamily,
    value: u128,
}

#[derive(Clone, Copy)]
struct IpRange {
    family: IpFamily,
    from: u128,
    to: u128,
}

fn parse_ip_range(cidr: &str) -> Result<IpRange> {
    let (addr, prefix_len) = cidr
        .trim()
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid CIDR prefix"))?;
    let prefix_len: u8 = prefix_len
        .parse()
        .with_context(|| format!("invalid CIDR prefix length in `{cidr}`"))?;
    let addr: IpAddr = addr
        .parse()
        .with_context(|| format!("invalid IP address in `{cidr}`"))?;

    match addr {
        IpAddr::V4(addr) => ipv4_range(addr, prefix_len),
        IpAddr::V6(addr) => ipv6_range(addr, prefix_len),
    }
}

fn ipv4_range(addr: Ipv4Addr, prefix_len: u8) -> Result<IpRange> {
    if prefix_len > 32 {
        bail!("invalid IPv4 prefix length");
    }
    let raw = u32::from(addr) as u128;
    let mask = if prefix_len == 0 {
        0
    } else {
        (!0u32 << (32 - prefix_len)) as u128
    };
    let from = raw & mask;
    let to = from | ((!mask) & u32::MAX as u128);
    Ok(IpRange {
        family: IpFamily::V4,
        from,
        to,
    })
}

fn ipv6_range(addr: Ipv6Addr, prefix_len: u8) -> Result<IpRange> {
    if prefix_len > 128 {
        bail!("invalid IPv6 prefix length");
    }
    let raw = u128::from(addr);
    let mask = if prefix_len == 0 {
        0
    } else {
        !0u128 << (128 - prefix_len)
    };
    let from = raw & mask;
    let to = from | !mask;
    Ok(IpRange {
        family: IpFamily::V6,
        from,
        to,
    })
}

fn range_to_prefixes(mut start: u128, end: u128, bits: u8) -> Vec<(u128, u8)> {
    let mut prefixes = Vec::new();
    let max_value = if bits == 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    };
    while start <= end {
        let align_exp = if start == 0 {
            bits
        } else {
            start.trailing_zeros().min(bits as u32) as u8
        };
        let size_exp = if start == 0 && end == max_value {
            bits
        } else {
            let remaining = end - start + 1;
            127 - remaining.leading_zeros() as u8
        };
        let exp = align_exp.min(size_exp).min(bits);
        let prefix_len = bits - exp;
        prefixes.push((start, prefix_len));
        if exp == 128 {
            break;
        }
        let step = 1u128 << exp;
        if end - start + 1 == step {
            break;
        }
        start += step;
    }
    prefixes
}

fn format_addr_prefix(family: IpFamily, value: u128, prefix_len: u8) -> String {
    match family {
        IpFamily::V4 => format!("{}/{}", Ipv4Addr::from(value as u32), prefix_len),
        IpFamily::V6 => format!("{}/{}", Ipv6Addr::from(value), prefix_len),
    }
}
