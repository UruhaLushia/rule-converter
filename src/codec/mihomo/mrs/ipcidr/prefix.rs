use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, anyhow, bail};

use super::range::{IpFamily, IpRange, ParsedAddr};

pub fn prefix_contains_ip(rule: &str, ip: IpAddr) -> Result<bool> {
    let range = parse_prefix(rule)?;
    let needle = parsed_addr_from_ip(ip);
    Ok(range.family == needle.family && range.from <= needle.value && needle.value <= range.to)
}

pub fn parse_prefix(rule: &str) -> Result<IpRange> {
    let (addr, prefix_len) = rule
        .trim()
        .split_once('/')
        .ok_or_else(|| anyhow!("invalid CIDR prefix"))?;
    let prefix_len: u8 = prefix_len
        .parse()
        .with_context(|| format!("invalid CIDR prefix length in `{rule}`"))?;
    let addr: IpAddr = addr
        .parse()
        .with_context(|| format!("invalid IP address in `{rule}`"))?;

    match addr {
        IpAddr::V4(addr) => ipv4_range(addr, prefix_len),
        IpAddr::V6(addr) => ipv6_range(addr, prefix_len),
    }
}

pub(super) fn parsed_addr_from_ip(ip: IpAddr) -> ParsedAddr {
    match ip {
        IpAddr::V4(addr) => ParsedAddr {
            family: IpFamily::V4,
            value: u32::from(addr) as u128,
        },
        IpAddr::V6(addr) => ParsedAddr {
            family: IpFamily::V6,
            value: u128::from(addr),
        },
    }
}

pub(super) fn ipv4_range(addr: Ipv4Addr, prefix_len: u8) -> Result<IpRange> {
    if prefix_len > 32 {
        bail!("invalid IPv4 prefix length");
    }
    Ok(ipv4_range_unchecked(addr, prefix_len))
}

pub(super) fn ipv6_range(addr: Ipv6Addr, prefix_len: u8) -> Result<IpRange> {
    if prefix_len > 128 {
        bail!("invalid IPv6 prefix length");
    }
    Ok(ipv6_range_unchecked(addr, prefix_len))
}

fn ipv4_range_unchecked(addr: Ipv4Addr, prefix_len: u8) -> IpRange {
    let raw = u32::from(addr) as u128;
    let mask = if prefix_len == 0 {
        0
    } else {
        (!0u32 << (32 - prefix_len)) as u128
    };
    let from = raw & mask;
    let to = from | ((!mask) & u32::MAX as u128);
    IpRange {
        family: IpFamily::V4,
        from,
        to,
    }
}

fn ipv6_range_unchecked(addr: Ipv6Addr, prefix_len: u8) -> IpRange {
    let raw = u128::from(addr);
    let mask = if prefix_len == 0 {
        0
    } else {
        !0u128 << (128 - prefix_len)
    };
    let from = raw & mask;
    let to = from | !mask;
    IpRange {
        family: IpFamily::V6,
        from,
        to,
    }
}

pub(super) fn range_from_value_prefix(family: IpFamily, value: u128, prefix_len: u8) -> IpRange {
    match family {
        IpFamily::V4 => ipv4_range_unchecked(Ipv4Addr::from(value as u32), prefix_len),
        IpFamily::V6 => ipv6_range_unchecked(Ipv6Addr::from(value), prefix_len),
    }
}

pub(super) fn ip_end_as16(family: IpFamily, value: u128) -> [u8; 16] {
    match family {
        IpFamily::V4 => {
            let mut bytes = [0; 16];
            bytes[10] = 0xff;
            bytes[11] = 0xff;
            bytes[12..16].copy_from_slice(&(value as u32).to_be_bytes());
            bytes
        }
        IpFamily::V6 => value.to_be_bytes(),
    }
}

pub(super) fn range_to_prefixes(mut start: u128, end: u128, bits: u8) -> Vec<(u128, u8)> {
    let mut prefixes = Vec::new();
    while start <= end {
        let remaining = end - start + 1;
        let align_exp = if start == 0 {
            bits
        } else {
            start.trailing_zeros().min(bits as u32) as u8
        };
        let size_exp = 127 - remaining.leading_zeros() as u8;
        let exp = align_exp.min(size_exp).min(bits);
        let prefix_len = bits - exp;
        prefixes.push((start, prefix_len));
        let step = if exp == 128 { u128::MAX } else { 1u128 << exp };
        if step == u128::MAX || end - start + 1 == step {
            break;
        }
        start += step;
    }
    prefixes
}

pub(super) fn format_addr_prefix(family: IpFamily, value: u128, prefix_len: u8) -> String {
    match family {
        IpFamily::V4 => format!("{}/{}", Ipv4Addr::from(value as u32), prefix_len),
        IpFamily::V6 => format!("{}/{}", Ipv6Addr::from(value), prefix_len),
    }
}

pub(super) fn value_to_ip(family: IpFamily, value: u128) -> IpAddr {
    match family {
        IpFamily::V4 => IpAddr::V4(Ipv4Addr::from(value as u32)),
        IpFamily::V6 => IpAddr::V6(Ipv6Addr::from(value)),
    }
}
