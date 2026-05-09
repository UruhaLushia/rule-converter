use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, anyhow, bail};

use super::write_i64;

#[derive(Default)]
pub struct IpCidrSetBuilder {
    ranges: Vec<IpRange>,
    count: usize,
}

impl IpCidrSetBuilder {
    pub fn reserve(&mut self, ranges: usize) {
        self.ranges.reserve(ranges);
    }

    pub fn insert(&mut self, rule: &str) -> Result<()> {
        let range = parse_prefix(rule)?;
        self.ranges.push(range);
        self.count += 1;
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn finish(mut self) -> Result<IpCidrSet> {
        if self.ranges.is_empty() {
            bail!("ipcidr rule-set is empty");
        }
        self.ranges.sort_by_key(|range| (range.family, range.from));

        let mut merged: Vec<IpRange> = Vec::with_capacity(self.ranges.len());
        for range in self.ranges {
            if let Some(last) = merged.last_mut() {
                if last.family == range.family && range.from <= last.to.saturating_add(1) {
                    last.to = last.to.max(range.to);
                    continue;
                }
            }
            merged.push(range);
        }

        Ok(IpCidrSet {
            count: self.count,
            ranges: merged,
        })
    }
}

pub struct IpCidrSet {
    count: usize,
    ranges: Vec<IpRange>,
}

impl IpCidrSet {
    pub fn count(&self) -> usize {
        self.count
    }

    pub(crate) fn write_bin<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&[1])?;
        write_i64(writer, self.ranges.len() as i64)?;
        for range in &self.ranges {
            writer.write_all(&range.from_as16())?;
            writer.write_all(&range.to_as16())?;
        }
        Ok(())
    }

    pub(crate) fn read_bin<R: Read>(reader: &mut R, count: usize) -> io::Result<Self> {
        let mut version = [0; 1];
        reader.read_exact(&mut version)?;
        if version[0] != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ipcidr set version",
            ));
        }

        let len = read_i64(reader)?;
        if len < 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid range length",
            ));
        }
        let mut ranges = Vec::with_capacity(len as usize);
        for _ in 0..len {
            let from = read_addr(reader)?;
            let to = read_addr(reader)?;
            if from.family != to.family {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "mixed address families in range",
                ));
            }
            ranges.push(IpRange {
                family: from.family,
                from: from.value,
                to: to.value,
            });
        }

        Ok(Self { count, ranges })
    }

    pub fn rules(&self) -> Vec<String> {
        let mut rules = Vec::new();
        let _ = self.for_each_rule(|rule| {
            rules.push(rule.to_string());
            Ok(())
        });
        rules
    }

    pub fn for_each_rule(&self, mut f: impl FnMut(&str) -> io::Result<()>) -> io::Result<()> {
        for range in &self.ranges {
            for (addr, prefix_len) in range.prefixes() {
                f(&format_addr_prefix(range.family, addr, prefix_len))?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum IpFamily {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug)]
pub struct IpRange {
    family: IpFamily,
    from: u128,
    to: u128,
}

impl IpRange {
    fn from_as16(self) -> [u8; 16] {
        ip_to_as16(self.family, self.from)
    }

    fn to_as16(self) -> [u8; 16] {
        ip_to_as16(self.family, self.to)
    }

    fn prefixes(self) -> Vec<(u128, u8)> {
        let bits = match self.family {
            IpFamily::V4 => 32,
            IpFamily::V6 => 128,
        };
        range_to_prefixes(self.from, self.to, bits)
    }
}

#[derive(Clone, Copy)]
struct ParsedAddr {
    family: IpFamily,
    value: u128,
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

fn ip_to_as16(family: IpFamily, value: u128) -> [u8; 16] {
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

fn read_i64<R: Read>(reader: &mut R) -> io::Result<i64> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    Ok(i64::from_be_bytes(bytes))
}

fn read_addr<R: Read>(reader: &mut R) -> io::Result<ParsedAddr> {
    let mut bytes = [0; 16];
    reader.read_exact(&mut bytes)?;
    let is_v4 = bytes[..10].iter().all(|byte| *byte == 0) && bytes[10] == 0xff && bytes[11] == 0xff;
    if is_v4 {
        let value = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as u128;
        Ok(ParsedAddr {
            family: IpFamily::V4,
            value,
        })
    } else {
        Ok(ParsedAddr {
            family: IpFamily::V6,
            value: u128::from_be_bytes(bytes),
        })
    }
}

fn range_to_prefixes(mut start: u128, end: u128, bits: u8) -> Vec<(u128, u8)> {
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

fn format_addr_prefix(family: IpFamily, value: u128, prefix_len: u8) -> String {
    match family {
        IpFamily::V4 => format!("{}/{}", Ipv4Addr::from(value as u32), prefix_len),
        IpFamily::V6 => format!("{}/{}", Ipv6Addr::from(value), prefix_len),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_prefix_is_masked_and_written_as_mapped_ipv6() {
        let range = parse_prefix("192.168.1.123/24").unwrap();
        assert_eq!(range.from_as16()[12..16], [192, 168, 1, 0]);
        assert_eq!(range.to_as16()[12..16], [192, 168, 1, 255]);
        assert_eq!(range.from_as16()[10..12], [0xff, 0xff]);
    }
}
