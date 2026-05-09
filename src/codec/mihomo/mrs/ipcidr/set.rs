use std::io::{self, Read, Write};
use std::net::IpAddr;

use super::io::{read_addr, read_i64};
use super::prefix::{
    format_addr_prefix, parsed_addr_from_ip, range_from_value_prefix, value_to_ip,
};
use super::range::IpRange;
use crate::codec::mihomo::mrs::write_i64;

pub struct IpCidrSet {
    pub(super) count: usize,
    pub(super) ranges: Vec<IpRange>,
}

impl IpCidrSet {
    pub fn count(&self) -> usize {
        self.count
    }

    pub(crate) fn write_bin<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&[1])?;
        write_i64(writer, self.ranges.len() as i64)?;
        for range in &self.ranges {
            writer.write_all(&range.start_as16())?;
            writer.write_all(&range.end_as16())?;
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

    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        self.matching_range(ip).is_some()
    }

    pub fn matching_prefix(&self, ip: IpAddr) -> Option<String> {
        let range = *self.matching_range(ip)?;
        let needle = parsed_addr_from_ip(ip);
        for (addr, prefix_len) in range.prefixes() {
            let prefix_range = range_from_value_prefix(range.family, addr, prefix_len);
            if prefix_range.from <= needle.value && needle.value <= prefix_range.to {
                return Some(format_addr_prefix(range.family, addr, prefix_len));
            }
        }
        None
    }

    fn matching_range(&self, ip: IpAddr) -> Option<&IpRange> {
        let needle = parsed_addr_from_ip(ip);
        self.ranges
            .binary_search_by(|range| {
                if range.family != needle.family {
                    return range.family.cmp(&needle.family);
                }
                if range.to < needle.value {
                    std::cmp::Ordering::Less
                } else if range.from > needle.value {
                    std::cmp::Ordering::Greater
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .ok()
            .map(|index| &self.ranges[index])
    }

    pub fn for_each_prefix(
        &self,
        mut f: impl FnMut(IpAddr, u8) -> io::Result<()>,
    ) -> io::Result<()> {
        for range in &self.ranges {
            for (addr, prefix_len) in range.prefixes() {
                f(value_to_ip(range.family, addr), prefix_len)?;
            }
        }
        Ok(())
    }
}
