use std::net::IpAddr;

use anyhow::{Result, bail};

use super::prefix::{ipv4_range, ipv6_range, parse_prefix};
use super::range::IpRange;
use super::set::IpCidrSet;

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
        self.insert_range(range);
        Ok(())
    }

    pub(crate) fn insert_prefix(&mut self, addr: IpAddr, prefix_len: u8) -> Result<()> {
        let range = match addr {
            IpAddr::V4(addr) => ipv4_range(addr, prefix_len)?,
            IpAddr::V6(addr) => ipv6_range(addr, prefix_len)?,
        };
        self.insert_range(range);
        Ok(())
    }

    fn insert_range(&mut self, range: IpRange) {
        self.ranges.push(range);
        self.count += 1;
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn finish(mut self) -> Result<IpCidrSet> {
        if self.ranges.is_empty() {
            bail!("ipcidr rule-set is empty");
        }
        self.ranges.sort_by_key(|range| (range.family, range.from));

        let mut write = 0usize;
        for read in 0..self.ranges.len() {
            let range = self.ranges[read];
            if write > 0 {
                let last = &mut self.ranges[write - 1];
                if last.family == range.family && range.from <= last.to.saturating_add(1) {
                    last.to = last.to.max(range.to);
                    continue;
                }
            }
            self.ranges[write] = range;
            write += 1;
        }
        self.ranges.truncate(write);
        self.ranges.shrink_to_fit();

        Ok(IpCidrSet {
            count: self.count,
            ranges: self.ranges,
        })
    }
}
