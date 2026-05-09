use super::prefix::{ip_end_as16, range_to_prefixes};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum IpFamily {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug)]
pub struct IpRange {
    pub(super) family: IpFamily,
    pub(super) from: u128,
    pub(super) to: u128,
}

impl IpRange {
    pub(super) fn start_as16(self) -> [u8; 16] {
        ip_end_as16(self.family, self.from)
    }

    pub(super) fn end_as16(self) -> [u8; 16] {
        ip_end_as16(self.family, self.to)
    }

    pub(super) fn prefixes(self) -> Vec<(u128, u8)> {
        let bits = match self.family {
            IpFamily::V4 => 32,
            IpFamily::V6 => 128,
        };
        range_to_prefixes(self.from, self.to, bits)
    }
}

#[derive(Clone, Copy)]
pub(super) struct ParsedAddr {
    pub(super) family: IpFamily,
    pub(super) value: u128,
}
