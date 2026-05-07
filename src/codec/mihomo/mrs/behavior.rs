#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Behavior {
    Domain,
    Ipcidr,
}

impl Behavior {
    pub fn as_str(self) -> &'static str {
        match self {
            Behavior::Domain => "domain",
            Behavior::Ipcidr => "ip",
        }
    }

    pub(crate) fn byte(self) -> u8 {
        match self {
            Behavior::Domain => 0,
            Behavior::Ipcidr => 1,
        }
    }

    pub(crate) fn from_byte(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Domain),
            1 => Some(Self::Ipcidr),
            _ => None,
        }
    }
}
