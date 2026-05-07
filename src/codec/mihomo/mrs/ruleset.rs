use anyhow::Result;

use super::{Behavior, DomainSet, IpCidrSet};

pub enum RuleSetOutput {
    Domain(DomainSet),
    Ipcidr(IpCidrSet),
}

impl RuleSetOutput {
    pub fn behavior(&self) -> Behavior {
        match self {
            Self::Domain(_) => Behavior::Domain,
            Self::Ipcidr(_) => Behavior::Ipcidr,
        }
    }

    pub fn count(&self) -> usize {
        match self {
            Self::Domain(set) => set.count(),
            Self::Ipcidr(set) => set.count(),
        }
    }

    pub fn to_mrs_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        self.write_mrs(&mut bytes)?;
        Ok(bytes)
    }

    pub fn rules(&self) -> Vec<String> {
        match self {
            Self::Domain(set) => set.rules(),
            Self::Ipcidr(set) => set.rules(),
        }
    }

    pub fn for_each_rule(&self, f: impl FnMut(&str) -> std::io::Result<()>) -> std::io::Result<()> {
        match self {
            Self::Domain(set) => set.for_each_rule(f),
            Self::Ipcidr(set) => set.for_each_rule(f),
        }
    }
}
