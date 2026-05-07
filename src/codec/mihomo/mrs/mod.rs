mod behavior;
mod binary;
mod container;
mod domain;
mod ipcidr;
mod ruleset;

pub use behavior::Behavior;
pub(crate) use binary::{write_i64, write_u64_vec};
pub use container::read_mrs;
pub use domain::{DomainSet, DomainSetBuilder, normalize_domain_rule};
pub use ipcidr::{IpCidrSet, IpCidrSetBuilder, parse_prefix};
pub use ruleset::RuleSetOutput;

pub fn read_mrs_rules(raw: &[u8]) -> anyhow::Result<Vec<String>> {
    Ok(read_mrs(raw)?.rules())
}
