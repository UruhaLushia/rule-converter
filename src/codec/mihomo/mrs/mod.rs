mod behavior;
mod binary;
mod container;
mod domain;
mod ipcidr;
mod ruleset;

pub use behavior::Behavior;
pub(crate) use binary::{write_i64, write_u64_vec};
pub use container::{read_mrs, read_mrs_behavior, read_mrs_behavior_stream, read_mrs_stream};
pub use domain::{DomainSet, DomainSetBuilder, normalize_domain_rule};
pub use ipcidr::{IpCidrSet, IpCidrSetBuilder, parse_prefix, prefix_contains_ip};
pub use ruleset::RuleSetOutput;

pub fn read_mrs_rules(raw: &[u8]) -> anyhow::Result<Vec<String>> {
    Ok(read_mrs(raw)?.rules())
}
