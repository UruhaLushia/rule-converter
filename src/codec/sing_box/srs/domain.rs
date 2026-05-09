mod keys;
mod louds;
mod read;
mod succinct;

use std::io::Write;

use anyhow::Result;

use crate::codec::sing_box::rule::RuleList;
use crate::codec::sing_box::srs::binary::{write_u64_vec, write_uvarint};

pub(in crate::codec::sing_box::srs) use keys::DomainMatcherKeys;
use keys::{domain_matcher_byte_len, domain_matcher_list_byte_len};
pub(in crate::codec::sing_box::srs) use read::read_domain_matcher;
use succinct::SuccinctSet;

const PREFIX_LABEL: char = '\r';
const ROOT_LABEL: char = '\n';

pub(super) fn write_domain_matcher<W, S>(
    writer: &mut W,
    domains: &[S],
    domain_suffix: &[S],
) -> Result<()>
where
    W: Write,
    S: AsRef<str>,
{
    let mut keys = DomainMatcherKeys::with_byte_capacity(
        domains.len() + domain_suffix.len(),
        domain_matcher_byte_len(domains, domain_suffix),
    );
    push_domain_matcher_keys(&mut keys, domains, domain_suffix)?;
    write_domain_matcher_keys(writer, &mut keys)
}

pub(super) fn push_domain_matcher_keys<S>(
    keys: &mut DomainMatcherKeys,
    domains: &[S],
    domain_suffix: &[S],
) -> Result<()>
where
    S: AsRef<str>,
{
    for suffix in domain_suffix {
        keys.push_suffix(suffix.as_ref())?;
    }
    for domain in domains {
        keys.push_exact(domain.as_ref())?;
    }
    Ok(())
}

pub(super) fn write_domain_matcher_list<W: Write>(
    writer: &mut W,
    domains: &RuleList,
    domain_suffix: &RuleList,
) -> Result<()> {
    let mut keys = DomainMatcherKeys::with_byte_capacity(
        domains.len() + domain_suffix.len(),
        domain_matcher_list_byte_len(domains, domain_suffix),
    );
    push_domain_matcher_list_keys(&mut keys, domains, domain_suffix)?;
    write_domain_matcher_keys(writer, &mut keys)
}

pub(super) fn write_owned_domain_matcher_list<W: Write>(
    writer: &mut W,
    domains: RuleList,
    domain_suffix: RuleList,
) -> Result<()> {
    let suffix_bytes = domain_suffix.iter().map(|value| value.len() + 1).sum();
    let suffix_len = domain_suffix.len();
    let mut keys = DomainMatcherKeys::from_exact_rule_list(domains, suffix_len, suffix_bytes)?;
    for suffix in domain_suffix.iter() {
        keys.push_suffix(suffix)?;
    }
    write_domain_matcher_keys(writer, &mut keys)
}

pub(super) fn push_domain_matcher_list_keys(
    keys: &mut DomainMatcherKeys,
    domains: &RuleList,
    domain_suffix: &RuleList,
) -> Result<()> {
    for suffix in domain_suffix.iter() {
        keys.push_suffix(suffix)?;
    }
    for domain in domains.iter() {
        keys.push_exact(domain)?;
    }
    Ok(())
}

pub(super) fn write_domain_matcher_keys<W: Write>(
    writer: &mut W,
    keys: &mut DomainMatcherKeys,
) -> Result<()> {
    keys.sort_and_dedup();

    let set = SuccinctSet::new(keys)?;
    writer.write_all(&[0])?;
    write_u64_vec(writer, &set.leaves)?;
    write_u64_vec(writer, &set.label_bitmap)?;
    write_uvarint(writer, set.labels.len() as u64)?;
    writer.write_all(&set.labels)?;
    Ok(())
}
