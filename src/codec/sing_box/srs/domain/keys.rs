use anyhow::{Result, anyhow, bail};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::codec::sing_box::rule::RuleList;

use super::{PREFIX_LABEL, ROOT_LABEL};

pub(in crate::codec::sing_box::srs) struct DomainMatcherKeys {
    pub(super) keys: Vec<KeyRef>,
    pub(super) bytes: Vec<u8>,
}

impl DomainMatcherKeys {
    pub(in crate::codec::sing_box::srs) fn with_capacity(capacity: usize) -> Self {
        Self {
            keys: Vec::with_capacity(capacity),
            bytes: Vec::new(),
        }
    }

    pub(in crate::codec::sing_box::srs) fn with_byte_capacity(
        capacity: usize,
        byte_capacity: usize,
    ) -> Self {
        Self {
            keys: Vec::with_capacity(capacity),
            bytes: Vec::with_capacity(byte_capacity.saturating_add(capacity)),
        }
    }

    pub(in crate::codec::sing_box::srs) fn from_exact_rule_list(
        domains: RuleList,
        extra_keys: usize,
        extra_bytes: usize,
    ) -> Result<Self> {
        let (mut bytes, items) = domains.into_parts();
        bytes.reserve(items.len() + extra_bytes);
        let old_len = bytes.len();
        if bytes[..old_len].contains(&0) {
            return Err(anyhow!("invalid sing-box domain matcher key"));
        }
        bytes.resize(old_len + items.len(), 0);
        let mut keys = vec![KeyRef { offset: 0, len: 0 }; items.len()];
        let mut shifted_end = bytes.len();
        for (index, (offset, len)) in items.into_iter().enumerate().rev() {
            let start = offset as usize;
            let end = start + len as usize;
            if end > old_len {
                return Err(anyhow!("invalid sing-box domain rule list"));
            }
            let new_start = shifted_end - len as usize - 1;
            bytes.copy_within(start..end, new_start);
            bytes[new_start..new_start + len as usize].reverse();
            bytes[new_start + len as usize] = 0;
            keys[index] = KeyRef {
                offset: u32::try_from(new_start)
                    .map_err(|_| anyhow!("sing-box domain matcher is too large"))?,
                len,
            };
            shifted_end = new_start;
        }
        keys.reserve(extra_keys);
        Ok(Self { keys, bytes })
    }

    pub(in crate::codec::sing_box::srs) fn push_exact(&mut self, value: &str) -> Result<()> {
        validate_domain_matcher_key(value)?;
        self.push_reversed(value.as_bytes())
    }

    pub(in crate::codec::sing_box::srs) fn push_suffix(&mut self, value: &str) -> Result<()> {
        validate_domain_matcher_key(value)?;
        let label = if value.starts_with('.') {
            PREFIX_LABEL as u8
        } else {
            ROOT_LABEL as u8
        };
        let offset = self.bytes.len();
        self.push_reversed_bytes(value.as_bytes());
        self.bytes.push(label);
        self.push_ref(offset)
    }

    fn push_reversed(&mut self, value: &[u8]) -> Result<()> {
        let offset = self.bytes.len();
        self.push_reversed_bytes(value);
        self.push_ref(offset)
    }

    fn push_reversed_bytes(&mut self, value: &[u8]) {
        self.bytes.extend(value.iter().rev().copied());
    }

    fn push_ref(&mut self, offset: usize) -> Result<()> {
        let len = self.bytes.len() - offset;
        self.keys.push(KeyRef {
            offset: u32::try_from(offset)
                .map_err(|_| anyhow!("sing-box domain matcher is too large"))?,
            len: u32::try_from(len).map_err(|_| anyhow!("sing-box domain key is too large"))?,
        });
        self.bytes.push(0);
        Ok(())
    }

    pub(super) fn sort_and_dedup(&mut self) {
        let bytes = &self.bytes;
        #[cfg(feature = "parallel")]
        {
            if self.keys.len() >= 100_000 {
                self.keys.par_sort_unstable_by(|left, right| {
                    key_bytes(bytes, *left).cmp(key_bytes(bytes, *right))
                });
                self.keys
                    .dedup_by(|left, right| key_bytes(bytes, *left) == key_bytes(bytes, *right));
                return;
            }
        }

        self.keys
            .sort_unstable_by(|left, right| key_bytes(bytes, *left).cmp(key_bytes(bytes, *right)));
        self.keys
            .dedup_by(|left, right| key_bytes(bytes, *left) == key_bytes(bytes, *right));
    }
}

pub(super) fn domain_matcher_byte_len<S: AsRef<str>>(domains: &[S], domain_suffix: &[S]) -> usize {
    domains
        .iter()
        .map(|value| value.as_ref().len() + 1)
        .sum::<usize>()
        + domain_suffix
            .iter()
            .map(|value| value.as_ref().len() + 2)
            .sum::<usize>()
}

pub(super) fn domain_matcher_list_byte_len(domains: &RuleList, domain_suffix: &RuleList) -> usize {
    domains.iter().map(|value| value.len() + 1).sum::<usize>()
        + domain_suffix
            .iter()
            .map(|value| value.len() + 2)
            .sum::<usize>()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct KeyRef {
    pub(super) offset: u32,
    len: u32,
}

pub(super) fn key_bytes(bytes: &[u8], key: KeyRef) -> &[u8] {
    let start = key.offset as usize;
    &bytes[start..start + key.len as usize]
}

pub(super) fn key_byte(bytes: &[u8], offset: u32, index: usize) -> u8 {
    bytes[offset as usize + index]
}

fn validate_domain_matcher_key(value: &str) -> Result<()> {
    if value.as_bytes().contains(&0) {
        bail!("invalid sing-box domain matcher key");
    }
    Ok(())
}

pub(super) fn pack_range(start: usize, end: usize) -> Result<u64> {
    let start =
        u32::try_from(start).map_err(|_| anyhow!("sing-box domain matcher is too large"))?;
    let end = u32::try_from(end).map_err(|_| anyhow!("sing-box domain matcher is too large"))?;
    Ok(((start as u64) << 32) | end as u64)
}

pub(super) fn unpack_range(range: u64) -> (usize, usize) {
    ((range >> 32) as usize, (range as u32) as usize)
}
