use anyhow::{Result, bail};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::louds::set_bit;
use super::normalize::normalize_domain_rule;
use super::set::DomainSet;

#[derive(Default)]
pub struct DomainSetBuilder {
    keys: Vec<KeyRef>,
    bytes: Vec<u8>,
    count: usize,
    has_suffix: bool,
}

impl DomainSetBuilder {
    pub fn reserve(&mut self, keys: usize, bytes: usize) {
        self.keys.reserve(keys);
        self.bytes.reserve(bytes.saturating_add(keys));
    }

    pub fn insert(&mut self, rule: &str) -> Result<()> {
        normalize_domain_rule(rule, |domain| {
            self.has_suffix |= domain.starts_with("+.") || domain.starts_with('.');
            self.push_reversed_key(domain)
        })?;
        self.count += 1;
        Ok(())
    }

    pub fn insert_domain_set(&mut self, rule: &str) -> Result<()> {
        let rule = rule.trim();
        if let Some(suffix) = rule.strip_prefix('.') {
            if suffix.is_empty() {
                bail!("invalid domain-set suffix");
            }
            self.push_reversed_key(suffix)?;
            self.push_reversed_key(&format!("+.{suffix}"))?;
            self.has_suffix = true;
        } else {
            self.insert(rule)?;
            return Ok(());
        }
        self.count += 1;
        Ok(())
    }

    fn push_reversed_key(&mut self, value: &str) -> Result<()> {
        let offset = self.bytes.len();
        for ch in value.chars().rev() {
            let mut buf = [0; 4];
            self.bytes
                .extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
        let len = self.bytes.len() - offset;
        self.bytes.push(0);
        let offset =
            u32::try_from(offset).map_err(|_| anyhow::anyhow!("domain set is too large"))?;
        let len = u32::try_from(len).map_err(|_| anyhow::anyhow!("domain key is too large"))?;
        self.keys.push(KeyRef { offset, len });
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn finish(mut self) -> Result<DomainSet> {
        if self.keys.is_empty() {
            bail!("domain rule-set is empty");
        }

        sort_domain_keys(&mut self.keys, &self.bytes);
        self.keys
            .dedup_by(|a, b| key_bytes(&self.bytes, *a) == key_bytes(&self.bytes, *b));
        let count = self.count;
        let has_suffix = self.has_suffix;
        let key_refs = self.keys;
        let bytes = self.bytes;
        let keys: Vec<u32> = key_refs.iter().map(|key| key.offset).collect();
        drop(key_refs);
        let mut leaves = Vec::with_capacity((keys.len() / 64).saturating_add(1));
        let mut label_bitmap = Vec::with_capacity((keys.len() / 32).saturating_add(1));
        let mut labels = Vec::with_capacity(keys.len());
        let mut current = vec![pack_range(0, keys.len())?];
        let mut next = Vec::new();

        let mut label_index = 0usize;
        let mut node_id = 0usize;
        let mut depth = 0usize;
        while !current.is_empty() {
            next.clear();
            for range in current.drain(..) {
                let (mut start, end) = unpack_range(range);
                if key_byte(&bytes, keys[start], depth) == 0 {
                    start += 1;
                    set_bit(&mut leaves, node_id, 1);
                }

                let mut cursor = start;
                while cursor < end {
                    let from = cursor;
                    while cursor < end
                        && key_byte(&bytes, keys[cursor], depth)
                            == key_byte(&bytes, keys[from], depth)
                    {
                        cursor += 1;
                    }
                    next.push(pack_range(from, cursor)?);
                    labels.push(key_byte(&bytes, keys[from], depth));
                    set_bit(&mut label_bitmap, label_index, 0);
                    label_index += 1;
                }
                set_bit(&mut label_bitmap, label_index, 1);
                label_index += 1;
                node_id += 1;
            }
            std::mem::swap(&mut current, &mut next);
            depth += 1;
        }

        drop(bytes);
        drop(keys);
        drop(current);
        drop(next);

        Ok(DomainSet {
            count,
            has_suffix,
            leaves,
            label_bitmap,
            labels,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KeyRef {
    offset: u32,
    len: u32,
}

fn key_bytes(bytes: &[u8], key: KeyRef) -> &[u8] {
    let start = key.offset as usize;
    let end = start + key.len as usize;
    &bytes[start..end]
}

fn key_byte(bytes: &[u8], offset: u32, index: usize) -> u8 {
    bytes[offset as usize + index]
}

fn pack_range(start: usize, end: usize) -> Result<u64> {
    let start = u32::try_from(start).map_err(|_| anyhow::anyhow!("domain set is too large"))?;
    let end = u32::try_from(end).map_err(|_| anyhow::anyhow!("domain set is too large"))?;
    Ok(((start as u64) << 32) | end as u64)
}

fn unpack_range(range: u64) -> (usize, usize) {
    ((range >> 32) as usize, (range as u32) as usize)
}

fn sort_domain_keys(keys: &mut [KeyRef], bytes: &[u8]) {
    #[cfg(feature = "parallel")]
    {
        if keys.len() >= 100_000 {
            keys.par_sort_unstable_by(|left, right| {
                key_bytes(bytes, *left).cmp(key_bytes(bytes, *right))
            });
            return;
        }
    }

    keys.sort_unstable_by(|left, right| key_bytes(bytes, *left).cmp(key_bytes(bytes, *right)));
}

impl FromIterator<String> for DomainSetBuilder {
    fn from_iter<T: IntoIterator<Item = String>>(iter: T) -> Self {
        let mut builder = Self::default();
        for rule in iter {
            let _ = builder.insert(&rule);
        }
        builder
    }
}
