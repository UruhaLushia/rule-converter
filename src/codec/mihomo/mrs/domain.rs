use std::io::{self, Read, Write};

use anyhow::{Result, bail};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::{write_i64, write_u64_vec};

#[derive(Default)]
pub struct DomainSetBuilder {
    keys: Vec<KeyRef>,
    bytes: Vec<u8>,
    count: usize,
    has_suffix: bool,
}

impl DomainSetBuilder {
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
        let keys = self.keys;
        let bytes = self.bytes;
        let mut leaves = Vec::with_capacity((keys.len() / 64).saturating_add(1));
        let mut label_bitmap = Vec::with_capacity((keys.len() / 32).saturating_add(1));
        let mut labels = Vec::with_capacity(keys.len());
        let mut current = vec![QueueItem {
            start: 0,
            end: keys.len() as u32,
            col: 0,
        }];
        let mut next = Vec::new();

        let mut label_index = 0usize;
        let mut node_id = 0usize;
        while !current.is_empty() {
            next.clear();
            for mut item in current.drain(..) {
                let start = item.start as usize;
                let col = item.col as usize;
                if col == key_len(keys[start]) {
                    item.start += 1;
                    set_bit(&mut leaves, node_id, 1);
                }

                let mut cursor = item.start as usize;
                while cursor < item.end as usize {
                    let from = cursor;
                    while cursor < item.end as usize
                        && key_byte(&bytes, keys[cursor], col) == key_byte(&bytes, keys[from], col)
                    {
                        cursor += 1;
                    }
                    next.push(QueueItem {
                        start: from as u32,
                        end: cursor as u32,
                        col: item.col + 1,
                    });
                    labels.push(key_byte(&bytes, keys[from], col));
                    set_bit(&mut label_bitmap, label_index, 0);
                    label_index += 1;
                }
                set_bit(&mut label_bitmap, label_index, 1);
                label_index += 1;
                node_id += 1;
            }
            std::mem::swap(&mut current, &mut next);
        }

        drop(bytes);
        drop(keys);
        drop(current);
        drop(next);

        Ok(DomainSet {
            count: self.count,
            has_suffix: self.has_suffix,
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

fn key_len(key: KeyRef) -> usize {
    key.len as usize
}

fn key_byte(bytes: &[u8], key: KeyRef, index: usize) -> u8 {
    bytes[key.offset as usize + index]
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

#[derive(Clone, Copy)]
struct QueueItem {
    start: u32,
    end: u32,
    col: u32,
}

pub struct DomainSet {
    count: usize,
    has_suffix: bool,
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
}

impl DomainSet {
    pub fn count(&self) -> usize {
        self.count
    }

    pub(crate) fn write_bin<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&[1])?;
        write_u64_vec(writer, &self.leaves)?;
        write_u64_vec(writer, &self.label_bitmap)?;
        write_i64(writer, self.labels.len() as i64)?;
        writer.write_all(&self.labels)?;
        Ok(())
    }

    pub(crate) fn read_bin<R: Read>(reader: &mut R, count: usize) -> io::Result<Self> {
        let mut version = [0; 1];
        reader.read_exact(&mut version)?;
        if version[0] != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid domain set version",
            ));
        }

        let leaves = read_u64_vec(reader)?;
        let label_bitmap = read_u64_vec(reader)?;
        let labels_len = read_i64(reader)?;
        if labels_len < 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid labels length",
            ));
        }
        let mut labels = vec![0; labels_len as usize];
        reader.read_exact(&mut labels)?;

        Ok(Self {
            count,
            has_suffix: true,
            leaves,
            label_bitmap,
            labels,
        })
    }

    pub fn rules(&self) -> Vec<String> {
        let mut keys = Vec::new();
        let _ = self.for_each_rule(|rule| {
            keys.push(rule.to_string());
            Ok(())
        });
        keys
    }

    pub fn for_each_rule(&self, mut f: impl FnMut(&str) -> io::Result<()>) -> io::Result<()> {
        if !self.has_suffix {
            return self.for_each_raw_rule(f);
        }

        let index = LoudsIndex::new(&self.label_bitmap);
        let mut wildcard = Vec::new();
        self.visit_reversed_keys(&mut Vec::new(), &mut |reversed| {
            if let Some(suffix_reversed) = reversed.strip_suffix(b".+") {
                let Some(suffix) = reversed_key_to_rule(suffix_reversed) else {
                    return Ok(());
                };
                let rule = if self.contains_reversed_key(suffix_reversed, &index) {
                    format!("+.{suffix}")
                } else {
                    format!(".{suffix}")
                };
                f(&rule)?;
            } else {
                wildcard.clear();
                wildcard.extend_from_slice(reversed);
                wildcard.extend_from_slice(b".+");
                if self.contains_reversed_key(&wildcard, &index) {
                    return Ok(());
                }
                let Some(key) = reversed_key_to_rule(reversed) else {
                    return Ok(());
                };
                f(&key)?;
            }
            Ok(())
        })
    }

    pub fn for_each_exact_rule(&self, mut f: impl FnMut(&str) -> io::Result<()>) -> io::Result<()> {
        if !self.has_suffix {
            return self.for_each_raw_rule(f);
        }

        let index = LoudsIndex::new(&self.label_bitmap);
        let mut wildcard = Vec::new();
        self.visit_reversed_keys(&mut Vec::new(), &mut |reversed| {
            if reversed.ends_with(b".+") {
                return Ok(());
            }
            wildcard.clear();
            wildcard.extend_from_slice(reversed);
            wildcard.extend_from_slice(b".+");
            if self.contains_reversed_key(&wildcard, &index) {
                return Ok(());
            }
            let Some(key) = reversed_key_to_rule(reversed) else {
                return Ok(());
            };
            f(&key)?;
            Ok(())
        })
    }

    pub fn for_each_suffix_rule(
        &self,
        mut f: impl FnMut(&str) -> io::Result<()>,
    ) -> io::Result<()> {
        self.visit_reversed_keys(&mut Vec::new(), &mut |reversed| {
            if let Some(suffix) = reversed_suffix_to_rule(reversed) {
                f(&suffix)?;
            }
            Ok(())
        })
    }

    fn for_each_raw_rule(&self, mut f: impl FnMut(&str) -> io::Result<()>) -> io::Result<()> {
        self.visit_reversed_keys(&mut Vec::new(), &mut |reversed| {
            let Some(key) = reversed_key_to_rule(reversed) else {
                return Ok(());
            };
            f(&key)
        })
    }

    fn visit_reversed_keys(
        &self,
        current: &mut Vec<u8>,
        f: &mut impl FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        let index = LoudsIndex::new(&self.label_bitmap);
        self.visit_reversed_keys_at(0, 0, current, &index, f)
    }

    fn contains_reversed_key(&self, key: &[u8], index: &LoudsIndex<'_>) -> bool {
        let mut node_id = 0usize;
        let mut bm_idx = 0usize;

        for byte in key {
            let mut idx = bm_idx;
            let (next_node_id, next_bm_idx) = loop {
                if get_bit(&self.label_bitmap, idx) != 0 {
                    return false;
                }
                let label = self.labels[idx - node_id];
                if &label == byte {
                    let next_node_id = index.count_zeros(idx + 1);
                    let next_bm_idx = index.select_ith_one(next_node_id - 1) + 1;
                    break (next_node_id, next_bm_idx);
                }
                idx += 1;
            };
            node_id = next_node_id;
            bm_idx = next_bm_idx;
        }

        get_bit(&self.leaves, node_id) != 0
    }

    fn visit_reversed_keys_at(
        &self,
        node_id: usize,
        bm_idx: usize,
        current: &mut Vec<u8>,
        index: &LoudsIndex,
        f: &mut impl FnMut(&[u8]) -> io::Result<()>,
    ) -> io::Result<()> {
        if get_bit(&self.leaves, node_id) != 0 {
            f(current)?;
        }

        let mut idx = bm_idx;
        loop {
            if get_bit(&self.label_bitmap, idx) != 0 {
                return Ok(());
            }
            let label = self.labels[idx - node_id];
            current.push(label);
            let next_node_id = index.count_zeros(idx + 1);
            let next_bm_idx = index.select_ith_one(next_node_id - 1) + 1;
            self.visit_reversed_keys_at(next_node_id, next_bm_idx, current, index, f)?;
            current.pop();
            idx += 1;
        }
    }
}

pub fn normalize_domain_rule(mut rule: &str, mut f: impl FnMut(&str) -> Result<()>) -> Result<()> {
    rule = rule.trim();
    if rule.contains('/') {
        bail!("invalid domain contains `/`");
    }
    if rule.is_empty() || rule.ends_with('.') {
        bail!("invalid domain");
    }
    if rule.chars().next().is_some_and(char::is_whitespace)
        || rule.chars().next_back().is_some_and(char::is_whitespace)
    {
        bail!("invalid domain has surrounding whitespace");
    }

    let lower;
    let domain = if rule.bytes().any(|byte| byte.is_ascii_uppercase()) {
        lower = rule.to_ascii_lowercase();
        lower.as_str()
    } else {
        rule
    };

    if let Some(suffix) = domain.strip_prefix("+.") {
        validate_domain_tail(suffix, "invalid complex wildcard domain")?;
        f(suffix)?;
        let wildcard = format!("+.{suffix}");
        f(&wildcard)?;
    } else if let Some(suffix) = domain.strip_prefix('.') {
        validate_domain_tail(suffix, "invalid wildcard domain")?;
        let wildcard = format!("+.{suffix}");
        f(&wildcard)?;
    } else {
        validate_domain_tail(domain, "invalid domain")?;
        f(domain)?;
    }

    Ok(())
}

fn validate_domain_tail(domain: &str, empty_error: &str) -> Result<()> {
    if domain.is_empty() {
        bail!(empty_error.to_string());
    }
    if domain.split('.').any(str::is_empty) {
        bail!("invalid domain");
    }
    Ok(())
}

fn reverse_runes(value: &str) -> String {
    value.chars().rev().collect()
}

fn reversed_key_to_rule(reversed: &[u8]) -> Option<String> {
    let reversed = String::from_utf8(reversed.to_vec()).ok()?;
    Some(reverse_runes(&reversed))
}

fn reversed_suffix_to_rule(reversed: &[u8]) -> Option<String> {
    let reversed = reversed.strip_suffix(b".+")?;
    reversed_key_to_rule(reversed)
}

fn set_bit(bitmap: &mut Vec<u64>, index: usize, value: u64) {
    while index >> 6 >= bitmap.len() {
        bitmap.push(0);
    }
    bitmap[index >> 6] |= value << (index & 63);
}

fn get_bit(bitmap: &[u64], index: usize) -> u64 {
    bitmap[index >> 6] & (1 << (index & 63))
}

struct LoudsIndex<'a> {
    words: &'a [u64],
    ones_before_word: Vec<usize>,
    one_positions: Vec<u32>,
}

impl<'a> LoudsIndex<'a> {
    fn new(bitmap: &'a [u64]) -> Self {
        let mut ones_before_word = Vec::with_capacity(bitmap.len() + 1);
        let mut one_positions = Vec::new();
        let mut ones = 0usize;
        for (word_index, word) in bitmap.iter().copied().enumerate() {
            ones_before_word.push(ones);
            let mut word_bits = word;
            while word_bits != 0 {
                let bit = word_bits.trailing_zeros() as usize;
                one_positions.push((word_index * 64 + bit) as u32);
                word_bits &= word_bits - 1;
                ones += 1;
            }
        }
        ones_before_word.push(ones);
        Self {
            words: bitmap,
            ones_before_word,
            one_positions,
        }
    }

    fn count_zeros(&self, index: usize) -> usize {
        index - self.count_ones_before(index)
    }

    fn select_ith_one(&self, target: usize) -> usize {
        self.one_positions[target] as usize
    }

    fn count_ones_before(&self, index: usize) -> usize {
        let word = index >> 6;
        let bit = index & 63;
        let before = self.ones_before_word[word];
        if bit == 0 {
            return before;
        }
        let mask = (1u64 << bit) - 1;
        before + (self.words[word] & mask).count_ones() as usize
    }
}

fn read_u64_vec<R: Read>(reader: &mut R) -> io::Result<Vec<u64>> {
    let len = read_i64(reader)?;
    if len < 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid vector length",
        ));
    }
    let mut values = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let mut bytes = [0; 8];
        reader.read_exact(&mut bytes)?;
        values.push(u64::from_be_bytes(bytes));
    }
    Ok(values)
}

fn read_i64<R: Read>(reader: &mut R) -> io::Result<i64> {
    let mut bytes = [0; 8];
    reader.read_exact(&mut bytes)?;
    Ok(i64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_expands_to_exact_and_complex_wildcard() {
        let mut domains = Vec::new();
        normalize_domain_rule("+.example.com", |rule| {
            domains.push(rule.to_string());
            Ok(())
        })
        .unwrap();
        assert_eq!(domains, vec!["example.com", "+.example.com"]);
    }

    #[test]
    fn rules_distinguish_subdomain_only_and_complex_wildcard() {
        let mut builder = DomainSetBuilder::default();
        builder.insert(".example.com").unwrap();
        builder.insert("+.example.net").unwrap();

        let set = builder.finish().unwrap();

        assert_eq!(set.rules(), vec![".example.com", "+.example.net"]);
    }

    #[test]
    fn domain_set_suffix_lines_include_exact_domain() {
        let mut builder = DomainSetBuilder::default();
        builder.insert_domain_set(".example.com").unwrap();

        let set = builder.finish().unwrap();

        assert_eq!(set.rules(), vec!["+.example.com"]);
    }
}
