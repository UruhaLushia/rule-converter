use std::io::{Read, Write};

use anyhow::{Context, Result, anyhow};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::codec::sing_box::rule::RuleList;

use super::binary::{read_byte, read_u64_vec, read_uvarint, write_u64_vec, write_uvarint};

const PREFIX_LABEL: char = '\r';
const ROOT_LABEL: char = '\n';

#[derive(Default)]
pub(super) struct DomainMatcherDump {
    pub(super) domain: Vec<String>,
    pub(super) domain_suffix: Vec<String>,
}

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

    let set = SuccinctSet::new(keys);
    writer.write_all(&[0])?;
    write_u64_vec(writer, &set.leaves)?;
    write_u64_vec(writer, &set.label_bitmap)?;
    write_uvarint(writer, set.labels.len() as u64)?;
    writer.write_all(&set.labels)?;
    Ok(())
}

pub(super) struct DomainMatcherKeys {
    keys: Vec<KeyRef>,
    bytes: Vec<u8>,
}

impl DomainMatcherKeys {
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            keys: Vec::with_capacity(capacity),
            bytes: Vec::new(),
        }
    }

    pub(super) fn with_byte_capacity(capacity: usize, byte_capacity: usize) -> Self {
        Self {
            keys: Vec::with_capacity(capacity),
            bytes: Vec::with_capacity(byte_capacity),
        }
    }

    pub(super) fn push_exact(&mut self, value: &str) -> Result<()> {
        self.push_reversed(value.as_bytes())
    }

    pub(super) fn push_suffix(&mut self, value: &str) -> Result<()> {
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
        Ok(())
    }

    fn sort_and_dedup(&mut self) {
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

    fn key_len(&self, key: KeyRef) -> usize {
        key.len as usize
    }

    fn key_byte(&self, key: KeyRef, index: usize) -> u8 {
        self.bytes[key.offset as usize + index]
    }
}

pub(super) fn domain_matcher_byte_len<S: AsRef<str>>(domains: &[S], domain_suffix: &[S]) -> usize {
    domains
        .iter()
        .map(|value| value.as_ref().len())
        .sum::<usize>()
        + domain_suffix
            .iter()
            .map(|value| value.as_ref().len() + 1)
            .sum::<usize>()
}

pub(super) fn domain_matcher_list_byte_len(domains: &RuleList, domain_suffix: &RuleList) -> usize {
    domains.iter().map(str::len).sum::<usize>()
        + domain_suffix
            .iter()
            .map(|value| value.len() + 1)
            .sum::<usize>()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KeyRef {
    offset: u32,
    len: u32,
}

fn key_bytes(bytes: &[u8], key: KeyRef) -> &[u8] {
    let start = key.offset as usize;
    &bytes[start..start + key.len as usize]
}

pub(super) fn read_domain_matcher<R: Read>(reader: &mut R) -> Result<DomainMatcherDump> {
    let _reserved = read_byte(reader)?;
    let leaves = read_u64_vec(reader)?;
    let label_bitmap = read_u64_vec(reader)?;
    let labels_len = read_uvarint(reader)?;
    let mut labels = vec![0; labels_len as usize];
    reader.read_exact(&mut labels)?;
    let set = SuccinctSet {
        leaves,
        label_bitmap,
        labels,
    };

    let mut dump = DomainMatcherDump::default();
    for key in set.keys()? {
        let key = reverse_runes(&key);
        if let Some(suffix) = key.strip_prefix(PREFIX_LABEL) {
            dump.domain_suffix.push(suffix.to_string());
        } else if let Some(suffix) = key.strip_prefix(ROOT_LABEL) {
            dump.domain_suffix.push(suffix.to_string());
        } else {
            dump.domain.push(key);
        }
    }
    dump.domain.sort_unstable();
    dump.domain_suffix.sort_unstable();
    Ok(dump)
}

struct SuccinctSet {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
}

impl SuccinctSet {
    fn new(keys: &DomainMatcherKeys) -> Self {
        let mut leaves = Vec::with_capacity((keys.keys.len() / 64).saturating_add(1));
        let mut label_bitmap = Vec::with_capacity((keys.keys.len() / 32).saturating_add(1));
        let mut labels = Vec::with_capacity(keys.keys.len());
        let mut current = vec![QueueItem {
            start: 0,
            end: keys.keys.len() as u32,
            col: 0,
        }];
        let mut next = Vec::new();
        let mut node_id = 0usize;
        let mut label_index = 0usize;
        while !current.is_empty() {
            next.clear();
            for mut item in current.drain(..) {
                let start = item.start as usize;
                let end = item.end as usize;
                let col = item.col as usize;
                if col == keys.key_len(keys.keys[start]) {
                    item.start += 1;
                    set_bit(&mut leaves, node_id, 1);
                }

                let mut cursor = item.start as usize;
                while cursor < end {
                    let from = cursor;
                    while cursor < end
                        && keys.key_byte(keys.keys[cursor], col)
                            == keys.key_byte(keys.keys[from], col)
                    {
                        cursor += 1;
                    }
                    next.push(QueueItem {
                        start: from as u32,
                        end: cursor as u32,
                        col: item.col + 1,
                    });
                    labels.push(keys.key_byte(keys.keys[from], col));
                    set_bit(&mut label_bitmap, label_index, 0);
                    label_index += 1;
                }
                set_bit(&mut label_bitmap, label_index, 1);
                label_index += 1;
                node_id += 1;
            }
            std::mem::swap(&mut current, &mut next);
        }

        Self {
            leaves,
            label_bitmap,
            labels,
        }
    }

    fn keys(&self) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        if self.label_bitmap.is_empty() {
            return Ok(keys);
        }
        self.visit_keys(
            0,
            0,
            &mut Vec::new(),
            &LoudsIndex::new(&self.label_bitmap),
            &mut |key| {
                keys.push(String::from_utf8(key.to_vec()).context("invalid domain key in SRS")?);
                Ok(())
            },
        )?;
        Ok(keys)
    }

    fn visit_keys(
        &self,
        node_id: usize,
        bm_idx: usize,
        current: &mut Vec<u8>,
        index: &LoudsIndex,
        f: &mut impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
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
            self.visit_keys(next_node_id, next_bm_idx, current, index, f)?;
            current.pop();
            idx += 1;
        }
    }
}

#[derive(Clone, Copy)]
struct QueueItem {
    start: u32,
    end: u32,
    col: u32,
}

fn reverse_runes(value: &str) -> String {
    value.chars().rev().collect()
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
