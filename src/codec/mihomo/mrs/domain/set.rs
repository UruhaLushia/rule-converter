use std::io::{self, Read, Write};

use super::io::{read_i64, read_u64_vec};
use super::louds::{LoudsIndex, get_bit};
use super::normalize::{reversed_key_to_rule_buf, reversed_key_to_rule_buf_prefixed};
use crate::codec::mihomo::mrs::{write_i64, write_u64_vec};

pub struct DomainSet {
    pub(super) count: usize,
    pub(super) has_suffix: bool,
    pub(super) leaves: Vec<u64>,
    pub(super) label_bitmap: Vec<u64>,
    pub(super) labels: Vec<u8>,
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

    pub fn contains_domain(&self, domain: &str) -> bool {
        let domain = domain.trim().trim_end_matches('.');
        if domain.is_empty() || domain.as_bytes().contains(&0) {
            return false;
        }
        let lower;
        let domain = if domain.bytes().any(|byte| byte.is_ascii_uppercase()) {
            lower = domain.to_ascii_lowercase();
            lower.as_str()
        } else {
            domain
        };
        if domain.split('.').any(str::is_empty) {
            return false;
        }

        let index = LoudsIndex::new(&self.label_bitmap);
        let mut reversed = Vec::with_capacity(domain.len());
        for ch in domain.chars().rev() {
            let mut buf = [0; 4];
            reversed.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
        }
        if self.contains_reversed_key(&reversed, &index) {
            return true;
        }

        let mut suffix = domain;
        while let Some((_, parent)) = suffix.split_once('.') {
            suffix = parent;
            reversed.clear();
            for ch in suffix.chars().rev() {
                let mut buf = [0; 4];
                reversed.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
            if self.contains_reversed_key_with_suffix(&reversed, b".+", &index) {
                return true;
            }
        }
        false
    }

    pub fn for_each_rule(&self, mut f: impl FnMut(&str) -> io::Result<()>) -> io::Result<()> {
        if !self.has_suffix {
            return self.for_each_raw_rule(f);
        }

        let index = LoudsIndex::new(&self.label_bitmap);
        let mut rule = String::new();
        self.visit_reversed_keys(&mut Vec::new(), &mut |reversed| {
            if let Some(suffix_reversed) = reversed.strip_suffix(b".+") {
                if self.contains_reversed_key(suffix_reversed, &index) {
                    if !reversed_key_to_rule_buf_prefixed(suffix_reversed, "+.", &mut rule) {
                        return Ok(());
                    }
                } else {
                    if !reversed_key_to_rule_buf_prefixed(suffix_reversed, ".", &mut rule) {
                        return Ok(());
                    }
                }
                f(&rule)?;
            } else {
                if self.contains_reversed_key_with_suffix(reversed, b".+", &index) {
                    return Ok(());
                }
                if !reversed_key_to_rule_buf(reversed, &mut rule) {
                    return Ok(());
                }
                f(&rule)?;
            }
            Ok(())
        })
    }

    pub fn for_each_exact_rule(&self, mut f: impl FnMut(&str) -> io::Result<()>) -> io::Result<()> {
        if !self.has_suffix {
            return self.for_each_raw_rule(f);
        }

        let index = LoudsIndex::new(&self.label_bitmap);
        let mut rule = String::new();
        self.visit_reversed_keys(&mut Vec::new(), &mut |reversed| {
            if reversed.ends_with(b".+") {
                return Ok(());
            }
            if self.contains_reversed_key_with_suffix(reversed, b".+", &index) {
                return Ok(());
            }
            if !reversed_key_to_rule_buf(reversed, &mut rule) {
                return Ok(());
            }
            f(&rule)?;
            Ok(())
        })
    }

    pub fn for_each_suffix_rule(
        &self,
        mut f: impl FnMut(&str) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut rule = String::new();
        self.visit_reversed_keys(&mut Vec::new(), &mut |reversed| {
            if let Some(reversed) = reversed.strip_suffix(b".+") {
                if !reversed_key_to_rule_buf(reversed, &mut rule) {
                    return Ok(());
                }
                f(&rule)?;
            }
            Ok(())
        })
    }

    fn for_each_raw_rule(&self, mut f: impl FnMut(&str) -> io::Result<()>) -> io::Result<()> {
        let mut rule = String::new();
        self.visit_reversed_keys(&mut Vec::new(), &mut |reversed| {
            if !reversed_key_to_rule_buf(reversed, &mut rule) {
                return Ok(());
            };
            f(&rule)
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
        self.contains_reversed_key_with_suffix(key, b"", index)
    }

    fn contains_reversed_key_with_suffix(
        &self,
        key: &[u8],
        suffix: &[u8],
        index: &LoudsIndex<'_>,
    ) -> bool {
        let mut node_id = 0usize;
        let mut bm_idx = 0usize;

        for byte in key.iter().chain(suffix) {
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
