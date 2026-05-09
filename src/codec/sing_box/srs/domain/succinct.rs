use anyhow::{Context, Result};

use super::keys::{DomainMatcherKeys, key_byte, pack_range, unpack_range};
use super::louds::{LoudsIndex, get_bit, set_bit};

pub(super) struct SuccinctSet {
    pub(super) leaves: Vec<u64>,
    pub(super) label_bitmap: Vec<u64>,
    pub(super) labels: Vec<u8>,
}

impl SuccinctSet {
    pub(super) fn new(keys: &mut DomainMatcherKeys) -> Result<Self> {
        let key_refs = std::mem::take(&mut keys.keys);
        let offsets: Vec<u32> = key_refs.iter().map(|key| key.offset).collect();
        drop(key_refs);
        let bytes = &keys.bytes;
        let mut leaves = Vec::with_capacity((offsets.len() / 64).saturating_add(1));
        let mut label_bitmap = Vec::with_capacity((offsets.len() / 32).saturating_add(1));
        let mut labels = Vec::with_capacity(offsets.len());
        let mut current = vec![pack_range(0, offsets.len())?];
        let mut next = Vec::new();
        let mut node_id = 0usize;
        let mut label_index = 0usize;
        let mut depth = 0usize;
        while !current.is_empty() {
            next.clear();
            for range in current.drain(..) {
                let (mut start, end) = unpack_range(range);
                if key_byte(bytes, offsets[start], depth) == 0 {
                    start += 1;
                    set_bit(&mut leaves, node_id, 1);
                }

                let mut cursor = start;
                while cursor < end {
                    let from = cursor;
                    while cursor < end
                        && key_byte(bytes, offsets[cursor], depth)
                            == key_byte(bytes, offsets[from], depth)
                    {
                        cursor += 1;
                    }
                    next.push(pack_range(from, cursor)?);
                    labels.push(key_byte(bytes, offsets[from], depth));
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

        Ok(Self {
            leaves,
            label_bitmap,
            labels,
        })
    }

    pub(super) fn keys(&self) -> Result<Vec<String>> {
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
