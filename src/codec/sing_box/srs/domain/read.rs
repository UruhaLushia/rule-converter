use std::io::Read;

use anyhow::Result;

use super::succinct::SuccinctSet;
use super::{PREFIX_LABEL, ROOT_LABEL};
use crate::codec::sing_box::srs::binary::{read_byte, read_u64_vec, read_uvarint};

#[derive(Default)]
pub(in crate::codec::sing_box::srs) struct DomainMatcherDump {
    pub(in crate::codec::sing_box::srs) domain: Vec<String>,
    pub(in crate::codec::sing_box::srs) domain_suffix: Vec<String>,
}

pub(in crate::codec::sing_box::srs) fn read_domain_matcher<R: Read>(
    reader: &mut R,
) -> Result<DomainMatcherDump> {
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

fn reverse_runes(value: &str) -> String {
    value.chars().rev().collect()
}
