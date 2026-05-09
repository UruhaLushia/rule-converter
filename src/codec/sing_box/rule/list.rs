use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};

use super::{RuleList, RuleTextRef};

impl RuleList {
    pub(crate) fn reserve(&mut self, items: usize, bytes: usize) {
        self.items.reserve(items);
        self.bytes.reserve(bytes);
    }

    pub(crate) fn push(&mut self, value: &str) {
        let offset = self.bytes.len();
        let len = value.len();
        assert!(
            offset <= u32::MAX as usize && len <= u32::MAX as usize,
            "sing-box rule store is too large"
        );
        self.bytes.extend_from_slice(value.as_bytes());
        self.items.push(RuleTextRef {
            offset: offset as u32,
            len: len as u32,
        });
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub(crate) fn clear(&mut self) {
        self.items.clear();
        self.bytes.clear();
    }

    pub(crate) fn iter(&self) -> RuleListIter<'_> {
        RuleListIter {
            list: self,
            index: 0,
        }
    }

    pub(crate) fn to_strings(&self) -> Vec<String> {
        self.iter().map(str::to_string).collect()
    }

    pub(crate) fn into_parts(self) -> (Vec<u8>, Vec<(u32, u32)>) {
        let items = self
            .items
            .into_iter()
            .map(|item| (item.offset, item.len))
            .collect();
        (self.bytes, items)
    }
}

pub(crate) struct RuleListIter<'a> {
    list: &'a RuleList,
    index: usize,
}

impl<'a> Iterator for RuleListIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        let item = *self.list.items.get(self.index)?;
        self.index += 1;
        let start = item.offset as usize;
        let end = start + item.len as usize;
        std::str::from_utf8(&self.list.bytes[start..end]).ok()
    }
}

impl Serialize for RuleList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        for value in self.iter() {
            seq.serialize_element(value)?;
        }
        seq.end()
    }
}
