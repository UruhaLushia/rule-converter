#[derive(Clone, Debug, Default)]
pub struct RuleTextStore {
    bytes: Vec<u8>,
    items: Vec<RuleTextRef>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuleTextRef {
    offset: u32,
    len: u32,
}

impl RuleTextStore {
    pub fn push(&mut self, value: impl AsRef<str>) {
        let value = value.as_ref();
        let offset = self.bytes.len();
        let len = value.len();
        assert!(
            offset <= u32::MAX as usize && len <= u32::MAX as usize,
            "rule text store is too large"
        );
        self.bytes.extend_from_slice(value.as_bytes());
        self.items.push(RuleTextRef {
            offset: offset as u32,
            len: len as u32,
        });
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn iter(&self) -> RuleTextStoreIter<'_> {
        RuleTextStoreIter {
            store: self,
            index: 0,
        }
    }

    pub fn to_vec(&self) -> Vec<String> {
        self.iter().map(str::to_string).collect()
    }
}

impl PartialEq<Vec<&str>> for RuleTextStore {
    fn eq(&self, other: &Vec<&str>) -> bool {
        self.iter().eq(other.iter().copied())
    }
}

impl PartialEq<Vec<String>> for RuleTextStore {
    fn eq(&self, other: &Vec<String>) -> bool {
        self.iter().eq(other.iter().map(String::as_str))
    }
}

pub struct RuleTextStoreIter<'a> {
    store: &'a RuleTextStore,
    index: usize,
}

impl<'a> Iterator for RuleTextStoreIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        let item = *self.store.items.get(self.index)?;
        self.index += 1;
        let start = item.offset as usize;
        let end = start + item.len as usize;
        std::str::from_utf8(&self.store.bytes[start..end]).ok()
    }
}
