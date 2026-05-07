use serde::ser::SerializeSeq;
use serde::{Deserialize, Serialize, Serializer};

use crate::codec::mihomo::mrs::RuleSetOutput;
use crate::rules::{BehaviorMode, ClassicalKind, ClassicalRule, RuleTextStore};

pub const VERSION_CURRENT: u8 = 5;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RuleSet {
    #[serde(default = "default_version")]
    pub version: u8,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Clone, Debug, Default)]
pub struct RuleStore {
    pub(crate) domain: RuleList,
    pub(crate) domain_suffix: RuleList,
    pub(crate) domain_keyword: RuleList,
    pub(crate) domain_regex: RuleList,
    pub(crate) source_ip_cidr: RuleList,
    pub(crate) ip_cidr: RuleList,
    pub(crate) network: RuleList,
    pub(crate) source_port_range: RuleList,
    pub(crate) port_range: RuleList,
    pub(crate) process_name: RuleList,
    pub(crate) process_path: RuleList,
    pub(crate) process_path_regex: RuleList,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RuleList {
    bytes: Vec<u8>,
    items: Vec<RuleTextRef>,
}

#[derive(Clone, Copy, Debug)]
struct RuleTextRef {
    offset: u32,
    len: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Rule {
    #[serde(rename = "type", default, skip_serializing_if = "String::is_empty")]
    pub rule_type: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub domain: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub domain_suffix: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub domain_keyword: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub domain_regex: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub source_ip_cidr: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub ip_cidr: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub network: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub source_port_range: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub port_range: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub process_name: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub process_path: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub process_path_regex: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub package_name: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "string_list")]
    pub package_name_regex: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub invert: bool,
}

fn default_version() -> u8 {
    VERSION_CURRENT
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl RuleSet {
    pub fn from_outputs(
        outputs: &[RuleSetOutput],
        mixed_rules: &RuleTextStore,
        _behavior: BehaviorMode,
    ) -> Self {
        let mut rules = Vec::new();
        if !mixed_rules.is_empty() {
            for rule in mixed_rules.iter() {
                if let Some(rule) = Rule::from_classical(rule) {
                    rules.push(rule);
                }
            }
        }

        if rules.is_empty() {
            for output in outputs {
                match output {
                    RuleSetOutput::Domain(domain) => {
                        let mut rule = Rule::default();
                        let _ = domain.for_each_exact_rule(|value| {
                            rule.domain.push(value.to_string());
                            Ok(())
                        });
                        let _ = domain.for_each_suffix_rule(|value| {
                            rule.domain_suffix.push(sing_box_domain_suffix(value));
                            Ok(())
                        });
                        if !rule.is_empty() {
                            rules.push(rule);
                        }
                    }
                    RuleSetOutput::Ipcidr(ipcidr) => {
                        let mut rule = Rule::default();
                        let _ = ipcidr.for_each_rule(|value| {
                            rule.ip_cidr.push(value.to_string());
                            Ok(())
                        });
                        if !rule.is_empty() {
                            rules.push(rule);
                        }
                    }
                }
            }
        }

        Self {
            version: VERSION_CURRENT,
            rules,
        }
    }

    pub fn to_classical_rules(&self) -> Vec<String> {
        let mut out = Vec::new();
        for rule in &self.rules {
            rule.push_classical_rules(&mut out);
        }
        out
    }

    pub fn count(&self) -> usize {
        self.rules.iter().map(Rule::item_count).sum()
    }
}

impl RuleList {
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

    pub(crate) fn shrink_to_fit(&mut self) {
        self.items.shrink_to_fit();
        self.bytes.shrink_to_fit();
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

impl RuleStore {
    pub fn push_classical(&mut self, rule: &str) -> bool {
        if self.push_fast_classical(rule) {
            return true;
        }

        let Some(parsed) = ClassicalRule::parse(rule).ok() else {
            return false;
        };
        let payload = parsed.payload.unwrap_or_default();
        match parsed.kind {
            ClassicalKind::Domain => self.domain.push(payload),
            ClassicalKind::DomainSuffix => self.domain_suffix.push(payload),
            ClassicalKind::DomainKeyword => self.domain_keyword.push(payload),
            ClassicalKind::DomainRegex => self.domain_regex.push(payload),
            ClassicalKind::Ipcidr => self.ip_cidr.push(payload),
            ClassicalKind::SrcIpcidr | ClassicalKind::SrcIp => self.source_ip_cidr.push(payload),
            ClassicalKind::Network => self.network.push(payload),
            ClassicalKind::DstPort => self.port_range.push(payload),
            ClassicalKind::SrcPort => self.source_port_range.push(payload),
            ClassicalKind::ProcessName => self.process_name.push(payload),
            ClassicalKind::ProcessPath => self.process_path.push(payload),
            ClassicalKind::ProcessPathRegex => self.process_path_regex.push(payload),
            _ => return false,
        }
        true
    }

    fn push_fast_classical(&mut self, rule: &str) -> bool {
        let Some((kind, rest)) = rule.split_once(',') else {
            return false;
        };
        let payload = rest
            .split_once(',')
            .map_or(rest, |(payload, _)| payload)
            .trim();
        if payload.is_empty() {
            return false;
        }

        if kind.eq_ignore_ascii_case("DOMAIN") {
            self.domain.push(payload);
        } else if kind.eq_ignore_ascii_case("DOMAIN-SUFFIX") {
            self.domain_suffix.push(payload);
        } else if kind.eq_ignore_ascii_case("DOMAIN-KEYWORD") {
            self.domain_keyword.push(payload);
        } else if kind.eq_ignore_ascii_case("DOMAIN-REGEX") {
            self.domain_regex.push(payload);
        } else if kind.eq_ignore_ascii_case("IP-CIDR") || kind.eq_ignore_ascii_case("IP-CIDR6") {
            self.ip_cidr.push(payload);
        } else if kind.eq_ignore_ascii_case("SRC-IP-CIDR") || kind.eq_ignore_ascii_case("SRC-IP") {
            self.source_ip_cidr.push(payload);
        } else if kind.eq_ignore_ascii_case("NETWORK") {
            self.network.push(payload);
        } else if kind.eq_ignore_ascii_case("DST-PORT") || kind.eq_ignore_ascii_case("DEST-PORT") {
            self.port_range.push(payload);
        } else if kind.eq_ignore_ascii_case("SRC-PORT") {
            self.source_port_range.push(payload);
        } else if kind.eq_ignore_ascii_case("PROCESS-NAME") {
            self.process_name.push(payload);
        } else if kind.eq_ignore_ascii_case("PROCESS-PATH") {
            self.process_path.push(payload);
        } else if kind.eq_ignore_ascii_case("PROCESS-PATH-REGEX") {
            self.process_path_regex.push(payload);
        } else {
            return false;
        }
        true
    }

    pub fn push_domain(&mut self, value: impl AsRef<str>) {
        self.domain.push(value.as_ref());
    }

    pub fn push_domain_suffix(&mut self, value: impl AsRef<str>) {
        self.domain_suffix.push(value.as_ref());
    }

    pub fn push_ip_cidr(&mut self, value: impl AsRef<str>) {
        self.ip_cidr.push(value.as_ref());
    }

    pub fn is_empty(&self) -> bool {
        self.count() == 0
    }

    pub fn count(&self) -> usize {
        self.domain.len()
            + self.domain_suffix.len()
            + self.domain_keyword.len()
            + self.domain_regex.len()
            + self.source_ip_cidr.len()
            + self.ip_cidr.len()
            + self.network.len()
            + self.source_port_range.len()
            + self.port_range.len()
            + self.process_name.len()
            + self.process_path.len()
            + self.process_path_regex.len()
    }

    pub fn rule_count(&self) -> usize {
        usize::from(!self.domain.is_empty() || !self.domain_suffix.is_empty())
            + usize::from(!self.domain_keyword.is_empty())
            + usize::from(!self.domain_regex.is_empty())
            + usize::from(!self.source_ip_cidr.is_empty())
            + usize::from(!self.ip_cidr.is_empty())
            + usize::from(!self.network.is_empty())
            + usize::from(!self.source_port_range.is_empty())
            + usize::from(!self.port_range.is_empty())
            + usize::from(!self.process_name.is_empty())
            + usize::from(!self.process_path.is_empty())
            + usize::from(!self.process_path_regex.is_empty())
    }

    pub fn to_rule_set(&self) -> RuleSet {
        let mut rules = Vec::with_capacity(self.rule_count());
        push_rule(&mut rules, |rule| {
            rule.domain = self.domain.to_strings();
            rule.domain_suffix = self.domain_suffix.to_strings();
        });
        push_rule(&mut rules, |rule| {
            rule.domain_keyword = self.domain_keyword.to_strings()
        });
        push_rule(&mut rules, |rule| {
            rule.domain_regex = self.domain_regex.to_strings()
        });
        push_rule(&mut rules, |rule| {
            rule.source_ip_cidr = self.source_ip_cidr.to_strings()
        });
        push_rule(&mut rules, |rule| rule.ip_cidr = self.ip_cidr.to_strings());
        push_rule(&mut rules, |rule| rule.network = self.network.to_strings());
        push_rule(&mut rules, |rule| {
            rule.source_port_range = self.source_port_range.to_strings()
        });
        push_rule(&mut rules, |rule| {
            rule.port_range = self.port_range.to_strings()
        });
        push_rule(&mut rules, |rule| {
            rule.process_name = self.process_name.to_strings()
        });
        push_rule(&mut rules, |rule| {
            rule.process_path = self.process_path.to_strings()
        });
        push_rule(&mut rules, |rule| {
            rule.process_path_regex = self.process_path_regex.to_strings()
        });

        RuleSet {
            version: VERSION_CURRENT,
            rules,
        }
    }
}

fn push_rule(rules: &mut Vec<Rule>, f: impl FnOnce(&mut Rule)) {
    let mut rule = Rule::default();
    f(&mut rule);
    if !rule.is_empty() {
        rules.push(rule);
    }
}

impl Rule {
    pub fn from_classical(rule: &str) -> Option<Self> {
        let parsed = ClassicalRule::parse(rule).ok()?;
        let payload = parsed.payload.unwrap_or_default();
        let mut out = Rule::default();
        match parsed.kind {
            ClassicalKind::Domain => out.domain.push(payload.into()),
            ClassicalKind::DomainSuffix => out.domain_suffix.push(payload.into()),
            ClassicalKind::DomainKeyword => out.domain_keyword.push(payload.into()),
            ClassicalKind::DomainRegex => out.domain_regex.push(payload.into()),
            ClassicalKind::Ipcidr => out.ip_cidr.push(payload.into()),
            ClassicalKind::SrcIpcidr | ClassicalKind::SrcIp => {
                out.source_ip_cidr.push(payload.into())
            }
            ClassicalKind::Network => out.network.push(payload.into()),
            ClassicalKind::DstPort => out.port_range.push(payload.into()),
            ClassicalKind::SrcPort => out.source_port_range.push(payload.into()),
            ClassicalKind::ProcessName => out.process_name.push(payload.into()),
            ClassicalKind::ProcessPath => out.process_path.push(payload.into()),
            ClassicalKind::ProcessPathRegex => out.process_path_regex.push(payload.into()),
            _ => return None,
        }
        Some(out)
    }

    pub fn is_empty(&self) -> bool {
        self.item_count() == 0
    }

    pub fn item_count(&self) -> usize {
        self.domain.len()
            + self.domain_suffix.len()
            + self.domain_keyword.len()
            + self.domain_regex.len()
            + self.source_ip_cidr.len()
            + self.ip_cidr.len()
            + self.network.len()
            + self.source_port_range.len()
            + self.port_range.len()
            + self.process_name.len()
            + self.process_path.len()
            + self.process_path_regex.len()
            + self.package_name.len()
            + self.package_name_regex.len()
    }

    fn push_classical_rules(&self, out: &mut Vec<String>) {
        extend_prefixed(out, "DOMAIN", &self.domain);
        extend_prefixed(out, "DOMAIN-SUFFIX", &self.domain_suffix);
        extend_prefixed(out, "DOMAIN-KEYWORD", &self.domain_keyword);
        extend_prefixed(out, "DOMAIN-REGEX", &self.domain_regex);
        extend_prefixed(out, "SRC-IP-CIDR", &self.source_ip_cidr);
        extend_prefixed(out, "IP-CIDR", &self.ip_cidr);
        extend_prefixed(out, "NETWORK", &self.network);
        extend_prefixed(out, "SRC-PORT", &self.source_port_range);
        extend_prefixed(out, "DST-PORT", &self.port_range);
        extend_prefixed(out, "PROCESS-NAME", &self.process_name);
        extend_prefixed(out, "PROCESS-PATH", &self.process_path);
        extend_prefixed(out, "PROCESS-PATH-REGEX", &self.process_path_regex);
        extend_prefixed(out, "PROCESS-NAME", &self.package_name);
        extend_prefixed(out, "PROCESS-NAME-REGEX", &self.package_name_regex);
    }
}

pub fn sing_box_domain_suffix(rule: &str) -> String {
    if let Some(suffix) = rule.strip_prefix("+.") {
        suffix.to_string()
    } else if rule.starts_with('.') {
        rule.to_string()
    } else {
        rule.to_string()
    }
}

fn extend_prefixed(out: &mut Vec<String>, kind: &str, values: &[String]) {
    out.extend(values.iter().map(|value| format!("{kind},{value}")));
}

mod string_list {
    use serde::de::{Error, Visitor};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(values: &[String], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        values.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StringListVisitor)
    }

    struct StringListVisitor;

    impl<'de> Visitor<'de> for StringListVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a string or a list of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            Ok(vec![value.to_string()])
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: Error,
        {
            Ok(vec![value])
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while let Some(value) = seq.next_element::<String>()? {
                values.push(value);
            }
            Ok(values)
        }
    }

    use serde::Serialize;
}
