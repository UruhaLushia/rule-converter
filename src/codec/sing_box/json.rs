use std::io::Write;

use anyhow::{Context, Result};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};

use super::rule::VERSION_CURRENT;
use super::{RuleSet, RuleStore};

pub fn parse_json(raw: &[u8]) -> Result<Vec<String>> {
    let rule_set = read_json(raw)?;
    Ok(rule_set.to_classical_rules())
}

pub fn read_json(raw: &[u8]) -> Result<RuleSet> {
    serde_json::from_slice(raw).context("failed to parse sing-box rule-set JSON")
}

pub fn write_json<W: Write>(writer: W, rule_set: &RuleSet) -> Result<()> {
    serde_json::to_writer_pretty(writer, rule_set).context("failed to write sing-box JSON")
}

pub fn write_store_json<W: Write>(writer: W, store: &RuleStore) -> Result<()> {
    let rule_set = StoreRuleSet { store };
    serde_json::to_writer_pretty(writer, &rule_set).context("failed to write sing-box JSON")
}

struct StoreRuleSet<'a> {
    store: &'a RuleStore,
}

impl Serialize for StoreRuleSet<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("version", &VERSION_CURRENT)?;
        map.serialize_entry("rules", &StoreRules(self.store))?;
        map.end()
    }
}

struct StoreRules<'a>(&'a RuleStore);

impl Serialize for StoreRules<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let store = self.0;
        let mut seq = serializer.serialize_seq(Some(store.rule_count()))?;

        if !store.domain.is_empty() || !store.domain_suffix.is_empty() {
            seq.serialize_element(&StoreRule::Domain(store))?;
        }
        if !store.domain_keyword.is_empty() {
            seq.serialize_element(&StoreRule::DomainKeyword(store))?;
        }
        if !store.domain_regex.is_empty() {
            seq.serialize_element(&StoreRule::DomainRegex(store))?;
        }
        if !store.source_ip_cidr.is_empty() {
            seq.serialize_element(&StoreRule::SourceIpCidr(store))?;
        }
        if !store.ip_cidr.is_empty() {
            seq.serialize_element(&StoreRule::IpCidr(store))?;
        }
        if !store.network.is_empty() {
            seq.serialize_element(&StoreRule::Network(store))?;
        }
        if !store.source_port_range.is_empty() {
            seq.serialize_element(&StoreRule::SourcePortRange(store))?;
        }
        if !store.port_range.is_empty() {
            seq.serialize_element(&StoreRule::PortRange(store))?;
        }
        if !store.process_name.is_empty() {
            seq.serialize_element(&StoreRule::ProcessName(store))?;
        }
        if !store.process_path.is_empty() {
            seq.serialize_element(&StoreRule::ProcessPath(store))?;
        }
        if !store.process_path_regex.is_empty() {
            seq.serialize_element(&StoreRule::ProcessPathRegex(store))?;
        }

        seq.end()
    }
}

enum StoreRule<'a> {
    Domain(&'a RuleStore),
    DomainKeyword(&'a RuleStore),
    DomainRegex(&'a RuleStore),
    SourceIpCidr(&'a RuleStore),
    IpCidr(&'a RuleStore),
    Network(&'a RuleStore),
    SourcePortRange(&'a RuleStore),
    PortRange(&'a RuleStore),
    ProcessName(&'a RuleStore),
    ProcessPath(&'a RuleStore),
    ProcessPathRegex(&'a RuleStore),
}

impl Serialize for StoreRule<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        match self {
            StoreRule::Domain(store) => {
                if !store.domain.is_empty() {
                    map.serialize_entry("domain", &store.domain)?;
                }
                if !store.domain_suffix.is_empty() {
                    map.serialize_entry("domain_suffix", &store.domain_suffix)?;
                }
            }
            StoreRule::DomainKeyword(store) => {
                map.serialize_entry("domain_keyword", &store.domain_keyword)?;
            }
            StoreRule::DomainRegex(store) => {
                map.serialize_entry("domain_regex", &store.domain_regex)?;
            }
            StoreRule::SourceIpCidr(store) => {
                map.serialize_entry("source_ip_cidr", &store.source_ip_cidr)?;
            }
            StoreRule::IpCidr(store) => {
                map.serialize_entry("ip_cidr", &store.ip_cidr)?;
            }
            StoreRule::Network(store) => {
                map.serialize_entry("network", &store.network)?;
            }
            StoreRule::SourcePortRange(store) => {
                map.serialize_entry("source_port_range", &store.source_port_range)?;
            }
            StoreRule::PortRange(store) => {
                map.serialize_entry("port_range", &store.port_range)?;
            }
            StoreRule::ProcessName(store) => {
                map.serialize_entry("process_name", &store.process_name)?;
            }
            StoreRule::ProcessPath(store) => {
                map.serialize_entry("process_path", &store.process_path)?;
            }
            StoreRule::ProcessPathRegex(store) => {
                map.serialize_entry("process_path_regex", &store.process_path_regex)?;
            }
        }
        map.end()
    }
}
