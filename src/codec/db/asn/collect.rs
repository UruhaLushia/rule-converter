use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use maxminddb::{Reader, WithinOptions};

use crate::codec::mihomo::mrs::{IpCidrSetBuilder, RuleSetOutput};

use super::common::{decode_asn, normalize_asn_filter};
use super::{AsnCidrSet, AsnRuleSet};

pub fn collect_asn_mmdb_rule_set(input: impl AsRef<Path>, asns: &[u32]) -> Result<RuleSetOutput> {
    let input = input.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read ASN MMDB {}", input.display()))?;
    collect_asn_mmdb_reader_rule_set(reader, asns)
}

pub fn collect_asn_mmdb_rule_set_from_bytes(input: &[u8], asns: &[u32]) -> Result<RuleSetOutput> {
    let reader = Reader::from_source(input).context("failed to read ASN MMDB payload")?;
    collect_asn_mmdb_reader_rule_set(reader, asns)
}

fn collect_asn_mmdb_reader_rule_set<S: AsRef<[u8]>>(
    reader: Reader<S>,
    asns: &[u32],
) -> Result<RuleSetOutput> {
    let filter = normalize_asn_filter(asns);
    let mut builder = IpCidrSetBuilder::default();

    for item in reader.networks(WithinOptions::default())? {
        let item = item.context("failed to read ASN MMDB network")?;
        let Some(asn) = decode_asn(&item)? else {
            continue;
        };
        if filter.as_ref().is_some_and(|filter| !filter.contains(&asn)) {
            continue;
        }
        let network = item.network()?;
        builder.insert_prefix(network.ip(), network.prefix())?;
    }

    if builder.is_empty() {
        bail!("ASN input does not contain any ASN records");
    }
    Ok(RuleSetOutput::Ipcidr(builder.finish()?))
}

pub fn collect_asn_mmdb_rule_sets(
    input: impl AsRef<Path>,
    asns: &[u32],
) -> Result<Vec<AsnRuleSet>> {
    let input = input.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read ASN MMDB {}", input.display()))?;
    collect_asn_mmdb_reader_rule_sets(reader, asns)
}

pub fn collect_asn_mmdb_rule_sets_from_bytes(
    input: &[u8],
    asns: &[u32],
) -> Result<Vec<AsnRuleSet>> {
    let reader = Reader::from_source(input).context("failed to read ASN MMDB payload")?;
    collect_asn_mmdb_reader_rule_sets(reader, asns)
}

fn collect_asn_mmdb_reader_rule_sets<S: AsRef<[u8]>>(
    reader: Reader<S>,
    asns: &[u32],
) -> Result<Vec<AsnRuleSet>> {
    let filter = normalize_asn_filter(asns);
    let mut by_asn: BTreeMap<u32, IpCidrSetBuilder> = BTreeMap::new();

    for item in reader.networks(WithinOptions::default())? {
        let item = item.context("failed to read ASN MMDB network")?;
        let Some(asn) = decode_asn(&item)? else {
            continue;
        };
        if filter.as_ref().is_some_and(|filter| !filter.contains(&asn)) {
            continue;
        }
        let network = item.network()?;
        by_asn
            .entry(asn)
            .or_default()
            .insert_prefix(network.ip(), network.prefix())?;
    }

    by_asn
        .into_iter()
        .map(|(asn, builder)| {
            Ok(AsnRuleSet {
                asn,
                output: RuleSetOutput::Ipcidr(builder.finish()?),
            })
        })
        .collect()
}

pub fn list_asn_mmdb_asns(input: impl AsRef<Path>) -> Result<Vec<u32>> {
    let input = input.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read ASN MMDB {}", input.display()))?;
    list_asn_mmdb_asns_from_reader(reader)
}

pub fn list_asn_mmdb_asns_from_bytes(input: &[u8]) -> Result<Vec<u32>> {
    let reader = Reader::from_source(input).context("failed to read ASN MMDB payload")?;
    list_asn_mmdb_asns_from_reader(reader)
}

fn list_asn_mmdb_asns_from_reader<S: AsRef<[u8]>>(reader: Reader<S>) -> Result<Vec<u32>> {
    let mut asns = BTreeSet::new();

    for item in reader.networks(WithinOptions::default())? {
        let item = item.context("failed to read ASN MMDB network")?;
        if let Some(asn) = decode_asn(&item)? {
            asns.insert(asn);
        }
    }

    if asns.is_empty() {
        bail!("ASN input does not contain any ASN records");
    }
    Ok(asns.into_iter().collect())
}

pub fn collect_asn_mmdb_cidrs(input: impl AsRef<Path>, asns: &[u32]) -> Result<Vec<AsnCidrSet>> {
    let input = input.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read ASN MMDB {}", input.display()))?;
    let filter = normalize_asn_filter(asns);
    let mut by_asn: BTreeMap<u32, Vec<String>> = BTreeMap::new();

    for item in reader.networks(WithinOptions::default())? {
        let item = item.context("failed to read ASN MMDB network")?;
        let network = item.network()?.to_string();
        if let Some(asn) = decode_asn(&item)? {
            if filter.as_ref().is_some_and(|filter| !filter.contains(&asn)) {
                continue;
            }
            by_asn.entry(asn).or_default().push(network);
        }
    }

    let mut outputs = Vec::with_capacity(by_asn.len());
    for (asn, mut cidrs) in by_asn {
        cidrs.sort();
        cidrs.dedup();
        outputs.push(AsnCidrSet { asn, cidrs });
    }
    Ok(outputs)
}
