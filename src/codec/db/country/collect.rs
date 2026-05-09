use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, bail};
use maxminddb::{Reader, WithinOptions};

use crate::codec::mihomo::mrs::{IpCidrSetBuilder, RuleSetOutput};

use super::common::{
    decode_country_codes, filter_matches, geoip_item_matches_filter, normalize_country_code,
    normalize_country_filter,
};
use super::{GeoipCidrSet, GeoipRuleSet};

pub fn collect_geoip_mmdb_rule_set(
    input: impl AsRef<Path>,
    countries: &[String],
) -> Result<RuleSetOutput> {
    let input = input.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read GeoIP MMDB {}", input.display()))?;
    collect_geoip_mmdb_reader_rule_set(reader, countries)
}

pub fn collect_geoip_mmdb_rule_set_from_bytes(
    input: &[u8],
    countries: &[String],
) -> Result<RuleSetOutput> {
    let reader = Reader::from_source(input).context("failed to read GeoIP MMDB payload")?;
    collect_geoip_mmdb_reader_rule_set(reader, countries)
}

fn collect_geoip_mmdb_reader_rule_set<S: AsRef<[u8]>>(
    reader: Reader<S>,
    countries: &[String],
) -> Result<RuleSetOutput> {
    let filter = normalize_country_filter(countries);
    let mut builder = IpCidrSetBuilder::default();

    for item in reader.networks(WithinOptions::default())? {
        let item = item.context("failed to read GeoIP MMDB network")?;
        if !geoip_item_matches_filter(&item, &filter)? {
            continue;
        }
        let network = item.network()?;
        builder.insert_prefix(network.ip(), network.prefix())?;
    }

    if builder.is_empty() {
        bail!("GeoIP input does not contain any country records");
    }
    Ok(RuleSetOutput::Ipcidr(builder.finish()?))
}

pub fn collect_geoip_mmdb_rule_sets(
    input: impl AsRef<Path>,
    countries: &[String],
) -> Result<Vec<GeoipRuleSet>> {
    let input = input.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read GeoIP MMDB {}", input.display()))?;
    collect_geoip_mmdb_reader_rule_sets(reader, countries)
}

pub fn collect_geoip_mmdb_rule_sets_from_bytes(
    input: &[u8],
    countries: &[String],
) -> Result<Vec<GeoipRuleSet>> {
    let reader = Reader::from_source(input).context("failed to read GeoIP MMDB payload")?;
    collect_geoip_mmdb_reader_rule_sets(reader, countries)
}

fn collect_geoip_mmdb_reader_rule_sets<S: AsRef<[u8]>>(
    reader: Reader<S>,
    countries: &[String],
) -> Result<Vec<GeoipRuleSet>> {
    let filter = normalize_country_filter(countries);
    let mut by_country: BTreeMap<String, IpCidrSetBuilder> = BTreeMap::new();

    for item in reader.networks(WithinOptions::default())? {
        let item = item.context("failed to read GeoIP MMDB network")?;
        let network = item.network()?;
        for country in decode_country_codes(&item)? {
            let country = normalize_country_code(&country);
            if country.is_empty() || !filter_matches(&filter, &country) {
                continue;
            }
            by_country
                .entry(country)
                .or_default()
                .insert_prefix(network.ip(), network.prefix())?;
        }
    }

    by_country
        .into_iter()
        .map(|(country, builder)| {
            Ok(GeoipRuleSet {
                country,
                output: RuleSetOutput::Ipcidr(builder.finish()?),
            })
        })
        .collect()
}

pub fn list_geoip_mmdb_countries(input: impl AsRef<Path>) -> Result<Vec<String>> {
    let input = input.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read GeoIP MMDB {}", input.display()))?;
    list_geoip_mmdb_countries_from_reader(reader)
}

pub fn list_geoip_mmdb_countries_from_bytes(input: &[u8]) -> Result<Vec<String>> {
    let reader = Reader::from_source(input).context("failed to read GeoIP MMDB payload")?;
    list_geoip_mmdb_countries_from_reader(reader)
}

fn list_geoip_mmdb_countries_from_reader<S: AsRef<[u8]>>(reader: Reader<S>) -> Result<Vec<String>> {
    let mut countries = BTreeSet::new();

    for item in reader.networks(WithinOptions::default())? {
        let item = item.context("failed to read GeoIP MMDB network")?;
        for country in decode_country_codes(&item)? {
            let country = normalize_country_code(&country);
            if !country.is_empty() {
                countries.insert(country);
            }
        }
    }

    if countries.is_empty() {
        bail!("GeoIP input does not contain any country records");
    }
    Ok(countries.into_iter().collect())
}

pub fn collect_geoip_mmdb_cidrs(
    input: impl AsRef<Path>,
    countries: &[String],
) -> Result<Vec<GeoipCidrSet>> {
    let input = input.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read GeoIP MMDB {}", input.display()))?;
    let filter = normalize_country_filter(countries);
    let mut by_country: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for item in reader.networks(WithinOptions::default())? {
        let item = item.context("failed to read GeoIP MMDB network")?;
        let network = item.network()?.to_string();
        for country in decode_country_codes(&item)? {
            let country = normalize_country_code(&country);
            if country.is_empty() || !filter_matches(&filter, &country) {
                continue;
            }
            by_country.entry(country).or_default().push(network.clone());
        }
    }

    let mut outputs = Vec::with_capacity(by_country.len());
    for (country, mut cidrs) in by_country {
        cidrs.sort();
        cidrs.dedup();
        outputs.push(GeoipCidrSet { country, cidrs });
    }
    Ok(outputs)
}
