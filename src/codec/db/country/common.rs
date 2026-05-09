use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Result, bail};
use maxminddb::geoip2;
use serde::{Deserialize, Serialize};

pub(super) fn decode_country_codes<S: AsRef<[u8]>>(
    item: &maxminddb::LookupResult<'_, S>,
) -> Result<Vec<String>> {
    if let Some(value) = item.decode::<String>().ok().flatten() {
        return Ok(vec![value]);
    }
    if let Some(value) = item.decode::<Vec<String>>().ok().flatten() {
        return Ok(value);
    }
    if let Some(value) = item.decode::<geoip2::Country<'_>>()?
        && let Some(code) = value.country.iso_code
    {
        return Ok(vec![code.to_string()]);
    }
    if let Some(value) = item.decode::<CountryRecord<'_>>().ok().flatten()
        && let Some(code) = value.country.and_then(|country| country.iso_code)
    {
        return Ok(vec![code.to_string()]);
    }
    Ok(Vec::new())
}

pub(super) fn decode_first_matching_country_code<S: AsRef<[u8]>>(
    item: &maxminddb::LookupResult<'_, S>,
    filter: &Option<BTreeSet<String>>,
) -> Result<Option<String>> {
    Ok(decode_matching_country_codes(item, filter)?
        .into_iter()
        .next())
}

pub(super) fn decode_matching_country_codes<S: AsRef<[u8]>>(
    item: &maxminddb::LookupResult<'_, S>,
    filter: &Option<BTreeSet<String>>,
) -> Result<Vec<String>> {
    Ok(decode_country_codes(item)?
        .into_iter()
        .map(|country| normalize_country_code(&country))
        .filter(|country| !country.is_empty() && filter_matches(filter, country))
        .collect())
}

#[derive(Deserialize)]
struct CountryRecord<'a> {
    #[serde(borrow)]
    country: Option<CountryCode<'a>>,
}

#[derive(Deserialize)]
struct CountryCode<'a> {
    iso_code: Option<&'a str>,
}

#[derive(Serialize)]
pub(super) struct CountryRecordValue<'a> {
    pub(super) country: CountryCodeValue<'a>,
}

#[derive(Serialize)]
pub(super) struct CountryCodeValue<'a> {
    pub(super) iso_code: &'a str,
}

pub(super) fn country_from_path(path: &Path) -> Result<String> {
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow::anyhow!("GeoIP path must have a UTF-8 file name"))?;
    let country = normalize_country_code(stem);
    if country.is_empty() {
        bail!("GeoIP country file name is empty");
    }
    Ok(country)
}

pub(super) fn normalize_country_filter(countries: &[String]) -> Option<BTreeSet<String>> {
    if countries.is_empty() {
        return None;
    }
    let values = countries
        .iter()
        .map(|value| normalize_country_code(value))
        .filter(|value| !value.is_empty())
        .collect();
    Some(values)
}

pub(super) fn filter_matches(filter: &Option<BTreeSet<String>>, country: &str) -> bool {
    filter
        .as_ref()
        .is_none_or(|filter| filter.contains(country))
}

pub(super) fn geoip_item_matches_filter<S: AsRef<[u8]>>(
    item: &maxminddb::LookupResult<'_, S>,
    filter: &Option<BTreeSet<String>>,
) -> Result<bool> {
    let countries = decode_country_codes(item)?;
    Ok(countries.into_iter().any(|country| {
        let country = normalize_country_code(&country);
        !country.is_empty() && filter_matches(filter, &country)
    }))
}

pub(super) fn normalize_country_code(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}
