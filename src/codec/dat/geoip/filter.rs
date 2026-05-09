#[cfg(not(target_arch = "wasm32"))]
use std::fs::{self, File};
#[cfg(not(target_arch = "wasm32"))]
use std::io::{BufReader, BufWriter, Read, Write};
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

use anyhow::{Result, bail};

use crate::codec::dat::proto::write_raw_message_field;
#[cfg(not(target_arch = "wasm32"))]
use crate::codec::dat::proto::{
    for_each_raw_message_field_from_reader, write_raw_message_field_to_writer,
};

use super::scan::{for_each_raw_geoip_entry, scan_geoip_entry_meta};

pub fn filter_geoip_dat(input: &[u8], countries: &[String]) -> Result<(usize, Vec<u8>)> {
    let filter = normalize_country_filter(countries);
    let mut count = 0usize;
    let mut output = Vec::new();
    for_each_raw_geoip_entry(input, |raw| {
        let meta = scan_geoip_entry_meta(raw)?;
        if !meta.reverse_match && matches_normalized_country(&meta.country, &filter) {
            count += meta.cidr_count;
            write_raw_message_field(&mut output, 1, raw)?;
        }
        Ok(())
    })?;
    if count == 0 {
        bail!("geoip dat input does not contain any matching records");
    }
    Ok((count, output))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn filter_geoip_dat_to_path(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    countries: &[String],
) -> Result<usize> {
    let input = input.as_ref();
    let output = output.as_ref();
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let reader = BufReader::new(File::open(input)?);
    let writer = BufWriter::new(File::create(output)?);
    filter_geoip_dat_to_writer(reader, writer, countries)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn filter_geoip_dat_to_writer<R: Read, W: Write>(
    reader: R,
    mut writer: W,
    countries: &[String],
) -> Result<usize> {
    let filter = normalize_country_filter(countries);
    let mut count = 0usize;
    for_each_raw_message_field_from_reader(reader, 1, "V2Ray geoip dat", |raw| {
        let meta = scan_geoip_entry_meta(raw)?;
        if !meta.reverse_match && matches_normalized_country(&meta.country, &filter) {
            count += meta.cidr_count;
            write_raw_message_field_to_writer(&mut writer, 1, raw)?;
        }
        Ok(())
    })?;
    if count == 0 {
        bail!("geoip dat input does not contain any matching records");
    }
    Ok(count)
}

pub(super) fn normalize_country_filter(countries: &[String]) -> Option<Vec<String>> {
    if countries.is_empty() {
        return None;
    }
    Some(
        countries
            .iter()
            .map(|country| normalize_country_code(country))
            .filter(|country| !country.is_empty())
            .collect(),
    )
}

pub(super) fn normalize_country_code(country: &str) -> String {
    country.trim().to_ascii_uppercase()
}

pub(super) fn matches_country(country: &str, filter: &Option<Vec<String>>) -> bool {
    let country = normalize_country_code(country);
    matches_normalized_country(&country, filter)
}

pub(super) fn matches_normalized_country(country: &str, filter: &Option<Vec<String>>) -> bool {
    !country.is_empty()
        && filter
            .as_ref()
            .is_none_or(|filter| filter.iter().any(|item| item == country))
}
