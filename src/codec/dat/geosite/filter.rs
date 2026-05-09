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

use super::scan::{for_each_raw_geosite_entry, scan_geosite_entry_meta};

pub fn filter_geosite_dat(input: &[u8], codes: &[String]) -> Result<(usize, Vec<u8>)> {
    let filter = normalize_code_filter(codes);
    let mut count = 0usize;
    let mut output = Vec::new();
    for_each_raw_geosite_entry(input, |raw| {
        let meta = scan_geosite_entry_meta(raw)?;
        if matches_normalized_code(&meta.code, &filter) {
            count += meta.domain_count;
            write_raw_message_field(&mut output, 1, raw)?;
        }
        Ok(())
    })?;
    if count == 0 {
        bail!("geosite dat input does not contain any matching records");
    }
    Ok((count, output))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn filter_geosite_dat_to_path(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    codes: &[String],
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
    filter_geosite_dat_to_writer(reader, writer, codes)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn filter_geosite_dat_to_writer<R: Read, W: Write>(
    reader: R,
    mut writer: W,
    codes: &[String],
) -> Result<usize> {
    let filter = normalize_code_filter(codes);
    let mut count = 0usize;
    for_each_raw_message_field_from_reader(reader, 1, "V2Ray geosite dat", |raw| {
        let meta = scan_geosite_entry_meta(raw)?;
        if matches_normalized_code(&meta.code, &filter) {
            count += meta.domain_count;
            write_raw_message_field_to_writer(&mut writer, 1, raw)?;
        }
        Ok(())
    })?;
    if count == 0 {
        bail!("geosite dat input does not contain any matching records");
    }
    Ok(count)
}

pub(super) fn normalize_code_filter(codes: &[String]) -> Option<Vec<String>> {
    if codes.is_empty() {
        return None;
    }
    Some(
        codes
            .iter()
            .map(|code| normalize_code(code))
            .filter(|code| !code.is_empty())
            .collect(),
    )
}

pub(super) fn normalize_code(code: &str) -> String {
    code.trim().to_ascii_uppercase()
}

pub(super) fn matches_code(code: &str, filter: &Option<Vec<String>>) -> bool {
    let code = normalize_code(code);
    matches_normalized_code(&code, filter)
}

pub(super) fn matches_normalized_code(code: &str, filter: &Option<Vec<String>>) -> bool {
    !code.is_empty()
        && filter
            .as_ref()
            .is_none_or(|filter| filter.iter().any(|item| item == code))
}
