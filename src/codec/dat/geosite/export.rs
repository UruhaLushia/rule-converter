#[cfg(not(target_arch = "wasm32"))]
use std::fs::{self, File};
#[cfg(not(target_arch = "wasm32"))]
use std::io::Write;
#[cfg(not(target_arch = "wasm32"))]
use std::io::{BufReader, BufWriter, Read};
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

use anyhow::{Result, bail};

use super::filter::{matches_normalized_code, normalize_code_filter};
use super::scan::{for_each_raw_geosite_entry, scan_geosite_entry_meta};
use super::writer::write_geosite_entry_ruleset;
#[cfg(not(target_arch = "wasm32"))]
use crate::codec::dat::proto::for_each_raw_message_field_from_reader;
pub fn export_geosite_dat_general_ruleset_to_memory(
    input: &[u8],
    codes: &[String],
    split: bool,
) -> Result<Vec<(String, usize, Vec<u8>)>> {
    let filter = normalize_code_filter(codes);
    if split {
        let mut outputs = Vec::new();
        for_each_raw_geosite_entry(input, |raw| {
            let meta = scan_geosite_entry_meta(raw)?;
            if !matches_normalized_code(&meta.code, &filter) {
                return Ok(());
            }
            let mut bytes = Vec::new();
            let mut count = 0usize;
            write_geosite_entry_ruleset(raw, &mut bytes, &mut count)?;
            if count > 0 {
                outputs.push((meta.code.to_ascii_lowercase(), count, bytes));
            }
            Ok(())
        })?;
        if outputs.is_empty() {
            bail!("geosite dat input does not contain any matching records");
        }
        return Ok(outputs);
    }

    let mut bytes = Vec::new();
    let mut count = 0usize;
    for_each_raw_geosite_entry(input, |raw| {
        let meta = scan_geosite_entry_meta(raw)?;
        if matches_normalized_code(&meta.code, &filter) {
            write_geosite_entry_ruleset(raw, &mut bytes, &mut count)?;
        }
        Ok(())
    })?;
    if count == 0 {
        bail!("geosite dat input does not contain any matching records");
    }
    Ok(vec![("geosite".to_string(), count, bytes)])
}

#[cfg(not(target_arch = "wasm32"))]
pub fn export_geosite_dat_general_ruleset_to_path(
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
    export_geosite_dat_general_ruleset_to_writer(reader, writer, codes)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn export_geosite_dat_general_ruleset_to_writer<R: Read, W: Write>(
    reader: R,
    mut writer: W,
    codes: &[String],
) -> Result<usize> {
    let filter = normalize_code_filter(codes);
    let mut count = 0usize;
    for_each_raw_message_field_from_reader(reader, 1, "V2Ray geosite dat", |raw| {
        let meta = scan_geosite_entry_meta(raw)?;
        if matches_normalized_code(&meta.code, &filter) {
            write_geosite_entry_ruleset(raw, &mut writer, &mut count)?;
        }
        Ok(())
    })?;
    if count == 0 {
        bail!("geosite dat input does not contain any matching records");
    }
    Ok(count)
}
