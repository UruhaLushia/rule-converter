use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use super::filter::{matches_normalized_code, normalize_code_filter};
use super::scan::scan_geosite_entry_meta;
use super::writer::write_geosite_entry_ruleset;
use crate::codec::dat::proto::for_each_raw_message_field_from_reader;

#[cfg(not(target_arch = "wasm32"))]
pub struct DatTextOutputFile {
    pub name: String,
    pub count: usize,
    pub path: PathBuf,
}

#[cfg(not(target_arch = "wasm32"))]
pub fn export_geosite_dat_general_ruleset_to_dir(
    input: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    codes: &[String],
) -> Result<Vec<DatTextOutputFile>> {
    let input = input.as_ref();
    let output_dir = output_dir.as_ref();
    fs::create_dir_all(output_dir)?;
    let reader = BufReader::new(File::open(input)?);
    export_geosite_dat_general_ruleset_to_dir_writer(reader, output_dir, codes)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn export_geosite_dat_general_ruleset_to_dir_writer<R: Read>(
    reader: R,
    output_dir: &Path,
    codes: &[String],
) -> Result<Vec<DatTextOutputFile>> {
    let filter = normalize_code_filter(codes);
    let mut files = Vec::new();
    for_each_raw_message_field_from_reader(reader, 1, "V2Ray geosite dat", |raw| {
        let meta = scan_geosite_entry_meta(raw)?;
        if !matches_normalized_code(&meta.code, &filter) {
            return Ok(());
        }
        let code = meta.code.to_ascii_lowercase();
        let path = output_dir.join(format!("{code}.list"));
        let file = File::create(&path)?;
        let mut writer = BufWriter::new(file);
        let mut count = 0usize;
        write_geosite_entry_ruleset(raw, &mut writer, &mut count)?;
        if count > 0 {
            files.push(DatTextOutputFile {
                name: code,
                count,
                path,
            });
        }
        Ok(())
    })?;
    if files.is_empty() {
        bail!("geosite dat input does not contain any matching records");
    }
    Ok(files)
}
