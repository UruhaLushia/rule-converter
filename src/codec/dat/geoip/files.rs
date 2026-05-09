use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::codec::dat::proto::for_each_raw_message_field_from_reader;

use super::filter::{matches_normalized_country, normalize_country_filter};
use super::scan::scan_geoip_entry_meta;
use super::writer::write_geoip_entry_ipset;

#[cfg(not(target_arch = "wasm32"))]
pub struct DatTextOutputFile {
    pub name: String,
    pub count: usize,
    pub path: PathBuf,
}

#[cfg(not(target_arch = "wasm32"))]
pub fn export_geoip_dat_ipset_to_dir(
    input: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    countries: &[String],
) -> Result<Vec<DatTextOutputFile>> {
    let input = input.as_ref();
    let output_dir = output_dir.as_ref();
    fs::create_dir_all(output_dir)?;
    let reader = BufReader::new(File::open(input)?);
    export_geoip_dat_ipset_to_dir_writer(reader, output_dir, countries)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn export_geoip_dat_ipset_to_dir_writer<R: Read>(
    reader: R,
    output_dir: &Path,
    countries: &[String],
) -> Result<Vec<DatTextOutputFile>> {
    let filter = normalize_country_filter(countries);
    let mut files = Vec::new();
    for_each_raw_message_field_from_reader(reader, 1, "V2Ray geoip dat", |raw| {
        let meta = scan_geoip_entry_meta(raw)?;
        if meta.reverse_match || !matches_normalized_country(&meta.country, &filter) {
            return Ok(());
        }
        let country = meta.country.to_ascii_lowercase();
        let path = output_dir.join(format!("{country}.list"));
        let file = File::create(&path)?;
        let mut writer = BufWriter::new(file);
        let mut count = 0usize;
        write_geoip_entry_ipset(raw, &mut writer, &mut count)?;
        if count > 0 {
            files.push(DatTextOutputFile {
                name: country,
                count,
                path,
            });
        }
        Ok(())
    })?;
    if files.is_empty() {
        bail!("geoip dat input does not contain any matching records");
    }
    Ok(files)
}
