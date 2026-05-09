use anyhow::{Result, bail};

use super::filter::{matches_normalized_country, normalize_country_filter};
use super::scan::{for_each_raw_geoip_entry, scan_geoip_entry_meta};
use super::writer::write_geoip_entry_ipset;

pub fn export_geoip_dat_ipset_to_memory(
    input: &[u8],
    countries: &[String],
    split: bool,
) -> Result<Vec<(String, usize, Vec<u8>)>> {
    let filter = normalize_country_filter(countries);
    if split {
        let mut outputs = Vec::new();
        for_each_raw_geoip_entry(input, |raw| {
            let meta = scan_geoip_entry_meta(raw)?;
            if meta.reverse_match || !matches_normalized_country(&meta.country, &filter) {
                return Ok(());
            }
            let mut bytes = Vec::new();
            let mut count = 0usize;
            write_geoip_entry_ipset(raw, &mut bytes, &mut count)?;
            if count > 0 {
                outputs.push((meta.country.to_ascii_lowercase(), count, bytes));
            }
            Ok(())
        })?;
        if outputs.is_empty() {
            bail!("geoip dat input does not contain any matching records");
        }
        return Ok(outputs);
    }

    let mut bytes = Vec::new();
    let mut count = 0usize;
    for_each_raw_geoip_entry(input, |raw| {
        let meta = scan_geoip_entry_meta(raw)?;
        if !meta.reverse_match && matches_normalized_country(&meta.country, &filter) {
            write_geoip_entry_ipset(raw, &mut bytes, &mut count)?;
        }
        Ok(())
    })?;
    if count == 0 {
        bail!("geoip dat input does not contain any matching records");
    }
    Ok(vec![("geoip".to_string(), count, bytes)])
}
