mod address;
mod builder;
mod convert;
mod export;
#[cfg(not(target_arch = "wasm32"))]
mod files;
mod filter;
mod scan;
mod writer;

use anyhow::{Result, bail};

use crate::codec::mihomo::mrs::{IpCidrSetBuilder, RuleSetOutput};

use super::proto::{GeoIp, for_each_message_field};
use filter::{matches_country, normalize_country_code, normalize_country_filter};

pub use builder::build_geoip_dat_from_rule_sets;
pub use export::export_geoip_dat_ipset_to_memory;
#[cfg(not(target_arch = "wasm32"))]
pub use files::{export_geoip_dat_ipset_to_dir, export_geoip_dat_ipset_to_dir_writer};
pub use filter::filter_geoip_dat;
#[cfg(not(target_arch = "wasm32"))]
pub use filter::{filter_geoip_dat_to_path, filter_geoip_dat_to_writer};
pub struct GeoipDatRuleSet {
    pub country: String,
    pub output: RuleSetOutput,
}

pub fn list_geoip_dat_countries(input: &[u8]) -> Result<Vec<String>> {
    let mut countries = Vec::new();
    scan::for_each_raw_geoip_entry(input, |entry| {
        let meta = scan::scan_geoip_entry_meta(entry)?;
        if !meta.reverse_match && !meta.country.is_empty() {
            countries.push(meta.country);
        }
        Ok(())
    })?;
    countries.sort_unstable();
    countries.dedup();
    Ok(countries)
}

pub fn collect_geoip_dat_rule_set(input: &[u8], countries: &[String]) -> Result<RuleSetOutput> {
    let filter = normalize_country_filter(countries);
    let mut builder = IpCidrSetBuilder::default();

    for_each_geoip_entry(input, |entry, _| {
        if matches_country(&entry.country_code, &filter) {
            convert::push_geoip_entry(&mut builder, &entry)?;
        }
        Ok(())
    })?;

    if builder.is_empty() {
        bail!("geoip dat input does not contain any matching records");
    }
    Ok(RuleSetOutput::Ipcidr(builder.finish()?))
}

pub fn collect_geoip_dat_rule_sets(
    input: &[u8],
    countries: &[String],
) -> Result<Vec<GeoipDatRuleSet>> {
    let filter = normalize_country_filter(countries);
    let mut outputs = Vec::new();

    for_each_geoip_entry(input, |entry, _| {
        if !matches_country(&entry.country_code, &filter) {
            return Ok(());
        }
        let mut builder = IpCidrSetBuilder::default();
        convert::push_geoip_entry(&mut builder, &entry)?;
        if !builder.is_empty() {
            outputs.push(GeoipDatRuleSet {
                country: normalize_country_code(&entry.country_code),
                output: RuleSetOutput::Ipcidr(builder.finish()?),
            });
        }
        Ok(())
    })?;

    if outputs.is_empty() {
        bail!("geoip dat input does not contain any matching records");
    }
    Ok(outputs)
}

fn for_each_geoip_entry(input: &[u8], f: impl FnMut(GeoIp, &[u8]) -> Result<()>) -> Result<()> {
    for_each_message_field(input, 1, "V2Ray geoip dat", f)
}
