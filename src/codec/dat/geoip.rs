#[cfg(not(target_arch = "wasm32"))]
use std::fs::{self, File};
use std::io::Write;
#[cfg(not(target_arch = "wasm32"))]
use std::io::{BufReader, BufWriter, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(not(target_arch = "wasm32"))]
use std::path::{Path, PathBuf};

use crate::codec::mihomo::mrs::{IpCidrSetBuilder, RuleSetOutput};
use anyhow::{Context, Result, bail};

use super::proto::{
    Cidr, GeoIp, decode_varint, for_each_message_field, for_each_raw_message_field, scan_field,
    write_message_field, write_raw_message_field,
};
#[cfg(not(target_arch = "wasm32"))]
use super::proto::{for_each_raw_message_field_from_reader, write_raw_message_field_to_writer};

pub struct GeoipDatRuleSet {
    pub country: String,
    pub output: RuleSetOutput,
}

pub fn list_geoip_dat_countries(input: &[u8]) -> Result<Vec<String>> {
    let mut countries = Vec::new();
    for_each_raw_geoip_entry(input, |entry| {
        let meta = scan_geoip_entry_meta(entry)?;
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
            push_geoip_entry(&mut builder, &entry)?;
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
        push_geoip_entry(&mut builder, &entry)?;
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

fn write_geoip_entry_ipset<W: Write>(
    input: &[u8],
    writer: &mut W,
    count: &mut usize,
) -> Result<()> {
    let mut pos = 0usize;
    while pos < input.len() {
        let (tag, wire_type, value_start, value_end) =
            scan_field(input, &mut pos, "V2Ray geoip dat entry")?;
        if (tag, wire_type) != (2, 2) {
            continue;
        }
        let payload_start = length_delimited_payload_start(input, value_start, value_end)?;
        if let Some((addr, prefix)) = scan_cidr_rule(&input[payload_start..value_end])? {
            writeln!(writer, "{addr}/{prefix}")?;
            *count += 1;
        }
    }
    Ok(())
}

fn scan_cidr_rule(input: &[u8]) -> Result<Option<(IpAddr, u8)>> {
    let mut pos = 0usize;
    let mut addr = None;
    let mut prefix = None;
    while pos < input.len() {
        let (tag, wire_type, value_start, value_end) =
            scan_field(input, &mut pos, "V2Ray geoip CIDR")?;
        match (tag, wire_type) {
            (1, 2) => {
                let start = length_delimited_payload_start(input, value_start, value_end)?;
                addr = Some(addr_from_raw(&input[start..value_end])?);
            }
            (2, 0) => {
                prefix = Some(u8::try_from(decode_varint(
                    &input[value_start..value_end],
                )?)?);
            }
            _ => {}
        }
    }
    Ok(match (addr, prefix) {
        (Some(addr), Some(prefix)) => Some((addr, prefix)),
        _ => None,
    })
}

fn length_delimited_payload_start(
    input: &[u8],
    value_start: usize,
    value_end: usize,
) -> Result<usize> {
    let len = decode_varint(&input[value_start..value_end])? as usize;
    let mut start = value_start;
    while input.get(start).is_some_and(|byte| byte & 0x80 != 0) {
        start += 1;
    }
    start += 1;
    start
        .checked_add(len)
        .filter(|end| *end == value_end)
        .ok_or_else(|| anyhow::anyhow!("invalid V2Ray geoip length-delimited field"))?;
    Ok(start)
}

pub fn build_geoip_dat_from_rule_sets<I>(entries: I) -> Result<(usize, Vec<u8>)>
where
    I: IntoIterator<Item = (String, RuleSetOutput)>,
{
    let mut count = 0usize;
    let mut output = Vec::new();
    for (country, rules) in entries {
        let country = normalize_country_code(&country);
        if country.is_empty() {
            bail!("GeoIP country is empty");
        }
        let mut cidr = Vec::new();
        rules.for_each_ip_prefix(|addr, prefix| {
            cidr.push(cidr_from_prefix(addr, prefix));
            count += 1;
            Ok(())
        })?;
        if !cidr.is_empty() {
            write_message_field(
                &mut output,
                1,
                &GeoIp {
                    country_code: country,
                    cidr,
                    reverse_match: false,
                },
            )?;
        }
    }
    if count == 0 {
        bail!("geoip dat output does not contain any CIDR records");
    }
    Ok((count, output))
}

struct GeoipEntryMeta {
    country: String,
    cidr_count: usize,
    reverse_match: bool,
}

fn for_each_raw_geoip_entry(input: &[u8], f: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
    for_each_raw_message_field(input, 1, "V2Ray geoip dat", f)
}

fn scan_geoip_entry_meta(input: &[u8]) -> Result<GeoipEntryMeta> {
    let mut pos = 0usize;
    let mut country = String::new();
    let mut cidr_count = 0usize;
    let mut reverse_match = false;
    while pos < input.len() {
        let (tag, wire_type, value_start, value_end) =
            scan_field(input, &mut pos, "V2Ray geoip dat entry")?;
        match (tag, wire_type) {
            (1, 2) => {
                let mut len_pos = value_start;
                let len = decode_varint(&input[value_start..value_end])? as usize;
                while input.get(len_pos).is_some_and(|byte| byte & 0x80 != 0) {
                    len_pos += 1;
                }
                len_pos += 1;
                let end = len_pos
                    .checked_add(len)
                    .filter(|end| *end <= value_end)
                    .ok_or_else(|| anyhow::anyhow!("invalid V2Ray geoip dat country length"))?;
                country = normalize_country_code(std::str::from_utf8(&input[len_pos..end])?);
            }
            (2, 2) => cidr_count += 1,
            (3, 0) => reverse_match = decode_varint(&input[value_start..value_end])? != 0,
            _ => {}
        }
    }
    Ok(GeoipEntryMeta {
        country,
        cidr_count,
        reverse_match,
    })
}

fn for_each_geoip_entry(input: &[u8], f: impl FnMut(GeoIp, &[u8]) -> Result<()>) -> Result<()> {
    for_each_message_field(input, 1, "V2Ray geoip dat", f)
}

fn push_geoip_entry(builder: &mut IpCidrSetBuilder, entry: &GeoIp) -> Result<()> {
    if entry.reverse_match {
        return Ok(());
    }
    for cidr in &entry.cidr {
        let addr = addr_from_cidr(cidr)?;
        let prefix = u8::try_from(cidr.prefix).context("invalid geoip dat CIDR prefix")?;
        builder.insert_prefix(addr, prefix)?;
    }
    Ok(())
}

fn addr_from_cidr(cidr: &Cidr) -> Result<IpAddr> {
    addr_from_raw(&cidr.ip)
}

fn addr_from_raw(raw: &[u8]) -> Result<IpAddr> {
    match raw.len() {
        4 => Ok(IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))),
        16 => {
            let bytes: [u8; 16] = raw.try_into().expect("length checked above");
            Ok(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        len => bail!("invalid geoip dat CIDR address length: {len}"),
    }
}

fn cidr_from_prefix(addr: IpAddr, prefix: u8) -> Cidr {
    match addr {
        IpAddr::V4(addr) => Cidr {
            ip: addr.octets().to_vec(),
            prefix: prefix as u32,
        },
        IpAddr::V6(addr) => Cidr {
            ip: addr.octets().to_vec(),
            prefix: prefix as u32,
        },
    }
}

fn normalize_country_filter(countries: &[String]) -> Option<Vec<String>> {
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

fn normalize_country_code(country: &str) -> String {
    country.trim().to_ascii_uppercase()
}

fn matches_country(country: &str, filter: &Option<Vec<String>>) -> bool {
    let country = normalize_country_code(country);
    matches_normalized_country(&country, filter)
}

fn matches_normalized_country(country: &str, filter: &Option<Vec<String>>) -> bool {
    !country.is_empty()
        && filter
            .as_ref()
            .is_none_or(|filter| filter.iter().any(|item| item == country))
}
