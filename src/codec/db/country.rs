use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use maxminddb::geoip2;
use maxminddb::{Reader, WithinOptions};
use maxminddb_writer::paths::IpAddrWithMask;
use serde::{Deserialize, Serialize};

use crate::codec::mihomo::mrs::{IpCidrSetBuilder, RuleSetOutput};
use crate::input::expand_file_paths;

use super::common::{
    for_each_cidr, new_database, parse_cidr_with_context, set_database_has_ipv6, write_database,
    write_database_to_memory, write_ip_prefix_range, write_mrs_ipcidr_header,
};
use super::format::MmdbFormat;
use super::sing::geoip_database_type;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeoipOutputFile {
    pub country: String,
    pub count: usize,
    pub path: PathBuf,
}

pub struct GeoipRuleSet {
    pub country: String,
    pub output: RuleSetOutput,
}

pub fn export_geoip_mmdb_to_dir(
    input: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    countries: &[String],
) -> Result<Vec<GeoipOutputFile>> {
    let input = input.as_ref();
    let output_dir = output_dir.as_ref();
    let sets = collect_geoip_mmdb_cidrs(input, countries)?;

    fs::create_dir_all(output_dir)
        .with_context(|| format!("failed to create output directory {}", output_dir.display()))?;
    let mut outputs = Vec::with_capacity(sets.len());
    for set in sets {
        let path = output_dir.join(format!("{}.list", set.country));
        let mut writer = BufWriter::new(
            File::create(&path).with_context(|| format!("failed to create {}", path.display()))?,
        );
        for cidr in &set.cidrs {
            writeln!(writer, "{cidr}")?;
        }
        outputs.push(GeoipOutputFile {
            country: set.country,
            count: set.cidrs.len(),
            path,
        });
    }
    Ok(outputs)
}

pub fn export_geoip_mmdb_ipset_to_path(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    countries: &[String],
) -> Result<GeoipOutputFile> {
    let input = input.as_ref();
    let output = output.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read GeoIP MMDB {}", input.display()))?;
    let filter = normalize_country_filter(countries);

    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    }
    let mut writer = BufWriter::with_capacity(
        64 * 1024,
        File::create(output).with_context(|| format!("failed to create {}", output.display()))?,
    );
    let count = write_geoip_mmdb_reader_ipset(reader, &filter, &mut writer)?;

    Ok(GeoipOutputFile {
        country: if countries.len() == 1 {
            normalize_country_code(&countries[0])
        } else {
            "geoip".to_string()
        },
        count,
        path: output.to_path_buf(),
    })
}

pub fn export_geoip_mmdb_ipset_to_bytes(
    input: &[u8],
    countries: &[String],
) -> Result<(usize, Vec<u8>)> {
    let reader = Reader::from_source(input).context("failed to read GeoIP MMDB payload")?;
    let filter = normalize_country_filter(countries);
    let mut output = Vec::with_capacity(64 * 1024);
    let count = write_geoip_mmdb_reader_ipset(reader, &filter, &mut output)?;
    Ok((count, output))
}

pub fn export_geoip_mmdb_file_ipset_to_bytes(
    input: impl AsRef<Path>,
    countries: &[String],
) -> Result<(usize, Vec<u8>)> {
    let input = input.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read GeoIP MMDB {}", input.display()))?;
    let filter = normalize_country_filter(countries);
    let mut output = Vec::with_capacity(64 * 1024);
    let count = write_geoip_mmdb_reader_ipset(reader, &filter, &mut output)?;
    Ok((count, output))
}

pub fn export_geoip_mmdb_ipset_to_string(
    input: &[u8],
    countries: &[String],
) -> Result<(usize, String)> {
    let reader = Reader::from_source(input).context("failed to read GeoIP MMDB payload")?;
    let filter = normalize_country_filter(countries);
    write_geoip_mmdb_reader_ipset_string(reader, &filter)
}

pub fn export_geoip_mmdb_file_ipset_to_string(
    input: impl AsRef<Path>,
    countries: &[String],
) -> Result<(usize, String)> {
    let input = input.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read GeoIP MMDB {}", input.display()))?;
    let filter = normalize_country_filter(countries);
    write_geoip_mmdb_reader_ipset_string(reader, &filter)
}

fn write_geoip_mmdb_reader_ipset<S: AsRef<[u8]>, W: Write>(
    reader: Reader<S>,
    filter: &Option<BTreeSet<String>>,
    writer: &mut W,
) -> Result<usize> {
    let mut count = 0usize;

    for item in reader.networks(WithinOptions::default())? {
        let item = item.context("failed to read GeoIP MMDB network")?;
        if !geoip_item_matches_filter(&item, filter)? {
            continue;
        }
        writeln!(writer, "{}", item.network()?)?;
        count += 1;
    }

    if count == 0 {
        bail!("GeoIP input does not contain any country records");
    }
    Ok(count)
}

fn write_geoip_mmdb_reader_ipset_string<S: AsRef<[u8]>>(
    reader: Reader<S>,
    filter: &Option<BTreeSet<String>>,
) -> Result<(usize, String)> {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(64 * 1024);
    let mut count = 0usize;

    for item in reader.networks(WithinOptions::default())? {
        let item = item.context("failed to read GeoIP MMDB network")?;
        if !geoip_item_matches_filter(&item, filter)? {
            continue;
        }
        writeln!(&mut output, "{}", item.network()?).expect("writing to String cannot fail");
        count += 1;
    }

    if count == 0 {
        bail!("GeoIP input does not contain any country records");
    }
    Ok((count, output))
}

pub fn export_geoip_mmdb_mrs_to_path(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    countries: &[String],
) -> Result<GeoipOutputFile> {
    let input = input.as_ref();
    let output = output.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read GeoIP MMDB {}", input.display()))?;
    let filter = normalize_country_filter(countries);
    let mut count = 0usize;

    for item in reader.networks(WithinOptions::default())? {
        let item = item.context("failed to read GeoIP MMDB network")?;
        if geoip_item_matches_filter(&item, &filter)? {
            count += 1;
        }
    }
    if count == 0 {
        bail!("GeoIP input does not contain any country records");
    }

    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    }
    let writer = BufWriter::with_capacity(
        64 * 1024,
        File::create(output).with_context(|| format!("failed to create {}", output.display()))?,
    );
    let mut encoder =
        zstd::stream::Encoder::new(writer, 0).context("failed to create zstd encoder")?;
    write_mrs_ipcidr_header(&mut encoder, count)?;

    for item in reader.networks(WithinOptions::default())? {
        let item = item.context("failed to read GeoIP MMDB network")?;
        if !geoip_item_matches_filter(&item, &filter)? {
            continue;
        }
        let network = item.network()?;
        write_ip_prefix_range(&mut encoder, network.ip(), network.prefix())?;
    }
    encoder.finish().context("failed to finish zstd stream")?;

    Ok(GeoipOutputFile {
        country: if countries.len() == 1 {
            normalize_country_code(&countries[0])
        } else {
            "geoip".to_string()
        },
        count,
        path: output.to_path_buf(),
    })
}

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

fn geoip_item_matches_filter<S: AsRef<[u8]>>(
    item: &maxminddb::LookupResult<'_, S>,
    filter: &Option<BTreeSet<String>>,
) -> Result<bool> {
    let countries = decode_country_codes(item)?;
    Ok(countries.into_iter().any(|country| {
        let country = normalize_country_code(&country);
        !country.is_empty() && filter_matches(filter, &country)
    }))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeoipCidrSet {
    pub country: String,
    pub cidrs: Vec<String>,
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

pub fn convert_geoip_mmdb(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    output_format: MmdbFormat,
) -> Result<usize> {
    convert_geoip_mmdb_filtered(input, output, output_format, &[])
}

pub fn convert_geoip_mmdb_filtered(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    output_format: MmdbFormat,
    countries: &[String],
) -> Result<usize> {
    let input = input.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read GeoIP MMDB {}", input.display()))?;
    let (count, db) = convert_geoip_mmdb_reader(reader, output_format, countries)?;
    write_database(db, output.as_ref())?;
    Ok(count)
}

pub fn convert_geoip_mmdb_to_bytes(
    input: &[u8],
    output_format: MmdbFormat,
) -> Result<(usize, Vec<u8>)> {
    convert_geoip_mmdb_to_bytes_filtered(input, output_format, &[])
}

pub fn convert_geoip_mmdb_to_bytes_filtered(
    input: &[u8],
    output_format: MmdbFormat,
    countries: &[String],
) -> Result<(usize, Vec<u8>)> {
    let reader = Reader::from_source(input).context("failed to read GeoIP MMDB payload")?;
    let (count, db) = convert_geoip_mmdb_reader(reader, output_format, countries)?;
    Ok((count, write_database_to_memory(db)?))
}

pub fn convert_geoip_mmdb_file_to_bytes(
    input: impl AsRef<Path>,
    output_format: MmdbFormat,
) -> Result<(usize, Vec<u8>)> {
    convert_geoip_mmdb_file_to_bytes_filtered(input, output_format, &[])
}

pub fn convert_geoip_mmdb_file_to_bytes_filtered(
    input: impl AsRef<Path>,
    output_format: MmdbFormat,
    countries: &[String],
) -> Result<(usize, Vec<u8>)> {
    let input = input.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read GeoIP MMDB {}", input.display()))?;
    let (count, db) = convert_geoip_mmdb_reader(reader, output_format, countries)?;
    Ok((count, write_database_to_memory(db)?))
}

fn convert_geoip_mmdb_reader<S: AsRef<[u8]>>(
    reader: Reader<S>,
    output_format: MmdbFormat,
    countries: &[String],
) -> Result<(usize, maxminddb_writer::Database)> {
    let mut db = new_database(
        reader.metadata.ip_version == 6,
        geoip_database_type(output_format),
        "GeoIP country database generated by rule-converter",
    );
    let filter = normalize_country_filter(countries);
    let mut count = 0usize;

    match output_format {
        MmdbFormat::Mmdb | MmdbFormat::SingDb => {
            let mut values = HashMap::new();
            for item in reader.networks(WithinOptions::default())? {
                let item = item.context("failed to read GeoIP MMDB network")?;
                let Some(country) = decode_first_matching_country_code(&item, &filter)? else {
                    continue;
                };
                let data_ref = match values.get(&country) {
                    Some(data_ref) => *data_ref,
                    None => {
                        let data_ref = match output_format {
                            MmdbFormat::Mmdb => db.insert_value(CountryRecordValue {
                                country: CountryCodeValue { iso_code: &country },
                            })?,
                            MmdbFormat::SingDb => db.insert_value(country.as_str())?,
                            MmdbFormat::MetaDb | MmdbFormat::Dat => unreachable!(),
                        };
                        values.insert(country, data_ref);
                        data_ref
                    }
                };
                let network = item.network()?;
                db.insert_node(
                    IpAddrWithMask::new(network.ip(), network.prefix()),
                    data_ref,
                );
                count += 1;
            }
        }
        MmdbFormat::Dat => unreachable!("dat is handled by codec::dat"),
        MmdbFormat::MetaDb => {
            let mut values = HashMap::new();
            for item in reader.networks(WithinOptions::default())? {
                let item = item.context("failed to read GeoIP MMDB network")?;
                let countries = decode_matching_country_codes(&item, &filter)?;
                if countries.is_empty() {
                    continue;
                }
                let data_ref = match values.get(&countries) {
                    Some(data_ref) => *data_ref,
                    None => {
                        let data_ref = if countries.len() == 1 {
                            db.insert_value(countries[0].as_str())?
                        } else {
                            db.insert_value(&countries)?
                        };
                        values.insert(countries, data_ref);
                        data_ref
                    }
                };
                let network = item.network()?;
                db.insert_node(
                    IpAddrWithMask::new(network.ip(), network.prefix()),
                    data_ref,
                );
                count += 1;
            }
        }
    }

    if count == 0 {
        bail!("GeoIP input does not contain any country records");
    }
    Ok((count, db))
}

pub fn build_geoip_mmdb_from_paths<P, I>(
    entries: I,
    output: impl AsRef<Path>,
    format: MmdbFormat,
) -> Result<usize>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = (String, P)>,
{
    let mut db = new_database(
        false,
        geoip_database_type(format),
        "GeoIP country database generated by rule-converter",
    );
    let mut values = HashMap::new();
    let mut has_ipv6 = false;
    let mut count = 0usize;

    for (country, path) in entries {
        let country = normalize_country_code(&country);
        if country.is_empty() {
            bail!("GeoIP country is empty");
        }
        let path = path.as_ref();
        count += for_each_cidr(path, |cidr| {
            has_ipv6 |= cidr.addr.is_ipv6();
            let data_ref = match values.get(&country) {
                Some(data_ref) => *data_ref,
                None => {
                    let data_ref = match format {
                        MmdbFormat::Mmdb => db.insert_value(CountryRecordValue {
                            country: CountryCodeValue { iso_code: &country },
                        })?,
                        MmdbFormat::SingDb | MmdbFormat::MetaDb => {
                            db.insert_value(country.as_str())?
                        }
                        MmdbFormat::Dat => unreachable!("dat is handled by codec::dat"),
                    };
                    values.insert(country.clone(), data_ref);
                    data_ref
                }
            };
            db.insert_node(cidr, data_ref);
            Ok(())
        })?;
    }
    if count == 0 {
        bail!("GeoIP input does not contain any CIDR records");
    }
    set_database_has_ipv6(&mut db, has_ipv6);
    write_database(db, output.as_ref())?;
    Ok(count)
}

pub fn build_geoip_mmdb_from_rule_sets<I>(
    entries: I,
    output: impl AsRef<Path>,
    format: MmdbFormat,
) -> Result<usize>
where
    I: IntoIterator<Item = (String, RuleSetOutput)>,
{
    let (count, db) = build_geoip_mmdb_database_from_rule_sets(entries, format)?;
    write_database(db, output.as_ref())?;
    Ok(count)
}

pub fn build_geoip_mmdb_from_rule_sets_to_bytes<I>(
    entries: I,
    format: MmdbFormat,
) -> Result<(usize, Vec<u8>)>
where
    I: IntoIterator<Item = (String, RuleSetOutput)>,
{
    let (count, db) = build_geoip_mmdb_database_from_rule_sets(entries, format)?;
    Ok((count, write_database_to_memory(db)?))
}

fn build_geoip_mmdb_database_from_rule_sets<I>(
    entries: I,
    format: MmdbFormat,
) -> Result<(usize, maxminddb_writer::Database)>
where
    I: IntoIterator<Item = (String, RuleSetOutput)>,
{
    let mut db = new_database(
        false,
        geoip_database_type(format),
        "GeoIP country database generated by rule-converter",
    );
    let mut values = HashMap::new();
    let mut has_ipv6 = false;
    let mut count = 0usize;

    for (country, rules) in entries {
        let country = normalize_country_code(&country);
        if country.is_empty() {
            bail!("GeoIP country is empty");
        }
        let data_ref = match values.get(&country) {
            Some(data_ref) => *data_ref,
            None => {
                let data_ref = match format {
                    MmdbFormat::Mmdb => db.insert_value(CountryRecordValue {
                        country: CountryCodeValue { iso_code: &country },
                    })?,
                    MmdbFormat::SingDb | MmdbFormat::MetaDb => db.insert_value(country.as_str())?,
                    MmdbFormat::Dat => unreachable!("dat is handled by codec::dat"),
                };
                values.insert(country.clone(), data_ref);
                data_ref
            }
        };
        rules.for_each_ip_prefix(|addr, prefix| {
            has_ipv6 |= addr.is_ipv6();
            db.insert_node(IpAddrWithMask::new(addr, prefix), data_ref);
            count += 1;
            Ok(())
        })?;
    }

    if count == 0 {
        bail!("GeoIP input does not contain any CIDR records");
    }
    set_database_has_ipv6(&mut db, has_ipv6);
    Ok((count, db))
}

pub fn build_geoip_mmdb_from_cidrs<I>(
    entries: I,
    output: impl AsRef<Path>,
    format: MmdbFormat,
) -> Result<usize>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut db = new_database(
        false,
        geoip_database_type(format),
        "GeoIP country database generated by rule-converter",
    );
    let mut values = HashMap::new();
    let mut has_ipv6 = false;
    let mut count = 0usize;

    for (country, cidr) in entries {
        let country = normalize_country_code(&country);
        if country.is_empty() {
            bail!("GeoIP country is empty");
        }
        let parsed = parse_cidr_with_context(&country, &cidr)?;
        has_ipv6 |= parsed.addr.is_ipv6();
        let data_ref = match values.get(&country) {
            Some(data_ref) => *data_ref,
            None => {
                let data_ref = match format {
                    MmdbFormat::Mmdb => db.insert_value(CountryRecordValue {
                        country: CountryCodeValue { iso_code: &country },
                    })?,
                    MmdbFormat::SingDb | MmdbFormat::MetaDb => db.insert_value(country.as_str())?,
                    MmdbFormat::Dat => unreachable!("dat is handled by codec::dat"),
                };
                values.insert(country.clone(), data_ref);
                data_ref
            }
        };
        db.insert_node(parsed, data_ref);
        count += 1;
    }

    if count == 0 {
        bail!("GeoIP input does not contain any CIDR records");
    }
    set_database_has_ipv6(&mut db, has_ipv6);
    write_database(db, output.as_ref())?;
    Ok(count)
}

pub fn build_geoip_mmdb_from_file_names<P, I>(
    paths: I,
    output: impl AsRef<Path>,
    format: MmdbFormat,
) -> Result<usize>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = P>,
{
    let paths = expand_file_paths(paths)?;
    let entries = paths
        .into_iter()
        .map(|path| {
            let country = country_from_path(&path)?;
            Ok((country, path))
        })
        .collect::<Result<Vec<_>>>()?;
    build_geoip_mmdb_from_paths(entries, output, format)
}

fn decode_country_codes<S: AsRef<[u8]>>(
    item: &maxminddb::LookupResult<'_, S>,
) -> Result<Vec<String>> {
    if let Some(value) = item.decode::<String>().ok().flatten() {
        return Ok(vec![value]);
    }
    if let Some(value) = item.decode::<Vec<String>>().ok().flatten() {
        return Ok(value);
    }
    if let Some(value) = item.decode::<geoip2::Country<'_>>()? {
        if let Some(code) = value.country.iso_code {
            return Ok(vec![code.to_string()]);
        }
    }
    if let Some(value) = item.decode::<CountryRecord<'_>>().ok().flatten()
        && let Some(code) = value.country.and_then(|country| country.iso_code)
    {
        return Ok(vec![code.to_string()]);
    }
    Ok(Vec::new())
}

fn decode_first_matching_country_code<S: AsRef<[u8]>>(
    item: &maxminddb::LookupResult<'_, S>,
    filter: &Option<BTreeSet<String>>,
) -> Result<Option<String>> {
    Ok(decode_matching_country_codes(item, filter)?
        .into_iter()
        .next())
}

fn decode_matching_country_codes<S: AsRef<[u8]>>(
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
struct CountryRecordValue<'a> {
    country: CountryCodeValue<'a>,
}

#[derive(Serialize)]
struct CountryCodeValue<'a> {
    iso_code: &'a str,
}

fn country_from_path(path: &Path) -> Result<String> {
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

fn normalize_country_filter(countries: &[String]) -> Option<BTreeSet<String>> {
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

fn filter_matches(filter: &Option<BTreeSet<String>>, country: &str) -> bool {
    filter
        .as_ref()
        .is_none_or(|filter| filter.contains(country))
}

fn normalize_country_code(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}
