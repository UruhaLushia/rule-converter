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

use super::common::{
    for_each_cidr, new_database, parse_cidr_with_context, set_database_has_ipv6, write_database,
    write_database_to_memory, write_ip_prefix_range, write_mrs_ipcidr_header,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsnOutputFile {
    pub asn: u32,
    pub count: usize,
    pub path: PathBuf,
}

pub struct AsnRuleSet {
    pub asn: u32,
    pub output: RuleSetOutput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AsnCidrSet {
    pub asn: u32,
    pub cidrs: Vec<String>,
}

pub fn export_asn_mmdb_to_dir(
    input: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    asns: &[u32],
) -> Result<Vec<AsnOutputFile>> {
    let input = input.as_ref();
    let output_dir = output_dir.as_ref();
    let sets = collect_asn_mmdb_cidrs(input, asns)?;

    fs::create_dir_all(output_dir)
        .with_context(|| format!("failed to create output directory {}", output_dir.display()))?;
    let mut outputs = Vec::with_capacity(sets.len());
    for set in sets {
        let path = output_dir.join(format!("{}.list", set.asn));
        let mut writer = BufWriter::new(
            File::create(&path).with_context(|| format!("failed to create {}", path.display()))?,
        );
        for cidr in &set.cidrs {
            writeln!(writer, "{cidr}")?;
        }
        outputs.push(AsnOutputFile {
            asn: set.asn,
            count: set.cidrs.len(),
            path,
        });
    }
    Ok(outputs)
}

pub fn export_asn_mmdb_ipset_to_path(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    asns: &[u32],
) -> Result<AsnOutputFile> {
    let input = input.as_ref();
    let output = output.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read ASN MMDB {}", input.display()))?;
    let filter = normalize_asn_filter(asns);

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
    let count = write_asn_mmdb_reader_ipset(reader, &filter, &mut writer)?;

    Ok(AsnOutputFile {
        asn: if asns.len() == 1 { asns[0] } else { 0 },
        count,
        path: output.to_path_buf(),
    })
}

pub fn export_asn_mmdb_ipset_to_bytes(input: &[u8], asns: &[u32]) -> Result<(usize, Vec<u8>)> {
    let reader = Reader::from_source(input).context("failed to read ASN MMDB payload")?;
    let filter = normalize_asn_filter(asns);
    let mut output = Vec::with_capacity(64 * 1024);
    let count = write_asn_mmdb_reader_ipset(reader, &filter, &mut output)?;
    Ok((count, output))
}

pub fn export_asn_mmdb_file_ipset_to_bytes(
    input: impl AsRef<Path>,
    asns: &[u32],
) -> Result<(usize, Vec<u8>)> {
    let input = input.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read ASN MMDB {}", input.display()))?;
    let filter = normalize_asn_filter(asns);
    let mut output = Vec::with_capacity(64 * 1024);
    let count = write_asn_mmdb_reader_ipset(reader, &filter, &mut output)?;
    Ok((count, output))
}

pub fn export_asn_mmdb_ipset_to_string(input: &[u8], asns: &[u32]) -> Result<(usize, String)> {
    let reader = Reader::from_source(input).context("failed to read ASN MMDB payload")?;
    let filter = normalize_asn_filter(asns);
    write_asn_mmdb_reader_ipset_string(reader, &filter)
}

pub fn export_asn_mmdb_file_ipset_to_string(
    input: impl AsRef<Path>,
    asns: &[u32],
) -> Result<(usize, String)> {
    let input = input.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read ASN MMDB {}", input.display()))?;
    let filter = normalize_asn_filter(asns);
    write_asn_mmdb_reader_ipset_string(reader, &filter)
}

fn write_asn_mmdb_reader_ipset<S: AsRef<[u8]>, W: Write>(
    reader: Reader<S>,
    filter: &Option<BTreeSet<u32>>,
    writer: &mut W,
) -> Result<usize> {
    let mut count = 0usize;

    for item in reader.networks(WithinOptions::default())? {
        let item = item.context("failed to read ASN MMDB network")?;
        let Some(asn) = decode_asn(&item)? else {
            continue;
        };
        if filter.as_ref().is_some_and(|filter| !filter.contains(&asn)) {
            continue;
        }
        writeln!(writer, "{}", item.network()?)?;
        count += 1;
    }

    if count == 0 {
        bail!("ASN input does not contain any ASN records");
    }
    Ok(count)
}

fn write_asn_mmdb_reader_ipset_string<S: AsRef<[u8]>>(
    reader: Reader<S>,
    filter: &Option<BTreeSet<u32>>,
) -> Result<(usize, String)> {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(64 * 1024);
    let mut count = 0usize;

    for item in reader.networks(WithinOptions::default())? {
        let item = item.context("failed to read ASN MMDB network")?;
        let Some(asn) = decode_asn(&item)? else {
            continue;
        };
        if filter.as_ref().is_some_and(|filter| !filter.contains(&asn)) {
            continue;
        }
        writeln!(&mut output, "{}", item.network()?).expect("writing to String cannot fail");
        count += 1;
    }

    if count == 0 {
        bail!("ASN input does not contain any ASN records");
    }
    Ok((count, output))
}

pub fn export_asn_mmdb_mrs_to_path(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    asns: &[u32],
) -> Result<AsnOutputFile> {
    let input = input.as_ref();
    let output = output.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read ASN MMDB {}", input.display()))?;
    let filter = normalize_asn_filter(asns);
    let mut count = 0usize;

    for item in reader.networks(WithinOptions::default())? {
        let item = item.context("failed to read ASN MMDB network")?;
        let Some(asn) = decode_asn(&item)? else {
            continue;
        };
        if filter.as_ref().is_some_and(|filter| !filter.contains(&asn)) {
            continue;
        }
        count += 1;
    }
    if count == 0 {
        bail!("ASN input does not contain any ASN records");
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
        let item = item.context("failed to read ASN MMDB network")?;
        let Some(asn) = decode_asn(&item)? else {
            continue;
        };
        if filter.as_ref().is_some_and(|filter| !filter.contains(&asn)) {
            continue;
        }
        let network = item.network()?;
        write_ip_prefix_range(&mut encoder, network.ip(), network.prefix())?;
    }
    encoder.finish().context("failed to finish zstd stream")?;

    Ok(AsnOutputFile {
        asn: if asns.len() == 1 { asns[0] } else { 0 },
        count,
        path: output.to_path_buf(),
    })
}

pub fn collect_asn_mmdb_rule_set(input: impl AsRef<Path>, asns: &[u32]) -> Result<RuleSetOutput> {
    let input = input.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read ASN MMDB {}", input.display()))?;
    collect_asn_mmdb_reader_rule_set(reader, asns)
}

pub fn collect_asn_mmdb_rule_set_from_bytes(input: &[u8], asns: &[u32]) -> Result<RuleSetOutput> {
    let reader = Reader::from_source(input).context("failed to read ASN MMDB payload")?;
    collect_asn_mmdb_reader_rule_set(reader, asns)
}

fn collect_asn_mmdb_reader_rule_set<S: AsRef<[u8]>>(
    reader: Reader<S>,
    asns: &[u32],
) -> Result<RuleSetOutput> {
    let filter = normalize_asn_filter(asns);
    let mut builder = IpCidrSetBuilder::default();

    for item in reader.networks(WithinOptions::default())? {
        let item = item.context("failed to read ASN MMDB network")?;
        let Some(asn) = decode_asn(&item)? else {
            continue;
        };
        if filter.as_ref().is_some_and(|filter| !filter.contains(&asn)) {
            continue;
        }
        let network = item.network()?;
        builder.insert_prefix(network.ip(), network.prefix())?;
    }

    if builder.is_empty() {
        bail!("ASN input does not contain any ASN records");
    }
    Ok(RuleSetOutput::Ipcidr(builder.finish()?))
}

pub fn collect_asn_mmdb_rule_sets(
    input: impl AsRef<Path>,
    asns: &[u32],
) -> Result<Vec<AsnRuleSet>> {
    let input = input.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read ASN MMDB {}", input.display()))?;
    collect_asn_mmdb_reader_rule_sets(reader, asns)
}

pub fn collect_asn_mmdb_rule_sets_from_bytes(
    input: &[u8],
    asns: &[u32],
) -> Result<Vec<AsnRuleSet>> {
    let reader = Reader::from_source(input).context("failed to read ASN MMDB payload")?;
    collect_asn_mmdb_reader_rule_sets(reader, asns)
}

fn collect_asn_mmdb_reader_rule_sets<S: AsRef<[u8]>>(
    reader: Reader<S>,
    asns: &[u32],
) -> Result<Vec<AsnRuleSet>> {
    let filter = normalize_asn_filter(asns);
    let mut by_asn: BTreeMap<u32, IpCidrSetBuilder> = BTreeMap::new();

    for item in reader.networks(WithinOptions::default())? {
        let item = item.context("failed to read ASN MMDB network")?;
        let Some(asn) = decode_asn(&item)? else {
            continue;
        };
        if filter.as_ref().is_some_and(|filter| !filter.contains(&asn)) {
            continue;
        }
        let network = item.network()?;
        by_asn
            .entry(asn)
            .or_default()
            .insert_prefix(network.ip(), network.prefix())?;
    }

    by_asn
        .into_iter()
        .map(|(asn, builder)| {
            Ok(AsnRuleSet {
                asn,
                output: RuleSetOutput::Ipcidr(builder.finish()?),
            })
        })
        .collect()
}

pub fn list_asn_mmdb_asns(input: impl AsRef<Path>) -> Result<Vec<u32>> {
    let input = input.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read ASN MMDB {}", input.display()))?;
    list_asn_mmdb_asns_from_reader(reader)
}

pub fn list_asn_mmdb_asns_from_bytes(input: &[u8]) -> Result<Vec<u32>> {
    let reader = Reader::from_source(input).context("failed to read ASN MMDB payload")?;
    list_asn_mmdb_asns_from_reader(reader)
}

fn list_asn_mmdb_asns_from_reader<S: AsRef<[u8]>>(reader: Reader<S>) -> Result<Vec<u32>> {
    let mut asns = BTreeSet::new();

    for item in reader.networks(WithinOptions::default())? {
        let item = item.context("failed to read ASN MMDB network")?;
        if let Some(asn) = decode_asn(&item)? {
            asns.insert(asn);
        }
    }

    if asns.is_empty() {
        bail!("ASN input does not contain any ASN records");
    }
    Ok(asns.into_iter().collect())
}

pub fn collect_asn_mmdb_cidrs(input: impl AsRef<Path>, asns: &[u32]) -> Result<Vec<AsnCidrSet>> {
    let input = input.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read ASN MMDB {}", input.display()))?;
    let filter = normalize_asn_filter(asns);
    let mut by_asn: BTreeMap<u32, Vec<String>> = BTreeMap::new();

    for item in reader.networks(WithinOptions::default())? {
        let item = item.context("failed to read ASN MMDB network")?;
        let network = item.network()?.to_string();
        if let Some(asn) = decode_asn(&item)? {
            if filter.as_ref().is_some_and(|filter| !filter.contains(&asn)) {
                continue;
            }
            by_asn.entry(asn).or_default().push(network);
        }
    }

    let mut outputs = Vec::with_capacity(by_asn.len());
    for (asn, mut cidrs) in by_asn {
        cidrs.sort();
        cidrs.dedup();
        outputs.push(AsnCidrSet { asn, cidrs });
    }
    Ok(outputs)
}

pub fn convert_asn_mmdb(input: impl AsRef<Path>, output: impl AsRef<Path>) -> Result<usize> {
    let input = input.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read ASN MMDB {}", input.display()))?;
    let (count, db) = convert_asn_mmdb_reader(reader)?;
    write_database(db, output.as_ref())?;
    Ok(count)
}

pub fn convert_asn_mmdb_to_bytes(input: &[u8]) -> Result<(usize, Vec<u8>)> {
    let reader = Reader::from_source(input).context("failed to read ASN MMDB payload")?;
    let (count, db) = convert_asn_mmdb_reader(reader)?;
    Ok((count, write_database_to_memory(db)?))
}

pub fn convert_asn_mmdb_file_to_bytes(input: impl AsRef<Path>) -> Result<(usize, Vec<u8>)> {
    let input = input.as_ref();
    let reader = Reader::open_readfile(input)
        .with_context(|| format!("failed to read ASN MMDB {}", input.display()))?;
    let (count, db) = convert_asn_mmdb_reader(reader)?;
    Ok((count, write_database_to_memory(db)?))
}

fn convert_asn_mmdb_reader<S: AsRef<[u8]>>(
    reader: Reader<S>,
) -> Result<(usize, maxminddb_writer::Database)> {
    let mut db = new_database(
        reader.metadata.ip_version == 6,
        "GeoLite2-ASN",
        "ASN database generated by rule-converter",
    );
    let mut values = HashMap::new();
    let mut count = 0usize;

    for item in reader.networks(WithinOptions::default())? {
        let item = item.context("failed to read ASN MMDB network")?;
        let Some(asn) = decode_asn(&item)? else {
            continue;
        };
        let data_ref = match values.get(&asn) {
            Some(data_ref) => *data_ref,
            None => {
                let data_ref = db.insert_value(AsnRecordValue {
                    autonomous_system_number: asn,
                    autonomous_system_organization: "",
                })?;
                values.insert(asn, data_ref);
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

    if count == 0 {
        bail!("ASN input does not contain any ASN records");
    }
    Ok((count, db))
}

pub fn build_asn_mmdb_from_paths<P, I>(entries: I, output: impl AsRef<Path>) -> Result<usize>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = (u32, P)>,
{
    let mut db = new_database(
        false,
        "GeoLite2-ASN",
        "ASN database generated by rule-converter",
    );
    let mut values = HashMap::new();
    let mut has_ipv6 = false;
    let mut count = 0usize;

    for (asn, path) in entries {
        if asn == 0 {
            bail!("ASN must be greater than 0");
        }
        let path = path.as_ref();
        count += for_each_cidr(path, |cidr| {
            has_ipv6 |= cidr.addr.is_ipv6();
            let data_ref = match values.get(&asn) {
                Some(data_ref) => *data_ref,
                None => {
                    let data_ref = db.insert_value(AsnRecordValue {
                        autonomous_system_number: asn,
                        autonomous_system_organization: "",
                    })?;
                    values.insert(asn, data_ref);
                    data_ref
                }
            };
            db.insert_node(cidr, data_ref);
            Ok(())
        })?;
    }

    if count == 0 {
        bail!("ASN input does not contain any CIDR records");
    }
    set_database_has_ipv6(&mut db, has_ipv6);
    write_database(db, output.as_ref())?;
    Ok(count)
}

pub fn build_asn_mmdb_from_rule_sets<I>(entries: I, output: impl AsRef<Path>) -> Result<usize>
where
    I: IntoIterator<Item = (u32, RuleSetOutput)>,
{
    let (count, db) = build_asn_mmdb_database_from_rule_sets(entries)?;
    write_database(db, output.as_ref())?;
    Ok(count)
}

pub fn build_asn_mmdb_from_rule_sets_to_bytes<I>(entries: I) -> Result<(usize, Vec<u8>)>
where
    I: IntoIterator<Item = (u32, RuleSetOutput)>,
{
    let (count, db) = build_asn_mmdb_database_from_rule_sets(entries)?;
    Ok((count, write_database_to_memory(db)?))
}

fn build_asn_mmdb_database_from_rule_sets<I>(
    entries: I,
) -> Result<(usize, maxminddb_writer::Database)>
where
    I: IntoIterator<Item = (u32, RuleSetOutput)>,
{
    let mut db = new_database(
        false,
        "GeoLite2-ASN",
        "ASN database generated by rule-converter",
    );
    let mut values = HashMap::new();
    let mut has_ipv6 = false;
    let mut count = 0usize;

    for (asn, rules) in entries {
        if asn == 0 {
            bail!("ASN must be greater than 0");
        }
        let data_ref = match values.get(&asn) {
            Some(data_ref) => *data_ref,
            None => {
                let data_ref = db.insert_value(AsnRecordValue {
                    autonomous_system_number: asn,
                    autonomous_system_organization: "",
                })?;
                values.insert(asn, data_ref);
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
        bail!("ASN input does not contain any CIDR records");
    }
    set_database_has_ipv6(&mut db, has_ipv6);
    Ok((count, db))
}

pub fn build_asn_mmdb_from_cidrs<I>(entries: I, output: impl AsRef<Path>) -> Result<usize>
where
    I: IntoIterator<Item = (u32, String)>,
{
    let mut db = new_database(
        false,
        "GeoLite2-ASN",
        "ASN database generated by rule-converter",
    );
    let mut values = HashMap::new();
    let mut has_ipv6 = false;
    let mut count = 0usize;

    for (asn, cidr) in entries {
        if asn == 0 {
            bail!("ASN must be greater than 0");
        }
        let parsed = parse_cidr_with_context(&format!("AS{asn}"), &cidr)?;
        has_ipv6 |= parsed.addr.is_ipv6();
        let data_ref = match values.get(&asn) {
            Some(data_ref) => *data_ref,
            None => {
                let data_ref = db.insert_value(AsnRecordValue {
                    autonomous_system_number: asn,
                    autonomous_system_organization: "",
                })?;
                values.insert(asn, data_ref);
                data_ref
            }
        };
        db.insert_node(parsed, data_ref);
        count += 1;
    }

    if count == 0 {
        bail!("ASN input does not contain any CIDR records");
    }
    set_database_has_ipv6(&mut db, has_ipv6);
    write_database(db, output.as_ref())?;
    Ok(count)
}

fn decode_asn<S: AsRef<[u8]>>(item: &maxminddb::LookupResult<'_, S>) -> Result<Option<u32>> {
    if let Some(value) = item.decode::<geoip2::Asn<'_>>()?
        && let Some(asn) = value.autonomous_system_number
    {
        return Ok(Some(asn));
    }
    if let Some(value) = item.decode::<AsnRecord<'_>>().ok().flatten()
        && let Some(asn) = value.autonomous_system_number
    {
        return Ok(Some(asn));
    }
    if let Some(value) = item.decode::<IpinfoAsnRecord<'_>>().ok().flatten()
        && let Some(asn) = value.asn.and_then(parse_ipinfo_asn)
    {
        return Ok(Some(asn));
    }
    Ok(None)
}

#[derive(Deserialize)]
struct AsnRecord<'a> {
    autonomous_system_number: Option<u32>,
    #[allow(dead_code)]
    autonomous_system_organization: Option<&'a str>,
}

#[derive(Deserialize)]
struct IpinfoAsnRecord<'a> {
    asn: Option<&'a str>,
    #[allow(dead_code)]
    name: Option<&'a str>,
}

#[derive(Serialize)]
struct AsnRecordValue<'a> {
    autonomous_system_number: u32,
    autonomous_system_organization: &'a str,
}

fn normalize_asn_filter(asns: &[u32]) -> Option<BTreeSet<u32>> {
    if asns.is_empty() {
        return None;
    }
    Some(asns.iter().copied().filter(|value| *value > 0).collect())
}

fn parse_ipinfo_asn(value: &str) -> Option<u32> {
    value
        .trim()
        .strip_prefix("AS")
        .or_else(|| value.trim().strip_prefix("as"))
        .unwrap_or_else(|| value.trim())
        .parse()
        .ok()
}
