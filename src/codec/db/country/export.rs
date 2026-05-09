use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use maxminddb::{Reader, WithinOptions};

use super::GeoipOutputFile;
use super::collect::collect_geoip_mmdb_cidrs;
use super::common::{geoip_item_matches_filter, normalize_country_code, normalize_country_filter};
use crate::codec::db::common::{write_ip_prefix_range, write_mrs_ipcidr_header};

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
