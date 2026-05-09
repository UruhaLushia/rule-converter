use anyhow::{Context, Result};
use maxminddb_writer::Database;
use maxminddb_writer::metadata::IpVersion;
use maxminddb_writer::paths::IpAddrWithMask;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use crate::codec::mihomo::mrs::{Behavior, write_i64};

pub(crate) fn for_each_cidr(
    path: &Path,
    mut f: impl FnMut(IpAddrWithMask) -> Result<()>,
) -> Result<usize> {
    let file = File::open(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut count = 0usize;
    for line in BufReader::new(file).lines() {
        let line = line.with_context(|| format!("failed to read {}", path.display()))?;
        let Some(cidr) = parse_cidr_line(&line) else {
            continue;
        };
        f(parse_cidr(path, cidr)?)?;
        count += 1;
    }
    Ok(count)
}

pub(crate) fn parse_cidr_line(line: &str) -> Option<&str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
        return None;
    }
    if let Some((kind, rest)) = line.split_once(',')
        && (kind.eq_ignore_ascii_case("IP-CIDR") || kind.eq_ignore_ascii_case("IP-CIDR6"))
    {
        return rest
            .split(',')
            .next()
            .map(str::trim)
            .filter(|value| !value.is_empty());
    }
    Some(line)
}

pub(crate) fn parse_cidr(path: &Path, cidr: &str) -> Result<IpAddrWithMask> {
    parse_cidr_with_context(&path.display().to_string(), cidr)
}

pub(crate) fn parse_cidr_with_context(context: &str, cidr: &str) -> Result<IpAddrWithMask> {
    cidr.parse()
        .with_context(|| format!("invalid CIDR `{cidr}` in {context}"))
}

pub(crate) fn new_database(has_ipv6: bool, database_type: &str, description: &str) -> Database {
    let mut db = Database::default();
    db.metadata.ip_version = if has_ipv6 {
        IpVersion::V6
    } else {
        IpVersion::V4
    };
    db.metadata.database_type = database_type.to_string();
    db.metadata.languages = vec!["en".to_string()];
    db.metadata.binary_format_major_version = 2;
    db.metadata.binary_format_minor_version = 0;
    db.metadata.build_epoch = database_build_epoch();
    db.metadata.description = HashMap::from([("en".to_string(), description.to_string())]);
    db
}

#[cfg(not(target_arch = "wasm32"))]
fn database_build_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

#[cfg(target_arch = "wasm32")]
fn database_build_epoch() -> u64 {
    0
}

pub(crate) fn set_database_has_ipv6(db: &mut Database, has_ipv6: bool) {
    db.metadata.ip_version = if has_ipv6 {
        IpVersion::V6
    } else {
        IpVersion::V4
    };
}

pub(crate) fn write_ip_prefix_range<W: Write>(
    writer: &mut W,
    addr: IpAddr,
    prefix_len: u8,
) -> io::Result<()> {
    let (from, to) = ip_prefix_range(addr, prefix_len);
    writer.write_all(&ip_to_as16(addr, from))?;
    writer.write_all(&ip_to_as16(addr, to))?;
    Ok(())
}

pub(crate) fn write_mrs_ipcidr_header<W: Write>(writer: &mut W, count: usize) -> Result<()> {
    writer.write_all(b"MRS\x01")?;
    writer.write_all(&[Behavior::Ipcidr.byte()])?;
    write_i64(writer, count as i64)?;
    write_i64(writer, 0)?;
    writer.write_all(&[1])?;
    write_i64(writer, count as i64)?;
    Ok(())
}

fn ip_prefix_range(addr: IpAddr, prefix_len: u8) -> (u128, u128) {
    match addr {
        IpAddr::V4(addr) => {
            let raw = u32::from(addr) as u128;
            let mask = if prefix_len == 0 {
                0
            } else {
                (!0u32 << (32 - prefix_len)) as u128
            };
            let from = raw & mask;
            (from, from | ((!mask) & u32::MAX as u128))
        }
        IpAddr::V6(addr) => {
            let raw = u128::from(addr);
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u128 << (128 - prefix_len)
            };
            let from = raw & mask;
            (from, from | !mask)
        }
    }
}

fn ip_to_as16(addr: IpAddr, value: u128) -> [u8; 16] {
    match addr {
        IpAddr::V4(_) => {
            let mut bytes = [0; 16];
            bytes[10] = 0xff;
            bytes[11] = 0xff;
            bytes[12..16].copy_from_slice(&(value as u32).to_be_bytes());
            bytes
        }
        IpAddr::V6(_) => Ipv6Addr::from(value).octets(),
    }
}

pub(crate) fn write_database(db: Database, output: &Path) -> Result<()> {
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    }
    let writer = BufWriter::new(
        File::create(output).with_context(|| format!("failed to create {}", output.display()))?,
    );
    db.write_to(writer)?;
    Ok(())
}

pub(crate) fn write_database_to_memory(db: Database) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    db.write_to(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_classical_cidr_lines() {
        assert_eq!(parse_cidr_line("1.1.1.0/24"), Some("1.1.1.0/24"));
        assert_eq!(
            parse_cidr_line("IP-CIDR,1.1.1.0/24,no-resolve"),
            Some("1.1.1.0/24")
        );
        assert_eq!(parse_cidr_line("# comment"), None);
    }
}
