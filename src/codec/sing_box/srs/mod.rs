use std::io::{Cursor, Read, Write};

use anyhow::{Context, Result, bail};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;

mod binary;
mod classical;
mod constants;
mod domain;
mod ip_set;
mod rule_item;

use binary::{read_byte, read_uvarint, write_uvarint};
use classical::GroupedClassicalRuleCounts;
use constants::{RULE_DEFAULT, RULE_LOGICAL};
use rule_item::{read_default_rule, write_default_rule};

use crate::rules::RuleTextStore;

use super::RuleSet;
use super::RuleStore;
use super::rule::VERSION_CURRENT;

const MAGIC: &[u8; 3] = b"SRS";

pub fn parse_srs(raw: &[u8]) -> Result<Vec<String>> {
    Ok(read_srs(raw)?.to_classical_rules())
}

pub fn read_srs(raw: &[u8]) -> Result<RuleSet> {
    let mut reader = Cursor::new(raw);
    let mut magic = [0; 3];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        bail!("invalid sing-box SRS magic bytes");
    }

    let version = read_byte(&mut reader)?;
    if version > VERSION_CURRENT {
        bail!("unsupported sing-box SRS version: {version}");
    }

    let mut decoder = ZlibDecoder::new(reader);
    let rule_count = read_uvarint(&mut decoder)?;
    let mut rules = Vec::with_capacity(rule_count as usize);
    for index in 0..rule_count {
        let rule_type = read_byte(&mut decoder)
            .with_context(|| format!("failed to read sing-box SRS rule {index}"))?;
        match rule_type {
            RULE_DEFAULT => rules.push(read_default_rule(&mut decoder)?),
            RULE_LOGICAL => bail!("sing-box SRS logical rules are not supported yet"),
            other => bail!("unknown sing-box SRS rule type: {other}"),
        }
    }

    Ok(RuleSet { version, rules })
}

pub fn write_srs<W: Write>(mut writer: W, rule_set: &RuleSet) -> Result<()> {
    writer.write_all(MAGIC)?;
    writer.write_all(&[VERSION_CURRENT])?;
    let mut encoder = ZlibEncoder::new(writer, Compression::best());
    write_uvarint(&mut encoder, rule_set.rules.len() as u64)?;
    for rule in &rule_set.rules {
        write_default_rule(&mut encoder, rule)?;
    }
    encoder.finish().context("failed to finish sing-box SRS")?;
    Ok(())
}

pub fn write_classical_srs<W: Write>(mut writer: W, rules: &RuleTextStore) -> Result<usize> {
    let grouped = GroupedClassicalRuleCounts::from_rules(rules);
    writer.write_all(MAGIC)?;
    writer.write_all(&[VERSION_CURRENT])?;
    let mut encoder = ZlibEncoder::new(writer, Compression::fast());
    write_uvarint(&mut encoder, grouped.rule_count() as u64)?;
    grouped.write(&mut encoder, rules)?;
    encoder.finish().context("failed to finish sing-box SRS")?;
    Ok(grouped.item_count())
}

pub fn write_store_srs<W: Write>(mut writer: W, store: &RuleStore) -> Result<usize> {
    writer.write_all(MAGIC)?;
    writer.write_all(&[VERSION_CURRENT])?;
    let mut encoder = ZlibEncoder::new(writer, Compression::fast());
    write_uvarint(&mut encoder, store.rule_count() as u64)?;
    rule_item::write_store_rules(&mut encoder, store)?;
    encoder.finish().context("failed to finish sing-box SRS")?;
    Ok(store.count())
}

pub fn write_owned_store_srs<W: Write>(mut writer: W, store: RuleStore) -> Result<usize> {
    let count = store.count();
    let rule_count = store.rule_count();
    writer.write_all(MAGIC)?;
    writer.write_all(&[VERSION_CURRENT])?;
    let mut encoder = ZlibEncoder::new(writer, Compression::fast());
    write_uvarint(&mut encoder, rule_count as u64)?;
    rule_item::write_owned_store_rules(&mut encoder, store)?;
    encoder.finish().context("failed to finish sing-box SRS")?;
    Ok(count)
}
