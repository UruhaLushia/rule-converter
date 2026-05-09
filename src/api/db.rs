use anyhow::Result;
use std::path::Path;

use crate::codec::db::MmdbFormat;
use crate::codec::mihomo::mrs::Behavior;
use crate::output::OutputFormat;
use crate::rules::BehaviorMode;
use crate::{RuleSetOutput, RuleTarget};

use super::{ConvertResult, convert_rule_set_output, write_outputs_as_to_memory_owned};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DbMemoryOutput {
    pub name: String,
    pub behavior: Behavior,
    pub format: OutputFormat,
    pub count: usize,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DbBytesOutput {
    pub format: MmdbFormat,
    pub count: usize,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DbStringOutput {
    pub name: String,
    pub behavior: Behavior,
    pub format: OutputFormat,
    pub count: usize,
    pub text: String,
}

pub fn export_geoip_db_to_memory(
    input: impl AsRef<[u8]>,
    input_format: MmdbFormat,
    countries: &[String],
    split: bool,
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<Vec<DbMemoryOutput>> {
    match input_format {
        MmdbFormat::Dat => {
            export_geoip_dat_to_memory(input, countries, split, target, format, behavior)
        }
        MmdbFormat::Mmdb | MmdbFormat::SingDb | MmdbFormat::MetaDb => {
            export_geoip_mmdb_to_memory(input, countries, split, target, format, behavior)
        }
    }
}

pub fn export_geoip_dat_to_memory(
    input: impl AsRef<[u8]>,
    countries: &[String],
    split: bool,
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<Vec<DbMemoryOutput>> {
    let input = input.as_ref();
    let behavior = normalize_db_output_behavior(target, format, behavior);
    if target == RuleTarget::General
        && format == OutputFormat::IpSet
        && behavior == BehaviorMode::Ipcidr
    {
        return crate::codec::dat::export_geoip_dat_ipset_to_memory(input, countries, split)?
            .into_iter()
            .map(|(name, count, bytes)| {
                Ok(DbMemoryOutput {
                    name,
                    behavior: Behavior::Ipcidr,
                    format,
                    count,
                    bytes,
                })
            })
            .collect();
    }
    if split {
        let sets = crate::codec::dat::collect_geoip_dat_rule_sets(input, countries)?;
        let mut outputs = Vec::new();
        for set in sets {
            outputs.extend(db_rule_set_to_memory(
                set.country,
                set.output,
                target,
                format,
                behavior,
            )?);
        }
        return Ok(outputs);
    }

    let rule_set = crate::codec::dat::collect_geoip_dat_rule_set(input, countries)?;
    db_rule_set_to_memory("geoip", rule_set, target, format, behavior)
}

pub fn export_geosite_dat_to_memory(
    input: impl AsRef<[u8]>,
    codes: &[String],
    split: bool,
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<Vec<DbMemoryOutput>> {
    let input = input.as_ref();
    let behavior = normalize_db_output_behavior(target, format, behavior);
    if target == RuleTarget::General
        && format == OutputFormat::RuleSet
        && behavior == BehaviorMode::Classical
    {
        return crate::codec::dat::export_geosite_dat_general_ruleset_to_memory(
            input, codes, split,
        )?
        .into_iter()
        .map(|(name, count, bytes)| {
            Ok(DbMemoryOutput {
                name,
                behavior: Behavior::Domain,
                format,
                count,
                bytes,
            })
        })
        .collect();
    }
    if split {
        let sets = crate::codec::dat::collect_geosite_dat_rule_sets(input, codes)?;
        let mut outputs = Vec::new();
        for set in sets {
            let name = set.code.clone();
            outputs.extend(db_convert_result_to_memory(
                name,
                set.into_result(),
                target,
                format,
                behavior,
            )?);
        }
        return Ok(outputs);
    }

    let result = crate::codec::dat::collect_geosite_dat_rule_set(input, codes)?;
    db_convert_result_to_memory("geosite", result, target, format, behavior)
}

pub fn export_geoip_mmdb_to_memory(
    input: impl AsRef<[u8]>,
    countries: &[String],
    split: bool,
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<Vec<DbMemoryOutput>> {
    let input = input.as_ref();
    let behavior = normalize_db_output_behavior(target, format, behavior);
    if can_stream_ipset(split, target, format, behavior) {
        let (count, bytes) = crate::codec::db::export_geoip_mmdb_ipset_to_bytes(input, countries)?;
        return Ok(vec![DbMemoryOutput {
            name: "geoip".to_string(),
            behavior: Behavior::Ipcidr,
            format,
            count,
            bytes,
        }]);
    }
    if split {
        let sets = crate::codec::db::collect_geoip_mmdb_rule_sets_from_bytes(input, countries)?;
        let mut outputs = Vec::new();
        for set in sets {
            outputs.extend(db_rule_set_to_memory(
                set.country,
                set.output,
                target,
                format,
                behavior,
            )?);
        }
        return Ok(outputs);
    }

    let rule_set = crate::codec::db::collect_geoip_mmdb_rule_set_from_bytes(input, countries)?;
    db_rule_set_to_memory("geoip", rule_set, target, format, behavior)
}

pub fn export_geoip_mmdb_file_to_memory(
    input: impl AsRef<Path>,
    countries: &[String],
    split: bool,
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<Vec<DbMemoryOutput>> {
    let behavior = normalize_db_output_behavior(target, format, behavior);
    if can_stream_ipset(split, target, format, behavior) {
        let (count, bytes) =
            crate::codec::db::export_geoip_mmdb_file_ipset_to_bytes(input, countries)?;
        return Ok(vec![DbMemoryOutput {
            name: "geoip".to_string(),
            behavior: Behavior::Ipcidr,
            format,
            count,
            bytes,
        }]);
    }
    if split {
        let sets = crate::codec::db::collect_geoip_mmdb_rule_sets(input, countries)?;
        let mut outputs = Vec::new();
        for set in sets {
            outputs.extend(db_rule_set_to_memory(
                set.country,
                set.output,
                target,
                format,
                behavior,
            )?);
        }
        return Ok(outputs);
    }

    let rule_set = crate::codec::db::collect_geoip_mmdb_rule_set(input, countries)?;
    db_rule_set_to_memory("geoip", rule_set, target, format, behavior)
}

pub fn export_asn_mmdb_to_memory(
    input: impl AsRef<[u8]>,
    asns: &[u32],
    split: bool,
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<Vec<DbMemoryOutput>> {
    let input = input.as_ref();
    let behavior = normalize_db_output_behavior(target, format, behavior);
    if can_stream_ipset(split, target, format, behavior) {
        let (count, bytes) = crate::codec::db::export_asn_mmdb_ipset_to_bytes(input, asns)?;
        return Ok(vec![DbMemoryOutput {
            name: "asn".to_string(),
            behavior: Behavior::Ipcidr,
            format,
            count,
            bytes,
        }]);
    }
    if split {
        let sets = crate::codec::db::collect_asn_mmdb_rule_sets_from_bytes(input, asns)?;
        let mut outputs = Vec::new();
        for set in sets {
            outputs.extend(db_rule_set_to_memory(
                set.asn.to_string(),
                set.output,
                target,
                format,
                behavior,
            )?);
        }
        return Ok(outputs);
    }

    let rule_set = crate::codec::db::collect_asn_mmdb_rule_set_from_bytes(input, asns)?;
    db_rule_set_to_memory("asn", rule_set, target, format, behavior)
}

pub fn export_asn_mmdb_file_to_memory(
    input: impl AsRef<Path>,
    asns: &[u32],
    split: bool,
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<Vec<DbMemoryOutput>> {
    let behavior = normalize_db_output_behavior(target, format, behavior);
    if can_stream_ipset(split, target, format, behavior) {
        let (count, bytes) = crate::codec::db::export_asn_mmdb_file_ipset_to_bytes(input, asns)?;
        return Ok(vec![DbMemoryOutput {
            name: "asn".to_string(),
            behavior: Behavior::Ipcidr,
            format,
            count,
            bytes,
        }]);
    }
    if split {
        let sets = crate::codec::db::collect_asn_mmdb_rule_sets(input, asns)?;
        let mut outputs = Vec::new();
        for set in sets {
            outputs.extend(db_rule_set_to_memory(
                set.asn.to_string(),
                set.output,
                target,
                format,
                behavior,
            )?);
        }
        return Ok(outputs);
    }

    let rule_set = crate::codec::db::collect_asn_mmdb_rule_set(input, asns)?;
    db_rule_set_to_memory("asn", rule_set, target, format, behavior)
}

pub fn export_geoip_mmdb_to_ipset_string(
    input: impl AsRef<[u8]>,
    countries: &[String],
) -> Result<DbStringOutput> {
    let (count, text) =
        crate::codec::db::export_geoip_mmdb_ipset_to_string(input.as_ref(), countries)?;
    Ok(db_ipset_string_output("geoip", count, text))
}

pub fn export_geoip_mmdb_file_to_ipset_string(
    input: impl AsRef<Path>,
    countries: &[String],
) -> Result<DbStringOutput> {
    let (count, text) = crate::codec::db::export_geoip_mmdb_file_ipset_to_string(input, countries)?;
    Ok(db_ipset_string_output("geoip", count, text))
}

pub fn export_asn_mmdb_to_ipset_string(
    input: impl AsRef<[u8]>,
    asns: &[u32],
) -> Result<DbStringOutput> {
    let (count, text) = crate::codec::db::export_asn_mmdb_ipset_to_string(input.as_ref(), asns)?;
    Ok(db_ipset_string_output("asn", count, text))
}

pub fn export_asn_mmdb_file_to_ipset_string(
    input: impl AsRef<Path>,
    asns: &[u32],
) -> Result<DbStringOutput> {
    let (count, text) = crate::codec::db::export_asn_mmdb_file_ipset_to_string(input, asns)?;
    Ok(db_ipset_string_output("asn", count, text))
}

pub fn convert_geoip_db_to_memory_filtered(
    input: impl AsRef<[u8]>,
    input_format: MmdbFormat,
    countries: &[String],
    output_format: MmdbFormat,
) -> Result<DbBytesOutput> {
    match (input_format, output_format) {
        (MmdbFormat::Dat, MmdbFormat::Dat) => {
            let (count, bytes) = crate::codec::dat::filter_geoip_dat(input.as_ref(), countries)?;
            Ok(DbBytesOutput {
                format: MmdbFormat::Dat,
                count,
                bytes,
            })
        }
        (MmdbFormat::Dat, MmdbFormat::Mmdb | MmdbFormat::SingDb | MmdbFormat::MetaDb) => {
            let sets = crate::codec::dat::collect_geoip_dat_rule_sets(input.as_ref(), countries)?;
            build_geoip_mmdb_to_memory(
                sets.into_iter().map(|set| (set.country, set.output)),
                output_format,
            )
        }
        (MmdbFormat::Mmdb | MmdbFormat::SingDb | MmdbFormat::MetaDb, MmdbFormat::Dat) => {
            let sets = crate::codec::db::collect_geoip_mmdb_rule_sets_from_bytes(
                input.as_ref(),
                countries,
            )?;
            build_geoip_dat_to_memory(sets.into_iter().map(|set| (set.country, set.output)))
        }
        (
            MmdbFormat::Mmdb | MmdbFormat::SingDb | MmdbFormat::MetaDb,
            MmdbFormat::Mmdb | MmdbFormat::SingDb | MmdbFormat::MetaDb,
        ) => convert_geoip_mmdb_to_memory_filtered(input, countries, output_format),
    }
}

pub fn convert_geosite_dat_to_memory_filtered(
    input: impl AsRef<[u8]>,
    codes: &[String],
) -> Result<DbBytesOutput> {
    let (count, bytes) = crate::codec::dat::filter_geosite_dat(input.as_ref(), codes)?;
    Ok(DbBytesOutput {
        format: MmdbFormat::Dat,
        count,
        bytes,
    })
}

pub fn convert_geoip_mmdb_to_memory(
    input: impl AsRef<[u8]>,
    output_format: MmdbFormat,
) -> Result<DbBytesOutput> {
    let (count, bytes) =
        crate::codec::db::convert_geoip_mmdb_to_bytes(input.as_ref(), output_format)?;
    Ok(DbBytesOutput {
        format: output_format,
        count,
        bytes,
    })
}

pub fn convert_geoip_mmdb_to_memory_filtered(
    input: impl AsRef<[u8]>,
    countries: &[String],
    output_format: MmdbFormat,
) -> Result<DbBytesOutput> {
    let (count, bytes) = crate::codec::db::convert_geoip_mmdb_to_bytes_filtered(
        input.as_ref(),
        output_format,
        countries,
    )?;
    Ok(DbBytesOutput {
        format: output_format,
        count,
        bytes,
    })
}

pub fn convert_geoip_mmdb_file_to_memory(
    input: impl AsRef<Path>,
    output_format: MmdbFormat,
) -> Result<DbBytesOutput> {
    let (count, bytes) = crate::codec::db::convert_geoip_mmdb_file_to_bytes(input, output_format)?;
    Ok(DbBytesOutput {
        format: output_format,
        count,
        bytes,
    })
}

pub fn convert_geoip_mmdb_file_to_memory_filtered(
    input: impl AsRef<Path>,
    countries: &[String],
    output_format: MmdbFormat,
) -> Result<DbBytesOutput> {
    let (count, bytes) = crate::codec::db::convert_geoip_mmdb_file_to_bytes_filtered(
        input,
        output_format,
        countries,
    )?;
    Ok(DbBytesOutput {
        format: output_format,
        count,
        bytes,
    })
}

pub fn convert_asn_mmdb_to_memory(input: impl AsRef<[u8]>) -> Result<DbBytesOutput> {
    let (count, bytes) = crate::codec::db::convert_asn_mmdb_to_bytes(input.as_ref())?;
    Ok(DbBytesOutput {
        format: MmdbFormat::Mmdb,
        count,
        bytes,
    })
}

pub fn convert_asn_mmdb_to_memory_filtered(
    input: impl AsRef<[u8]>,
    asns: &[u32],
) -> Result<DbBytesOutput> {
    let input = input.as_ref();
    if asns.is_empty() {
        return convert_asn_mmdb_to_memory(input);
    }

    let entries = crate::codec::db::collect_asn_mmdb_rule_sets_from_bytes(input, asns)?
        .into_iter()
        .map(|set| (set.asn, set.output));
    build_asn_mmdb_to_memory(entries)
}

pub fn convert_asn_mmdb_file_to_memory(input: impl AsRef<Path>) -> Result<DbBytesOutput> {
    let (count, bytes) = crate::codec::db::convert_asn_mmdb_file_to_bytes(input)?;
    Ok(DbBytesOutput {
        format: MmdbFormat::Mmdb,
        count,
        bytes,
    })
}

pub fn convert_asn_mmdb_file_to_memory_filtered(
    input: impl AsRef<Path>,
    asns: &[u32],
) -> Result<DbBytesOutput> {
    let input = input.as_ref();
    if asns.is_empty() {
        return convert_asn_mmdb_file_to_memory(input);
    }

    let entries = crate::codec::db::collect_asn_mmdb_rule_sets(input, asns)?
        .into_iter()
        .map(|set| (set.asn, set.output));
    build_asn_mmdb_to_memory(entries)
}

pub fn build_geoip_db_to_memory<I>(entries: I, output_format: MmdbFormat) -> Result<DbBytesOutput>
where
    I: IntoIterator<Item = (String, RuleSetOutput)>,
{
    match output_format {
        MmdbFormat::Dat => build_geoip_dat_to_memory(entries),
        MmdbFormat::Mmdb | MmdbFormat::SingDb | MmdbFormat::MetaDb => {
            build_geoip_mmdb_to_memory(entries, output_format)
        }
    }
}

pub fn build_geoip_dat_to_memory<I>(entries: I) -> Result<DbBytesOutput>
where
    I: IntoIterator<Item = (String, RuleSetOutput)>,
{
    let (count, bytes) = crate::codec::dat::build_geoip_dat_from_rule_sets(entries)?;
    Ok(DbBytesOutput {
        format: MmdbFormat::Dat,
        count,
        bytes,
    })
}

pub fn build_geosite_dat_to_memory<I>(entries: I) -> Result<DbBytesOutput>
where
    I: IntoIterator<Item = (String, ConvertResult)>,
{
    let (count, bytes) = crate::codec::dat::build_geosite_dat_from_rule_sets(entries)?;
    Ok(DbBytesOutput {
        format: MmdbFormat::Dat,
        count,
        bytes,
    })
}

pub fn build_geoip_mmdb_to_memory<I>(entries: I, output_format: MmdbFormat) -> Result<DbBytesOutput>
where
    I: IntoIterator<Item = (String, RuleSetOutput)>,
{
    let (count, bytes) =
        crate::codec::db::build_geoip_mmdb_from_rule_sets_to_bytes(entries, output_format)?;
    Ok(DbBytesOutput {
        format: output_format,
        count,
        bytes,
    })
}

pub fn build_asn_mmdb_to_memory<I>(entries: I) -> Result<DbBytesOutput>
where
    I: IntoIterator<Item = (u32, RuleSetOutput)>,
{
    let (count, bytes) = crate::codec::db::build_asn_mmdb_from_rule_sets_to_bytes(entries)?;
    Ok(DbBytesOutput {
        format: MmdbFormat::Mmdb,
        count,
        bytes,
    })
}

fn db_convert_result_to_memory(
    name: impl Into<String>,
    mut result: ConvertResult,
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<Vec<DbMemoryOutput>> {
    result.output_behavior = behavior;
    let (outputs, _) = write_outputs_as_to_memory_owned(result, target, format)?;
    let name = name.into();
    Ok(outputs
        .into_iter()
        .map(|output| DbMemoryOutput {
            name: name.clone(),
            behavior: output.behavior,
            format: output.format,
            count: output.count,
            bytes: output.bytes,
        })
        .collect())
}

fn db_rule_set_to_memory(
    name: impl Into<String>,
    rule_set: RuleSetOutput,
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<Vec<DbMemoryOutput>> {
    let result = convert_rule_set_output(rule_set, behavior);
    let (outputs, _) = write_outputs_as_to_memory_owned(result, target, format)?;
    let name = name.into();
    Ok(outputs
        .into_iter()
        .map(|output| DbMemoryOutput {
            name: name.clone(),
            behavior: output.behavior,
            format: output.format,
            count: output.count,
            bytes: output.bytes,
        })
        .collect())
}

fn normalize_db_output_behavior(
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> BehaviorMode {
    match (target, format, behavior) {
        (RuleTarget::General, OutputFormat::IpSet, _) => BehaviorMode::Ipcidr,
        (RuleTarget::General, OutputFormat::DomainSet, _) => BehaviorMode::Domain,
        (_, _, BehaviorMode::Auto) => BehaviorMode::Ipcidr,
        _ => behavior,
    }
}

fn can_stream_ipset(
    split: bool,
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> bool {
    !split
        && target == RuleTarget::General
        && format == OutputFormat::IpSet
        && behavior == BehaviorMode::Ipcidr
}

fn db_ipset_string_output(name: &str, count: usize, text: String) -> DbStringOutput {
    DbStringOutput {
        name: name.to_string(),
        behavior: Behavior::Ipcidr,
        format: OutputFormat::IpSet,
        count,
        text,
    }
}
