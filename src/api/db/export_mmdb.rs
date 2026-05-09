use anyhow::Result;
use std::path::Path;

use super::common::{
    can_stream_ipset, db_ipset_string_output, db_rule_set_to_memory, normalize_db_output_behavior,
};
use super::types::{DbMemoryOutput, DbStringOutput};
use crate::RuleTarget;
use crate::codec::mihomo::mrs::Behavior;
use crate::output::OutputFormat;
use crate::rules::BehaviorMode;

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
