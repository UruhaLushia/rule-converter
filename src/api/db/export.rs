use super::common::{
    db_convert_result_to_memory, db_rule_set_to_memory, normalize_geoip_output_behavior,
    normalize_geosite_output_behavior,
};
use super::export_mmdb::export_geoip_mmdb_to_memory;
use super::types::DbMemoryOutput;
use crate::RuleTarget;
use crate::codec::db::MmdbFormat;
use crate::codec::mihomo::mrs::Behavior;
use crate::output::OutputFormat;
use crate::rules::BehaviorMode;
use anyhow::Result;

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
        MmdbFormat::SingGeosite => {
            anyhow::bail!("geoip target does not support sing-geosite format")
        }
    }
}

pub fn export_geosite_db_to_memory(
    input: impl AsRef<[u8]>,
    input_format: MmdbFormat,
    codes: &[String],
    split: bool,
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<Vec<DbMemoryOutput>> {
    match input_format {
        MmdbFormat::Dat => {
            export_geosite_dat_to_memory(input, codes, split, target, format, behavior)
        }
        MmdbFormat::SingGeosite => {
            export_sing_geosite_to_memory(input, codes, split, target, format, behavior)
        }
        _ => anyhow::bail!("geosite target only supports dat or sing-geosite format"),
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
    let behavior = normalize_geoip_output_behavior(target, format, behavior)?;
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
    let behavior = normalize_geosite_output_behavior(target, format, behavior)?;
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

fn export_sing_geosite_to_memory(
    input: impl AsRef<[u8]>,
    codes: &[String],
    split: bool,
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> Result<Vec<DbMemoryOutput>> {
    let input = input.as_ref();
    let behavior = normalize_geosite_output_behavior(target, format, behavior)?;
    if split {
        let sets = crate::codec::db::collect_sing_geosite_rule_sets(input, codes)?;
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

    let result = crate::codec::db::collect_sing_geosite_rule_set(input, codes)?;
    db_convert_result_to_memory("geosite", result, target, format, behavior)
}
