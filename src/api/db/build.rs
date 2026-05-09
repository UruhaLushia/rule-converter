use anyhow::Result;

use super::types::DbBytesOutput;
use crate::codec::db::MmdbFormat;
use crate::{ConvertResult, RuleSetOutput};

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
