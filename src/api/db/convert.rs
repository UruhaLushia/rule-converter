use anyhow::Result;
use std::path::Path;

use super::build::{
    build_asn_mmdb_to_memory, build_geoip_dat_to_memory, build_geoip_mmdb_to_memory,
    build_geosite_db_to_memory,
};
use super::types::DbBytesOutput;
use crate::codec::db::MmdbFormat;

pub fn convert_geoip_db_to_memory_filtered(
    input: impl AsRef<[u8]>,
    input_format: MmdbFormat,
    countries: &[String],
    output_format: MmdbFormat,
) -> Result<DbBytesOutput> {
    match (input_format, output_format) {
        (MmdbFormat::SingGeosite, _) | (_, MmdbFormat::SingGeosite) => {
            anyhow::bail!("unsupported geoip DB format conversion")
        }
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
    convert_geosite_db_to_memory_filtered(input, MmdbFormat::Dat, codes, MmdbFormat::Dat)
}

pub fn convert_geosite_db_to_memory_filtered(
    input: impl AsRef<[u8]>,
    input_format: MmdbFormat,
    codes: &[String],
    output_format: MmdbFormat,
) -> Result<DbBytesOutput> {
    let input = input.as_ref();
    match (input_format, output_format) {
        (MmdbFormat::Dat, MmdbFormat::Dat) => {
            let (count, bytes) = crate::codec::dat::filter_geosite_dat(input, codes)?;
            Ok(DbBytesOutput {
                format: MmdbFormat::Dat,
                count,
                bytes,
            })
        }
        (MmdbFormat::SingGeosite, MmdbFormat::SingGeosite) => {
            let (count, bytes) = crate::codec::db::filter_sing_geosite(input, codes)?;
            Ok(DbBytesOutput {
                format: MmdbFormat::SingGeosite,
                count,
                bytes,
            })
        }
        (MmdbFormat::Dat, MmdbFormat::SingGeosite) => {
            let sets = crate::codec::dat::collect_geosite_dat_rule_sets(input, codes)?;
            build_geosite_db_to_memory(
                sets.into_iter()
                    .map(|set| (set.code.clone(), set.into_result())),
                output_format,
            )
        }
        (MmdbFormat::SingGeosite, MmdbFormat::Dat) => {
            let sets = crate::codec::db::collect_sing_geosite_rule_sets(input, codes)?;
            build_geosite_db_to_memory(
                sets.into_iter()
                    .map(|set| (set.code.clone(), set.into_result())),
                output_format,
            )
        }
        _ => anyhow::bail!("geosite target only supports dat or sing-geosite format"),
    }
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
