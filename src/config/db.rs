use anyhow::{Result, bail};

use super::{ConfigDefaults, ConfigInputFile, ConfigOutputFile, DbTarget, MmdbFormat};

pub(super) fn db_export_job(
    input: &ConfigInputFile,
    output: &ConfigOutputFile,
    defaults: &ConfigDefaults,
) -> Result<Option<(DbTarget, MmdbFormat)>> {
    let Some(target) = input.target.as_deref().and_then(DbTarget::parse) else {
        return Ok(None);
    };
    let format = parse_db_format(input.format.as_deref())?;
    validate_db_format(target, format)?;
    if output.path.is_none() && output.dir.is_none() {
        return Ok(None);
    }
    if output
        .target
        .as_deref()
        .or(defaults.output_target.as_deref())
        .and_then(DbTarget::parse)
        .is_some()
    {
        return Ok(None);
    }
    Ok(Some((target, format)))
}

pub(super) fn db_build_job(
    input: &ConfigInputFile,
    output: &ConfigOutputFile,
) -> Result<Option<(DbTarget, MmdbFormat)>> {
    let Some(target) = output.target.as_deref().and_then(DbTarget::parse) else {
        return Ok(None);
    };
    let format = parse_db_format(output.format.as_deref())?;
    validate_db_format(target, format)?;
    if input.inputs.is_none() || output.path.is_none() {
        return Ok(None);
    }
    Ok(Some((target, format)))
}

pub(super) fn db_convert_job(
    input: &ConfigInputFile,
    output: &ConfigOutputFile,
) -> Result<Option<(DbTarget, MmdbFormat, MmdbFormat)>> {
    let Some(input_target) = input.target.as_deref().and_then(DbTarget::parse) else {
        return Ok(None);
    };
    let Some(output_target) = output.target.as_deref().and_then(DbTarget::parse) else {
        return Ok(None);
    };
    if input_target != output_target || input.path.is_none() || output.path.is_none() {
        return Ok(None);
    }

    let input_format = parse_db_format(input.format.as_deref())?;
    let output_format = parse_db_format(output.format.as_deref())?;
    validate_db_format(input_target, input_format)?;
    validate_db_format(output_target, output_format)?;
    Ok(Some((input_target, input_format, output_format)))
}

fn parse_db_format(format: Option<&str>) -> Result<MmdbFormat> {
    format
        .map(MmdbFormat::parse)
        .transpose()
        .map(|value| value.unwrap_or(MmdbFormat::Mmdb))
}

fn validate_db_format(target: DbTarget, format: MmdbFormat) -> Result<()> {
    match target {
        DbTarget::Geoip if format != MmdbFormat::SingGeosite => Ok(()),
        DbTarget::Geoip => bail!("geoip target does not support sing-geosite format"),
        DbTarget::Geosite if matches!(format, MmdbFormat::Dat | MmdbFormat::SingGeosite) => Ok(()),
        DbTarget::Geosite => bail!("geosite target only supports dat or sing-geosite format"),
        DbTarget::Asn if format == MmdbFormat::Mmdb => Ok(()),
        DbTarget::Asn => bail!("ASN target only supports mmdb format"),
    }
}
