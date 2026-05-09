use std::collections::BTreeSet;

use anyhow::Result;
use maxminddb::geoip2;
use serde::{Deserialize, Serialize};

pub(super) fn decode_asn<S: AsRef<[u8]>>(
    item: &maxminddb::LookupResult<'_, S>,
) -> Result<Option<u32>> {
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
pub(super) struct AsnRecordValue<'a> {
    pub(super) autonomous_system_number: u32,
    pub(super) autonomous_system_organization: &'a str,
}

pub(super) fn normalize_asn_filter(asns: &[u32]) -> Option<BTreeSet<u32>> {
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
