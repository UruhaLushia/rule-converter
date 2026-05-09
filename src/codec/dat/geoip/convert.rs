use anyhow::{Context, Result};

use crate::codec::dat::proto::GeoIp;
use crate::codec::mihomo::mrs::IpCidrSetBuilder;

use super::address::addr_from_cidr;

pub(super) fn push_geoip_entry(builder: &mut IpCidrSetBuilder, entry: &GeoIp) -> Result<()> {
    if entry.reverse_match {
        return Ok(());
    }
    for cidr in &entry.cidr {
        let addr = addr_from_cidr(cidr)?;
        let prefix = u8::try_from(cidr.prefix).context("invalid geoip dat CIDR prefix")?;
        builder.insert_prefix(addr, prefix)?;
    }
    Ok(())
}
