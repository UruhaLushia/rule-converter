use anyhow::{Result, bail};

use crate::codec::dat::proto::{GeoIp, write_message_field};
use crate::codec::mihomo::mrs::RuleSetOutput;

use super::address::cidr_from_prefix;
use super::filter::normalize_country_code;

pub fn build_geoip_dat_from_rule_sets<I>(entries: I) -> Result<(usize, Vec<u8>)>
where
    I: IntoIterator<Item = (String, RuleSetOutput)>,
{
    let mut count = 0usize;
    let mut output = Vec::new();
    for (country, rules) in entries {
        let country = normalize_country_code(&country);
        if country.is_empty() {
            bail!("GeoIP country is empty");
        }
        let mut cidr = Vec::new();
        rules.for_each_ip_prefix(|addr, prefix| {
            cidr.push(cidr_from_prefix(addr, prefix));
            count += 1;
            Ok(())
        })?;
        if !cidr.is_empty() {
            write_message_field(
                &mut output,
                1,
                &GeoIp {
                    country_code: country,
                    cidr,
                    reverse_match: false,
                },
            )?;
        }
    }
    if count == 0 {
        bail!("geoip dat output does not contain any CIDR records");
    }
    Ok((count, output))
}
