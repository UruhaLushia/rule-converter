use anyhow::{Result, bail};

use crate::api::ConvertResult;
use crate::codec::dat::proto::{GeoSite, write_message_field};
use crate::codec::mihomo::mrs::RuleSetOutput;

use super::convert::{domain_from_mixed_rule, domain_from_rule};
use super::filter::normalize_code;

pub fn build_geosite_dat_from_rule_sets<I>(entries: I) -> Result<(usize, Vec<u8>)>
where
    I: IntoIterator<Item = (String, ConvertResult)>,
{
    let mut count = 0usize;
    let mut output = Vec::new();

    for (code, result) in entries {
        let code = normalize_code(&code);
        if code.is_empty() {
            bail!("geosite code is empty");
        }
        let mut domain = Vec::new();
        for output in result.outputs {
            if let RuleSetOutput::Domain(set) = output {
                set.for_each_rule(|rule| {
                    if let Some(item) = domain_from_rule(rule) {
                        domain.push(item);
                        count += 1;
                    }
                    Ok(())
                })?;
            }
        }
        for rule in result.mixed_rules.iter() {
            if let Some(item) = domain_from_mixed_rule(rule)? {
                domain.push(item);
                count += 1;
            }
        }
        if !domain.is_empty() {
            write_message_field(
                &mut output,
                1,
                &GeoSite {
                    country_code: code,
                    domain,
                },
            )?;
        }
    }

    if count == 0 {
        bail!("geosite dat output does not contain any domain records");
    }
    Ok((count, output))
}
