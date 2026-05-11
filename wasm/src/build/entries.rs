use rule_converter::{ConvertResult, MmdbFormat, RuleSetOutput};
use wasm_bindgen::JsValue;

use super::convert::{
    collect_ip_rule_set, convert_to_classical, db_asn_payload_to_rule_set,
    db_geoip_payload_to_rule_set, db_geosite_payload_to_classical,
};
use super::options::{
    BuildDefaults, db_input_format, entry_keys, is_database_entry, normalize_key, parse_asn,
};
use crate::types::BuildDbEntry;

pub(super) fn append_geoip_entries(
    entry: BuildDbEntry,
    defaults: &BuildDefaults,
    output: &mut Vec<(String, RuleSetOutput)>,
) -> Result<(), JsValue> {
    if is_database_entry(&entry) {
        let input_format = db_input_format(&entry, defaults, MmdbFormat::Mmdb)?;
        for key in entry_keys(&entry) {
            output.push((
                normalize_key(&key)?,
                db_geoip_payload_to_rule_set(&entry.payload, input_format, &key)?,
            ));
        }
        return Ok(());
    }
    output.push((
        normalize_key(&entry.key)?,
        collect_ip_rule_set(entry, defaults)?,
    ));
    Ok(())
}

pub(super) fn append_geosite_entries(
    entry: BuildDbEntry,
    defaults: &BuildDefaults,
    output: &mut Vec<(String, ConvertResult)>,
) -> Result<(), JsValue> {
    if is_database_entry(&entry) {
        let input_format = db_input_format(&entry, defaults, MmdbFormat::Dat)?;
        for key in entry_keys(&entry) {
            output.push((
                normalize_key(&key)?,
                db_geosite_payload_to_classical(&entry.payload, input_format, &key)?,
            ));
        }
        return Ok(());
    }
    output.push((
        normalize_key(&entry.key)?,
        convert_to_classical(entry, defaults)?,
    ));
    Ok(())
}

pub(super) fn append_asn_entries(
    entry: BuildDbEntry,
    defaults: &BuildDefaults,
    output: &mut Vec<(u32, RuleSetOutput)>,
) -> Result<(), JsValue> {
    if is_database_entry(&entry) {
        for key in entry_keys(&entry) {
            output.push((
                parse_asn(&key)?,
                db_asn_payload_to_rule_set(&entry.payload, &key)?,
            ));
        }
        return Ok(());
    }
    output.push((
        parse_asn(&entry.key)?,
        collect_ip_rule_set(entry, defaults)?,
    ));
    Ok(())
}
