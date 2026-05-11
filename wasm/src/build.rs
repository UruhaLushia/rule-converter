mod convert;
mod entries;
mod options;

use rule_converter::{
    MmdbFormat, build_asn_mmdb_to_memory, build_geoip_db_to_memory, build_geosite_db_to_memory,
};
use wasm_bindgen::prelude::*;

use crate::error::to_js_error;
use crate::result::any_db_to_js;
use crate::types::BuildDbOptions;

use entries::{append_asn_entries, append_geoip_entries, append_geosite_entries};
use options::{BuildDefaults, parse_db_format};

#[wasm_bindgen(js_name = buildDb)]
pub fn build_db_wasm(options: JsValue) -> Result<JsValue, JsValue> {
    let options: BuildDbOptions = serde_wasm_bindgen::from_value(options).map_err(to_js_error)?;
    if options.entries.is_empty() {
        return Err(to_js_error("DB build needs at least one input"));
    }
    match options.output_target.as_str() {
        "geoip" => build_geoip(options),
        "geosite" => build_geosite(options),
        "asn" => build_asn(options),
        value => Err(to_js_error(format!(
            "unsupported DB output target: {value}"
        ))),
    }
}

fn build_geoip(options: BuildDbOptions) -> Result<JsValue, JsValue> {
    let output_format = parse_db_format(options.output_format.as_deref(), MmdbFormat::Mmdb)?;
    let defaults = BuildDefaults::from_options(&options);
    let mut entries = Vec::new();
    for entry in options.entries {
        append_geoip_entries(entry, &defaults, &mut entries)?;
    }
    any_db_to_js(build_geoip_db_to_memory(entries, output_format).map_err(to_js_error)?)
}

fn build_geosite(options: BuildDbOptions) -> Result<JsValue, JsValue> {
    let output_format = parse_db_format(options.output_format.as_deref(), MmdbFormat::Dat)?;
    let defaults = BuildDefaults::from_options(&options);
    let mut entries = Vec::new();
    for entry in options.entries {
        append_geosite_entries(entry, &defaults, &mut entries)?;
    }
    any_db_to_js(build_geosite_db_to_memory(entries, output_format).map_err(to_js_error)?)
}

fn build_asn(options: BuildDbOptions) -> Result<JsValue, JsValue> {
    let defaults = BuildDefaults::from_options(&options);
    let mut entries = Vec::new();
    for entry in options.entries {
        append_asn_entries(entry, &defaults, &mut entries)?;
    }
    any_db_to_js(build_asn_mmdb_to_memory(entries).map_err(to_js_error)?)
}
