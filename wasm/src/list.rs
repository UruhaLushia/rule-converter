use rule_converter::{
    list_asn_mmdb_asns_from_bytes, list_geoip_dat_countries, list_geoip_mmdb_countries_from_bytes,
    list_geosite_dat_codes,
};
use wasm_bindgen::prelude::*;

use crate::error::to_js_error;

#[wasm_bindgen(js_name = listGeoipCountries)]
pub fn list_geoip_countries_wasm(payload: &[u8]) -> Result<JsValue, JsValue> {
    let countries = list_geoip_mmdb_countries_from_bytes(payload).map_err(to_js_error)?;
    serde_wasm_bindgen::to_value(&countries).map_err(to_js_error)
}

#[wasm_bindgen(js_name = listGeoipDatCountries)]
pub fn list_geoip_dat_countries_wasm(payload: &[u8]) -> Result<JsValue, JsValue> {
    let countries = list_geoip_dat_countries(payload).map_err(to_js_error)?;
    serde_wasm_bindgen::to_value(&countries).map_err(to_js_error)
}

#[wasm_bindgen(js_name = listGeositeCodes)]
pub fn list_geosite_codes_wasm(payload: &[u8]) -> Result<JsValue, JsValue> {
    let codes = list_geosite_dat_codes(payload).map_err(to_js_error)?;
    serde_wasm_bindgen::to_value(&codes).map_err(to_js_error)
}

#[wasm_bindgen(js_name = listAsnNumbers)]
pub fn list_asn_numbers_wasm(payload: &[u8]) -> Result<JsValue, JsValue> {
    let asns = list_asn_mmdb_asns_from_bytes(payload).map_err(to_js_error)?;
    serde_wasm_bindgen::to_value(&asns).map_err(to_js_error)
}
