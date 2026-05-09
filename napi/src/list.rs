use napi::bindgen_prelude::{Result, Uint8Array};
use napi_derive::napi;
use rule_converter::{
    list_asn_mmdb_asns, list_asn_mmdb_asns_from_bytes,
    list_geoip_dat_countries as list_geoip_dat_countries_from_bytes_core,
    list_geoip_mmdb_countries, list_geoip_mmdb_countries_from_bytes, list_geosite_dat_codes,
};

use crate::error::to_napi_error;

#[napi]
pub fn list_geoip_countries(input: String) -> Result<Vec<String>> {
    list_geoip_mmdb_countries(input).map_err(to_napi_error)
}

#[napi]
pub fn list_geoip_countries_from_buffer(input: Uint8Array) -> Result<Vec<String>> {
    list_geoip_mmdb_countries_from_bytes(input.as_ref()).map_err(to_napi_error)
}

#[napi]
pub fn list_geoip_dat_countries_from_buffer(input: Uint8Array) -> Result<Vec<String>> {
    list_geoip_dat_countries_from_bytes_core(input.as_ref()).map_err(to_napi_error)
}

#[napi]
pub fn list_geosite_codes_from_buffer(input: Uint8Array) -> Result<Vec<String>> {
    list_geosite_dat_codes(input.as_ref()).map_err(to_napi_error)
}

#[napi]
pub fn list_geosite_codes(input: String) -> Result<Vec<String>> {
    let bytes = std::fs::read(input).map_err(|err| napi::Error::from_reason(err.to_string()))?;
    list_geosite_dat_codes(&bytes).map_err(to_napi_error)
}

#[napi]
pub fn list_geoip_dat_countries(input: String) -> Result<Vec<String>> {
    let bytes = std::fs::read(input).map_err(|err| napi::Error::from_reason(err.to_string()))?;
    list_geoip_dat_countries_from_bytes_core(&bytes).map_err(to_napi_error)
}

#[napi]
pub fn list_asn_numbers(input: String) -> Result<Vec<u32>> {
    list_asn_mmdb_asns(input).map_err(to_napi_error)
}

#[napi]
pub fn list_asn_numbers_from_buffer(input: Uint8Array) -> Result<Vec<u32>> {
    list_asn_mmdb_asns_from_bytes(input.as_ref()).map_err(to_napi_error)
}
