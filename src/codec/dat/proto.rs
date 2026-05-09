mod fields;
mod model;
mod wire;

#[cfg(not(target_arch = "wasm32"))]
pub(super) use fields::for_each_raw_message_field_from_reader;
#[cfg(not(target_arch = "wasm32"))]
pub(super) use fields::write_raw_message_field_to_writer;
pub(super) use fields::{
    decode_varint, for_each_message_field, for_each_raw_message_field, scan_field,
    write_message_field, write_raw_message_field,
};
pub(super) use model::{Cidr, Domain, DomainType, GeoIp, GeoSite};
