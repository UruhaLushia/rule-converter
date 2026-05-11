use super::format::MmdbFormat;

pub(crate) fn geoip_database_type(format: MmdbFormat) -> &'static str {
    match format {
        MmdbFormat::Mmdb => "GeoLite2-Country",
        MmdbFormat::SingDb => "sing-geoip",
        MmdbFormat::MetaDb => "Meta-geoip0",
        MmdbFormat::Dat | MmdbFormat::SingGeosite => unreachable!("handled by DB dispatch"),
    }
}
