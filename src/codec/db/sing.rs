use super::format::MmdbFormat;

pub(crate) fn geoip_database_type(format: MmdbFormat) -> &'static str {
    match format {
        MmdbFormat::Mmdb => "GeoLite2-Country",
        MmdbFormat::SingDb => "sing-geoip",
        MmdbFormat::MetaDb => "Meta-geoip0",
        MmdbFormat::Dat => unreachable!("dat is handled by codec::dat"),
    }
}
