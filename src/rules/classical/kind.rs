#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClassicalKind {
    Domain,
    DomainSuffix,
    DomainWildcard,
    DomainKeyword,
    DomainRegex,
    DomainSet,
    Ipcidr,
    IpSuffix,
    IpAsn,
    SrcIpcidr,
    SrcGeoip,
    SrcIpAsn,
    SrcIpSuffix,
    Geoip,
    Geosite,
    DstPort,
    SrcPort,
    SrcIp,
    InPort,
    InType,
    InUser,
    InName,
    ProcessPath,
    ProcessPathWildcard,
    ProcessPathRegex,
    ProcessName,
    ProcessNameWildcard,
    ProcessNameRegex,
    Uid,
    Network,
    Protocol,
    Dscp,
    UserAgent,
    UrlRegex,
    Script,
    CellularRadio,
    DeviceName,
    MacAddress,
    HostnameType,
    Match,
    RuleSet,
    And,
    Or,
    Not,
    SubRule,
}

pub(super) fn parse_kind(value: &str) -> Option<ClassicalKind> {
    if value.eq_ignore_ascii_case("DOMAIN") {
        Some(ClassicalKind::Domain)
    } else if value.eq_ignore_ascii_case("DOMAIN-SUFFIX") {
        Some(ClassicalKind::DomainSuffix)
    } else if value.eq_ignore_ascii_case("DOMAIN-WILDCARD") {
        Some(ClassicalKind::DomainWildcard)
    } else if value.eq_ignore_ascii_case("DOMAIN-KEYWORD") {
        Some(ClassicalKind::DomainKeyword)
    } else if value.eq_ignore_ascii_case("DOMAIN-REGEX") {
        Some(ClassicalKind::DomainRegex)
    } else if value.eq_ignore_ascii_case("DOMAIN-SET") {
        Some(ClassicalKind::DomainSet)
    } else if value.eq_ignore_ascii_case("IP-CIDR") || value.eq_ignore_ascii_case("IP-CIDR6") {
        Some(ClassicalKind::Ipcidr)
    } else if value.eq_ignore_ascii_case("IP-SUFFIX") {
        Some(ClassicalKind::IpSuffix)
    } else if value.eq_ignore_ascii_case("IP-ASN") {
        Some(ClassicalKind::IpAsn)
    } else if value.eq_ignore_ascii_case("SRC-IP-CIDR") {
        Some(ClassicalKind::SrcIpcidr)
    } else if value.eq_ignore_ascii_case("SRC-GEOIP") {
        Some(ClassicalKind::SrcGeoip)
    } else if value.eq_ignore_ascii_case("SRC-IP-ASN") {
        Some(ClassicalKind::SrcIpAsn)
    } else if value.eq_ignore_ascii_case("SRC-IP-SUFFIX") {
        Some(ClassicalKind::SrcIpSuffix)
    } else if value.eq_ignore_ascii_case("GEOIP") {
        Some(ClassicalKind::Geoip)
    } else if value.eq_ignore_ascii_case("GEOSITE") {
        Some(ClassicalKind::Geosite)
    } else if value.eq_ignore_ascii_case("DST-PORT") || value.eq_ignore_ascii_case("DEST-PORT") {
        Some(ClassicalKind::DstPort)
    } else if value.eq_ignore_ascii_case("SRC-PORT") {
        Some(ClassicalKind::SrcPort)
    } else if value.eq_ignore_ascii_case("SRC-IP") {
        Some(ClassicalKind::SrcIp)
    } else if value.eq_ignore_ascii_case("IN-PORT") {
        Some(ClassicalKind::InPort)
    } else if value.eq_ignore_ascii_case("IN-TYPE") {
        Some(ClassicalKind::InType)
    } else if value.eq_ignore_ascii_case("IN-USER") {
        Some(ClassicalKind::InUser)
    } else if value.eq_ignore_ascii_case("IN-NAME") {
        Some(ClassicalKind::InName)
    } else if value.eq_ignore_ascii_case("PROCESS-PATH") {
        Some(ClassicalKind::ProcessPath)
    } else if value.eq_ignore_ascii_case("PROCESS-PATH-WILDCARD") {
        Some(ClassicalKind::ProcessPathWildcard)
    } else if value.eq_ignore_ascii_case("PROCESS-PATH-REGEX") {
        Some(ClassicalKind::ProcessPathRegex)
    } else if value.eq_ignore_ascii_case("PROCESS-NAME") {
        Some(ClassicalKind::ProcessName)
    } else if value.eq_ignore_ascii_case("PROCESS-NAME-WILDCARD") {
        Some(ClassicalKind::ProcessNameWildcard)
    } else if value.eq_ignore_ascii_case("PROCESS-NAME-REGEX") {
        Some(ClassicalKind::ProcessNameRegex)
    } else if value.eq_ignore_ascii_case("UID") {
        Some(ClassicalKind::Uid)
    } else if value.eq_ignore_ascii_case("NETWORK") {
        Some(ClassicalKind::Network)
    } else if value.eq_ignore_ascii_case("PROTOCOL") {
        Some(ClassicalKind::Protocol)
    } else if value.eq_ignore_ascii_case("DSCP") {
        Some(ClassicalKind::Dscp)
    } else if value.eq_ignore_ascii_case("USER-AGENT") {
        Some(ClassicalKind::UserAgent)
    } else if value.eq_ignore_ascii_case("URL-REGEX") {
        Some(ClassicalKind::UrlRegex)
    } else if value.eq_ignore_ascii_case("SCRIPT") {
        Some(ClassicalKind::Script)
    } else if value.eq_ignore_ascii_case("CELLULAR-RADIO") {
        Some(ClassicalKind::CellularRadio)
    } else if value.eq_ignore_ascii_case("DEVICE-NAME") {
        Some(ClassicalKind::DeviceName)
    } else if value.eq_ignore_ascii_case("MAC-ADDRESS") {
        Some(ClassicalKind::MacAddress)
    } else if value.eq_ignore_ascii_case("HOSTNAME-TYPE") {
        Some(ClassicalKind::HostnameType)
    } else if value.eq_ignore_ascii_case("MATCH") {
        Some(ClassicalKind::Match)
    } else if value.eq_ignore_ascii_case("RULE-SET") {
        Some(ClassicalKind::RuleSet)
    } else if value.eq_ignore_ascii_case("AND") {
        Some(ClassicalKind::And)
    } else if value.eq_ignore_ascii_case("OR") {
        Some(ClassicalKind::Or)
    } else if value.eq_ignore_ascii_case("NOT") {
        Some(ClassicalKind::Not)
    } else if value.eq_ignore_ascii_case("SUB-RULE") {
        Some(ClassicalKind::SubRule)
    } else {
        None
    }
}
