use prost::Message;

#[derive(Clone, PartialEq, Message)]
pub struct GeoIp {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub cidr: Vec<Cidr>,
    #[prost(bool, tag = "3")]
    pub reverse_match: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct Cidr {
    #[prost(bytes = "vec", tag = "1")]
    pub ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub prefix: u32,
}

#[derive(Clone, PartialEq, Message)]
pub struct GeoSite {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub domain: Vec<Domain>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Domain {
    #[prost(enumeration = "DomainType", tag = "1")]
    pub r#type: i32,
    #[prost(string, tag = "2")]
    pub value: String,
    #[prost(message, repeated, tag = "3")]
    pub attribute: Vec<DomainAttribute>,
}

#[derive(Clone, PartialEq, Message)]
pub struct DomainAttribute {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(oneof = "domain_attribute::TypedValue", tags = "2, 3")]
    pub typed_value: Option<domain_attribute::TypedValue>,
}

pub mod domain_attribute {
    use prost::Oneof;

    #[derive(Clone, PartialEq, Oneof)]
    pub enum TypedValue {
        #[prost(bool, tag = "2")]
        BoolValue(bool),
        #[prost(int64, tag = "3")]
        IntValue(i64),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum DomainType {
    Plain = 0,
    Regex = 1,
    RootDomain = 2,
    Full = 3,
}
