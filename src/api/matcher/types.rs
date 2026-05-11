use anyhow::Result;
use serde::Serialize;

use crate::codec::mihomo::mrs::Behavior;
use crate::rules::InputBehaviorMode;
use crate::{InputFormat, RuleTarget};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchInputTarget {
    Rule(Option<RuleTarget>),
    Geoip,
    Geosite,
    Asn,
}

impl MatchInputTarget {
    pub fn parse_arg(arg: &str) -> Result<Self> {
        match arg {
            "geoip" => Ok(Self::Geoip),
            "geosite" => Ok(Self::Geosite),
            "asn" => Ok(Self::Asn),
            value => RuleTarget::parse_arg(value).map(|target| Self::Rule(Some(target))),
        }
    }
}

impl From<RuleTarget> for MatchInputTarget {
    fn from(value: RuleTarget) -> Self {
        Self::Rule(Some(value))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchInputFormat {
    Rule(Option<InputFormat>),
    Dat,
    SingGeosite,
    Mmdb,
}

impl MatchInputFormat {
    pub fn parse_arg(arg: &str) -> Result<Self> {
        match arg {
            "dat" => Ok(Self::Dat),
            "sing-geosite" | "sing-geosite-db" | "geosite-db" => Ok(Self::SingGeosite),
            "mmdb" | "sing-db" | "metadb" => Ok(Self::Mmdb),
            value => InputFormat::parse_arg(value).map(|format| Self::Rule(Some(format))),
        }
    }
}

impl From<InputFormat> for MatchInputFormat {
    fn from(value: InputFormat) -> Self {
        Self::Rule(Some(value))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchOptions {
    pub input_target: Option<MatchInputTarget>,
    pub input_format: Option<MatchInputFormat>,
    pub input_behavior: InputBehaviorMode,
}

impl Default for MatchOptions {
    fn default() -> Self {
        Self {
            input_target: None,
            input_format: None,
            input_behavior: InputBehaviorMode::Auto,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchQueryKind {
    Domain,
    Ip,
}

impl MatchQueryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Ip => "ip",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MatchedRule {
    #[serde(serialize_with = "serialize_behavior")]
    pub behavior: Behavior,
    pub rule: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub set: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MatchResult {
    pub matched: bool,
    pub query: String,
    pub kind: MatchQueryKind,
    pub rules: Vec<MatchedRule>,
}

fn serialize_behavior<S>(behavior: &Behavior, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(behavior.as_str())
}
