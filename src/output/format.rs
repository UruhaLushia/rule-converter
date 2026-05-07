use anyhow::{Result, bail};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    Mrs,
    Text,
    Yaml,
    Json,
    Srs,
    DomainSet,
    RuleSet,
    IpSet,
}

impl OutputFormat {
    pub fn parse_arg(arg: &str) -> Result<Self> {
        match arg {
            "mrs" => Ok(Self::Mrs),
            "text" => Ok(Self::Text),
            "yaml" => Ok(Self::Yaml),
            "json" => Ok(Self::Json),
            "srs" => Ok(Self::Srs),
            "domainset" => Ok(Self::DomainSet),
            "ruleset" => Ok(Self::RuleSet),
            "ipset" => Ok(Self::IpSet),
            other => bail!("unsupported output format: {other}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mrs => "mrs",
            Self::Text => "text",
            Self::Yaml => "yaml",
            Self::Json => "json",
            Self::Srs => "srs",
            Self::DomainSet => "domainset",
            Self::RuleSet => "ruleset",
            Self::IpSet => "ipset",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::Mrs => "mrs",
            Self::Text => "list",
            Self::Yaml => "yaml",
            Self::Json => "json",
            Self::Srs => "srs",
            Self::DomainSet | Self::RuleSet | Self::IpSet => "list",
        }
    }

    pub fn is_text_ruleset(self) -> bool {
        matches!(
            self,
            Self::Text | Self::Yaml | Self::DomainSet | Self::RuleSet | Self::IpSet
        )
    }
}
