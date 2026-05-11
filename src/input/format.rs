use anyhow::{Result, bail};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputFormat {
    Yaml,
    Mrs,
    Text,
    Adguard,
    Json,
    Srs,
}

impl InputFormat {
    pub fn parse_arg(arg: &str) -> Result<Self> {
        match arg {
            "yaml" => Ok(Self::Yaml),
            "mrs" => Ok(Self::Mrs),
            "text" | "domainset" | "ruleset" | "ipset" => Ok(Self::Text),
            "adguard" | "adguard-dns-filter" => Ok(Self::Adguard),
            "json" => Ok(Self::Json),
            "srs" => Ok(Self::Srs),
            other => bail!("unsupported input format: {other}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Yaml => "yaml",
            Self::Mrs => "mrs",
            Self::Text => "text",
            Self::Adguard => "adguard",
            Self::Json => "json",
            Self::Srs => "srs",
        }
    }
}
