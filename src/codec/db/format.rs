use anyhow::{Result, bail};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmdbFormat {
    Mmdb,
    SingDb,
    MetaDb,
}

impl MmdbFormat {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "mmdb" => Ok(Self::Mmdb),
            "sing-db" | "singdb" => Ok(Self::SingDb),
            "metadb" | "meta-db" => Ok(Self::MetaDb),
            other => bail!("unsupported MMDB format: {other}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mmdb => "mmdb",
            Self::SingDb => "sing-db",
            Self::MetaDb => "metadb",
        }
    }
}
