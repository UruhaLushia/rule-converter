use anyhow::{Result, bail};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleTarget {
    Mihomo,
    General,
    Egern,
    SingBox,
}

impl RuleTarget {
    pub fn parse_arg(arg: &str) -> Result<Self> {
        match arg {
            "mihomo" => Ok(Self::Mihomo),
            "general" => Ok(Self::General),
            "egern" => Ok(Self::Egern),
            "sing-box" => Ok(Self::SingBox),
            other => bail!("unsupported rule target: {other}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mihomo => "mihomo",
            Self::General => "general",
            Self::Egern => "egern",
            Self::SingBox => "sing-box",
        }
    }
}
