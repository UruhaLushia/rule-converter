use anyhow::Result;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BehaviorMode {
    Auto,
    Domain,
    Ipcidr,
    Classical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputBehaviorMode {
    Auto,
    Domain,
    Ipcidr,
    Classical,
}

impl BehaviorMode {
    pub fn parse_arg(arg: &str) -> Result<Self> {
        match arg {
            "auto" => Ok(Self::Auto),
            "domain" => Ok(Self::Domain),
            "ip" => Ok(Self::Ipcidr),
            "classical" => Ok(Self::Classical),
            other => anyhow::bail!("unsupported behavior: {other}"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Domain => "domain",
            Self::Ipcidr => "ip",
            Self::Classical => "classical",
        }
    }
}

impl InputBehaviorMode {
    pub fn parse_arg(arg: &str) -> Result<Self> {
        match arg {
            "auto" => Ok(Self::Auto),
            "domain" => Ok(Self::Domain),
            "ip" => Ok(Self::Ipcidr),
            "classical" => Ok(Self::Classical),
            other => anyhow::bail!("unsupported input behavior: {other}"),
        }
    }
}
