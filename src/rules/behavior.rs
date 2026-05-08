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
