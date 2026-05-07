use anyhow::{Result, bail};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputFormat {
    Yaml,
    Mrs,
    Text,
    Json,
    Srs,
}

impl InputFormat {
    pub fn parse_arg(arg: &str) -> Result<Self> {
        match arg {
            "yaml" => Ok(Self::Yaml),
            "mrs" => Ok(Self::Mrs),
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            "srs" => Ok(Self::Srs),
            other => bail!("unsupported input format: {other}"),
        }
    }
}
