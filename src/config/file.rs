use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use super::{ConfigFile, ConfigJob};

pub fn load_config(path: impl AsRef<Path>) -> Result<Vec<ConfigJob>> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read config {}", path.display()))?;
    let config = parse_config(path, &raw)?;
    config.into_jobs(path.parent().unwrap_or_else(|| Path::new("")))
}

fn parse_config(path: &Path, raw: &str) -> Result<ConfigFile> {
    match path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase())
        .as_deref()
    {
        Some("yaml") => serde_yaml::from_str(raw).context("failed to parse YAML config"),
        Some("toml") => toml::from_str(raw).context("failed to parse TOML config"),
        Some("json") => serde_json::from_str(raw).context("failed to parse JSON config"),
        Some(other) => bail!("unsupported config format: {other}"),
        None => bail!("config path must have yaml, toml, or json extension"),
    }
}
