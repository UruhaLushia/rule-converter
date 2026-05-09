use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use super::{
    ConfigInputFile, ConfigInputPath, ConfigPathInput, DbInputPath, DbTarget, FileInput,
    InputBehaviorMode, InputFormat, RuleTarget, resolve_config_path,
};

impl ConfigInputFile {
    pub(super) fn rule_inputs(self, base: &Path) -> Result<Vec<FileInput>> {
        let parent_options = InputItemOptions {
            target: self.target,
            format: self.format,
            behavior: self.behavior,
        };
        match (self.path, self.inputs) {
            (Some(path), None) => Ok(vec![file_input_from_parts(base, path, parent_options)?]),
            (None, Some(inputs)) if !inputs.is_empty() => inputs
                .into_iter()
                .map(|input| match input {
                    ConfigInputPath::Path(path) => {
                        file_input_from_config(base, path, parent_options.clone())
                    }
                    ConfigInputPath::Country(_) | ConfigInputPath::Asn(_) => {
                        bail!("config rule inputs must not contain country or asn")
                    }
                })
                .collect(),
            (Some(_), Some(_)) => bail!("config input cannot contain both path and inputs"),
            (None, Some(_)) | (None, None) => bail!("config input must contain path or inputs"),
        }
    }

    pub(super) fn single_path(self, base: &Path) -> Result<PathBuf> {
        match (self.path, self.inputs) {
            (Some(path), None) => Ok(resolve_config_path(base, path)),
            (None, Some(inputs)) => match inputs.as_slice() {
                [ConfigInputPath::Path(ConfigPathInput::Path(path))] => {
                    Ok(resolve_config_path(base, path.clone()))
                }
                [ConfigInputPath::Path(ConfigPathInput::Options(input))] => {
                    Ok(resolve_config_path(base, input.path.clone()))
                }
                _ => bail!("config input needs exactly one path"),
            },
            (Some(_), Some(_)) => bail!("config input cannot contain both path and inputs"),
            (None, None) => bail!("config input must contain path"),
        }
    }

    pub(super) fn db_paths(self, base: &Path, target: DbTarget) -> Result<Vec<DbInputPath>> {
        let parent_options = InputItemOptions {
            target: self.target,
            format: self.format,
            behavior: self.behavior,
        };
        match (self.path, self.inputs) {
            (None, Some(inputs)) if !inputs.is_empty() => inputs
                .into_iter()
                .map(|path| match path {
                    ConfigInputPath::Country(path)
                        if matches!(target, DbTarget::Geoip | DbTarget::Geosite) =>
                    {
                        let options = merge_input_options(
                            path.target,
                            path.format,
                            path.behavior,
                            parent_options.clone(),
                        );
                        Ok(DbInputPath::Country {
                            country: path.country,
                            input: file_input_from_parts(base, path.path, options)?,
                        })
                    }
                    ConfigInputPath::Asn(path) if target == DbTarget::Asn => {
                        let options = merge_input_options(
                            path.target,
                            path.format,
                            path.behavior,
                            parent_options.clone(),
                        );
                        Ok(DbInputPath::Asn {
                            asn: path.asn,
                            input: file_input_from_parts(base, path.path, options)?,
                        })
                    }
                    ConfigInputPath::Country(_) => bail!("ASN DB input needs asn and path"),
                    ConfigInputPath::Asn(_) => {
                        bail!("{} DB input needs country and path", target.as_str())
                    }
                    ConfigInputPath::Path(_) => bail!(
                        "{} DB build input needs typed path entries",
                        target.as_str()
                    ),
                })
                .collect(),
            (Some(_), None) => bail!("{} DB build input needs typed entries", target.as_str()),
            (Some(_), Some(_)) => bail!("config input cannot contain both path and inputs"),
            (None, Some(_)) | (None, None) => bail!("config input must contain inputs"),
        }
    }
}

#[derive(Clone)]
struct InputItemOptions {
    target: Option<String>,
    format: Option<String>,
    behavior: Option<String>,
}

fn file_input_from_config(
    base: &Path,
    input: ConfigPathInput,
    parent: InputItemOptions,
) -> Result<FileInput> {
    match input {
        ConfigPathInput::Path(path) => file_input_from_parts(base, path, parent),
        ConfigPathInput::Options(input) => {
            let options = merge_input_options(input.target, input.format, input.behavior, parent);
            file_input_from_parts(base, input.path, options)
        }
    }
}

fn merge_input_options(
    target: Option<String>,
    format: Option<String>,
    behavior: Option<String>,
    parent: InputItemOptions,
) -> InputItemOptions {
    InputItemOptions {
        target: target.or(parent.target),
        format: format.or(parent.format),
        behavior: behavior.or(parent.behavior),
    }
}

fn file_input_from_parts(
    base: &Path,
    path: PathBuf,
    options: InputItemOptions,
) -> Result<FileInput> {
    let (format, format_behavior) = options
        .format
        .as_deref()
        .map(parse_config_input_format)
        .transpose()?
        .unwrap_or((None, InputBehaviorMode::Auto));
    let behavior = options
        .behavior
        .as_deref()
        .map(InputBehaviorMode::parse_arg)
        .transpose()?
        .unwrap_or(format_behavior);

    Ok(FileInput {
        path: resolve_config_path(base, path),
        target: options
            .target
            .as_deref()
            .map(RuleTarget::parse_arg)
            .transpose()?,
        format,
        behavior,
    })
}

fn parse_config_input_format(value: &str) -> Result<(Option<InputFormat>, InputBehaviorMode)> {
    match value.to_ascii_lowercase().as_str() {
        "domainset" => Ok((Some(InputFormat::Text), InputBehaviorMode::Domain)),
        "ipset" => Ok((Some(InputFormat::Text), InputBehaviorMode::Ipcidr)),
        "ruleset" => Ok((Some(InputFormat::Text), InputBehaviorMode::Classical)),
        _ => Ok((
            Some(InputFormat::parse_arg(value)?),
            InputBehaviorMode::Auto,
        )),
    }
}
