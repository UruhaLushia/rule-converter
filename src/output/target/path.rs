use std::path::{Path, PathBuf};

use crate::RuleTarget;
use crate::codec::mihomo::mrs::Behavior;
use crate::output::OutputFormat;

pub fn resolve_output_path(
    base: &Path,
    behavior: Behavior,
    split: bool,
    format: OutputFormat,
) -> PathBuf {
    resolve_output_path_for_target(base, behavior, split, format, RuleTarget::Mihomo)
}

pub fn resolve_output_path_for_target(
    base: &Path,
    behavior: Behavior,
    split: bool,
    format: OutputFormat,
    target: RuleTarget,
) -> PathBuf {
    if split {
        return split_output_path(base, behavior, format, target);
    }
    with_format_extension(base, format, target)
}

fn split_output_path(
    base: &Path,
    behavior: Behavior,
    format: OutputFormat,
    target: RuleTarget,
) -> PathBuf {
    if base.is_dir() {
        return base.join(format!(
            "{}.{}",
            behavior.as_str(),
            format_extension(format, target)
        ));
    }

    let suffix = behavior.as_str();
    let extension = format_extension(format, target);
    let stem = base
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("rules");
    let filename = format!("{stem}-{suffix}.{extension}");

    match base.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(filename),
        _ => PathBuf::from(filename),
    }
}

fn with_format_extension(base: &Path, format: OutputFormat, target: RuleTarget) -> PathBuf {
    if base.is_dir() {
        return base.join(format!("rules.{}", format_extension(format, target)));
    }
    base.with_extension(format_extension(format, target))
}

fn format_extension(format: OutputFormat, target: RuleTarget) -> &'static str {
    match (target, format) {
        (RuleTarget::Egern, OutputFormat::RuleSet) => "yaml",
        _ => format.extension(),
    }
}
