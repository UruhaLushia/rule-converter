use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::{InputFormat, parse_input_as, parser};
use crate::RuleTarget;
use crate::codec::mihomo;

pub enum InputSource<'a> {
    Payload(&'a [u8]),
    FilePath(&'a Path),
}

pub fn expand_file_paths<P, I>(paths: I) -> Result<Vec<PathBuf>>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = P>,
{
    let mut expanded = Vec::new();
    for path in paths {
        expand_file_path(path.as_ref(), &mut expanded)?;
    }
    if expanded.is_empty() {
        anyhow::bail!("input path expansion did not match any files");
    }
    expanded.sort();
    expanded.dedup();
    Ok(expanded)
}

fn expand_file_path(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if path_has_wildcard(path) {
        return expand_wildcard_path(path, out);
    }

    let metadata = fs::metadata(path)
        .with_context(|| format!("failed to read input path {}", path.display()))?;
    if metadata.is_file() {
        out.push(path.to_path_buf());
    } else if metadata.is_dir() {
        collect_dir_files(path, out)?;
    } else {
        anyhow::bail!("input path is not a file or directory: {}", path.display());
    }
    Ok(())
}

fn collect_dir_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir)
        .with_context(|| format!("failed to read input directory {}", dir.display()))?
    {
        let entry = entry.with_context(|| format!("failed to read entry in {}", dir.display()))?;
        let path = entry.path();
        let metadata = entry
            .metadata()
            .with_context(|| format!("failed to read input path {}", path.display()))?;
        if metadata.is_file() {
            out.push(path);
        } else if metadata.is_dir() {
            collect_dir_files(&path, out)?;
        }
    }
    Ok(())
}

fn expand_wildcard_path(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let pattern = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow::anyhow!("wildcard input must end with a UTF-8 file pattern"))?;
    if path
        .parent()
        .is_some_and(|parent| path_has_wildcard(parent))
    {
        anyhow::bail!("wildcard input only supports `*` in the final path component");
    }

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut matched = 0usize;
    for entry in fs::read_dir(dir)
        .with_context(|| format!("failed to read input directory {}", dir.display()))?
    {
        let entry = entry.with_context(|| format!("failed to read entry in {}", dir.display()))?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if !wildcard_match(pattern, file_name) {
            continue;
        }

        let path = entry.path();
        let metadata = entry
            .metadata()
            .with_context(|| format!("failed to read input path {}", path.display()))?;
        if metadata.is_file() {
            out.push(path);
            matched += 1;
        } else if metadata.is_dir() {
            collect_dir_files(&path, out)?;
            matched += 1;
        }
    }

    if matched == 0 {
        anyhow::bail!("wildcard input did not match any files: {}", path.display());
    }
    Ok(())
}

fn path_has_wildcard(path: &Path) -> bool {
    path.to_string_lossy().contains('*')
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let starts_with_wildcard = pattern.starts_with('*');
    let ends_with_wildcard = pattern.ends_with('*');
    let mut remaining = value;

    for (index, part) in pattern
        .split('*')
        .filter(|part| !part.is_empty())
        .enumerate()
    {
        if index == 0 && !starts_with_wildcard {
            if !remaining.starts_with(part) {
                return false;
            }
            remaining = &remaining[part.len()..];
            continue;
        }

        let Some(offset) = remaining.find(part) else {
            return false;
        };
        remaining = &remaining[offset + part.len()..];
    }

    ends_with_wildcard || remaining.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn wildcard_matches_final_path_component() {
        assert!(wildcard_match("*.yaml", "a.yaml"));
        assert!(wildcard_match("ad-*.yaml", "ad-mihomo.yaml"));
        assert!(wildcard_match("ad-*", "ad-mihomo.yaml"));
        assert!(!wildcard_match("*.yaml", "a.list"));
        assert!(!wildcard_match("ad-*.yaml", "other.yaml"));
    }

    #[test]
    fn expands_directories_and_wildcards() {
        let base = std::env::temp_dir().join(format!(
            "rule-converter-expand-{}-{}",
            std::process::id(),
            "source"
        ));
        let nested = base.join("nested");
        fs::create_dir_all(&nested).unwrap();
        File::create(base.join("a.yaml"))
            .unwrap()
            .write_all(b"a")
            .unwrap();
        File::create(base.join("b.list"))
            .unwrap()
            .write_all(b"b")
            .unwrap();
        File::create(nested.join("c.yaml"))
            .unwrap()
            .write_all(b"c")
            .unwrap();

        let files = expand_file_paths([base.join("*.yaml")]).unwrap();
        assert_eq!(files, vec![base.join("a.yaml")]);

        let files = expand_file_paths([base.clone()]).unwrap();
        assert_eq!(files.len(), 3);

        fs::remove_dir_all(base).unwrap();
    }
}

pub fn load_rules(source: InputSource<'_>, format: InputFormat) -> Result<Vec<String>> {
    load_rules_as(source, RuleTarget::Mihomo, format)
}

pub fn load_rules_as(
    source: InputSource<'_>,
    target: RuleTarget,
    format: InputFormat,
) -> Result<Vec<String>> {
    match source {
        InputSource::Payload(payload) => parse_input_as(payload, target, format),
        InputSource::FilePath(path) => {
            let raw = fs::read(path)
                .with_context(|| format!("failed to read input {}", path.display()))?;
            parse_input_as(raw, target, format)
        }
    }
}

pub fn for_each_rule(
    source: InputSource<'_>,
    target: RuleTarget,
    format: InputFormat,
    f: impl FnMut(&str) -> Result<()>,
) -> Result<usize> {
    match source {
        InputSource::Payload(payload) => {
            parser::for_each_rule(BufReader::new(payload), target, format, f)
        }
        InputSource::FilePath(path) => {
            let file = File::open(path)
                .with_context(|| format!("failed to read input {}", path.display()))?;
            if target == RuleTarget::Mihomo && format == InputFormat::Yaml {
                let mut f = f;
                if let Some(count) =
                    mihomo::for_each_simple_yaml_rule(BufReader::new(file), &mut f)?
                {
                    return Ok(count);
                }

                let file = File::open(path)
                    .with_context(|| format!("failed to read input {}", path.display()))?;
                return parser::for_each_rule(BufReader::new(file), target, format, f);
            }
            parser::for_each_rule(BufReader::new(file), target, format, f)
        }
    }
}
