use std::fs;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::codec::mihomo::mrs::Behavior;
use crate::output::OutputFormat;

pub(super) const FILE_BUFFER_SIZE: usize = 64 * 1024;

pub enum OutputTarget<'a> {
    FilePath(&'a Path),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutputFile {
    pub behavior: Behavior,
    pub format: OutputFormat,
    pub count: usize,
    pub path: PathBuf,
}

pub(super) fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    }
    Ok(())
}

pub(super) fn create_output_writer(path: &Path) -> Result<BufWriter<fs::File>> {
    ensure_parent_dir(path)?;
    let file = fs::File::create(path)
        .with_context(|| format!("failed to create output {}", path.display()))?;
    Ok(BufWriter::with_capacity(FILE_BUFFER_SIZE, file))
}

pub(super) fn output_file(
    behavior: Behavior,
    format: OutputFormat,
    count: usize,
    path: PathBuf,
) -> OutputFile {
    OutputFile {
        behavior,
        format,
        count,
        path,
    }
}
