use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use super::{
    BehaviorMode, ConfigDefaults, ConfigOutputFile, DbExportOutput, OutputFormat, RuleTarget,
    resolve_config_path,
};

impl ConfigOutputFile {
    pub(super) fn path(&self, base: &Path) -> Result<PathBuf> {
        match (&self.path, &self.dir) {
            (Some(path), None) => Ok(resolve_config_path(base, path.clone())),
            (None, Some(_)) => bail!("config output needs path for this job"),
            (Some(_), Some(_)) => bail!("config output cannot contain both path and dir"),
            (None, None) => bail!("config output must contain path"),
        }
    }

    pub(super) fn db_export_output(
        &self,
        base: &Path,
        defaults: &ConfigDefaults,
    ) -> Result<DbExportOutput> {
        let (base, split) = match (&self.path, &self.dir) {
            (Some(path), None) => (resolve_config_path(base, path.clone()), false),
            (None, Some(dir)) => (resolve_config_path(base, dir.clone()), true),
            (Some(_), Some(_)) => bail!("config output cannot contain both path and dir"),
            (None, None) => bail!("config output must contain path or dir"),
        };
        let target = self
            .target
            .as_deref()
            .or(defaults.output_target.as_deref())
            .map(RuleTarget::parse_arg)
            .transpose()?
            .unwrap_or(RuleTarget::General);
        let format = self
            .format
            .as_deref()
            .or(defaults.output_format.as_deref())
            .map(OutputFormat::parse_arg)
            .transpose()?
            .unwrap_or(OutputFormat::IpSet);
        let behavior = self
            .behavior
            .as_deref()
            .map(BehaviorMode::parse_arg)
            .transpose()?
            .unwrap_or(BehaviorMode::Auto);

        Ok(DbExportOutput {
            base,
            split,
            target,
            format,
            behavior,
        })
    }
}
