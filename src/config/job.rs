use std::path::Path;

use anyhow::{Result, bail};

use super::db::{db_build_job, db_convert_job, db_export_job};
use super::{
    BehaviorMode, ConfigDefaults, ConfigFile, ConfigInputFile, ConfigJob, ConfigJobFile,
    ConfigOutputFile, ConvertOptions, DbConfigJob, DbTarget, InputBehaviorMode, InputFormat,
    OutputFormat, RuleConfigJob, RuleTarget,
};

impl ConfigFile {
    pub(super) fn into_jobs(self, base: &Path) -> Result<Vec<ConfigJob>> {
        if self.jobs.is_empty() {
            bail!("config jobs must not be empty");
        }
        let mut jobs = Vec::new();
        for job in self.jobs {
            jobs.extend(job.into_jobs(base, &self.defaults)?);
        }
        Ok(jobs)
    }
}

impl ConfigJobFile {
    fn into_jobs(self, base: &Path, defaults: &ConfigDefaults) -> Result<Vec<ConfigJob>> {
        let outputs = match (self.output, self.outputs) {
            (Some(output), None) => vec![output],
            (None, Some(outputs)) if !outputs.is_empty() => outputs,
            (Some(_), Some(_)) => bail!("config job cannot contain both output and outputs"),
            (None, Some(_)) => bail!("config outputs must not be empty"),
            (None, None) => bail!("config job must contain output or outputs"),
        };

        let mut jobs = Vec::with_capacity(outputs.len());
        for output in outputs {
            jobs.push(Self::into_job_for_output(
                self.input.clone(),
                output,
                base,
                defaults,
            )?);
        }
        Ok(jobs)
    }

    fn into_job_for_output(
        input: ConfigInputFile,
        output_file: ConfigOutputFile,
        base: &Path,
        defaults: &ConfigDefaults,
    ) -> Result<ConfigJob> {
        if let Some((target, input_format, output_format)) = db_convert_job(&input, &output_file)? {
            return Ok(ConfigJob::Db(DbConfigJob::Convert {
                target,
                input_format,
                output_format,
                input: input.single_path(base)?,
                output: output_file.path(base)?,
                countries: output_file.countries(),
                asns: output_file.asns(),
            }));
        }
        if let Some((target, format)) = db_export_job(&input, &output_file, defaults)? {
            let output = output_file.db_export_output(base, defaults)?;
            let countries = output_file.countries();
            let asns = output_file.asns();
            if !output.split {
                match target {
                    DbTarget::Geoip if countries.is_empty() => {
                        bail!("GeoIP DB export without country needs output.dir")
                    }
                    DbTarget::Asn if asns.is_empty() => {
                        bail!("ASN DB export without asn needs output.dir")
                    }
                    _ => {}
                }
            }
            return Ok(ConfigJob::Db(DbConfigJob::Export {
                target,
                format,
                input: input.single_path(base)?,
                output,
                countries,
                asns,
            }));
        }
        if let Some((target, format)) = db_build_job(&input, &output_file)? {
            return Ok(ConfigJob::Db(DbConfigJob::Build {
                target,
                format,
                input: input.db_paths(base, target)?,
                output: output_file.path(base)?,
            }));
        }

        let input_format = input
            .format
            .as_deref()
            .or(defaults.input_format.as_deref())
            .map(InputFormat::parse_arg)
            .transpose()?;
        let input_target = input
            .target
            .as_deref()
            .or(defaults.input_target.as_deref())
            .map(RuleTarget::parse_arg)
            .transpose()?;
        let input_behavior = input
            .behavior
            .as_deref()
            .or(defaults.input_behavior.as_deref())
            .map(InputBehaviorMode::parse_arg)
            .transpose()?
            .unwrap_or(InputBehaviorMode::Auto);
        let output_format = output_file
            .format
            .as_deref()
            .or(defaults.output_format.as_deref())
            .map(OutputFormat::parse_arg)
            .transpose()?
            .unwrap_or(OutputFormat::Mrs);
        let output_target = output_file
            .target
            .as_deref()
            .or(defaults.output_target.as_deref())
            .map(RuleTarget::parse_arg)
            .transpose()?
            .unwrap_or(RuleTarget::Mihomo);
        let output_behavior = output_file
            .behavior
            .as_deref()
            .or(defaults.output_behavior.as_deref())
            .map(BehaviorMode::parse_arg)
            .transpose()?
            .unwrap_or_else(|| crate::api::default_output_behavior(output_target, output_format));

        Ok(ConfigJob::Rules(RuleConfigJob {
            input: input.rule_inputs(base)?,
            output: output_file.path(base)?,
            options: ConvertOptions {
                input_target,
                input_format,
                input_behavior,
                output_target,
                output_format,
                output_behavior,
            },
        }))
    }
}
