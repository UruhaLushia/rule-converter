mod args;
mod db;
mod report;

use anyhow::Result;
use clap::Parser;
use rule_converter::{
    ConfigJob, FileInput, InputBehaviorMode, MatchOptions, RuleConfigJob, convert_file_inputs,
    convert_file_inputs_to_path_streaming, match_file_inputs, write_outputs_as_owned,
};

use args::{Cli, Command, ConvertCli, MatchCli};
use db::{run_db_job, run_db_list};
use report::report_result;

pub fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Convert(cli) => run_convert_command(cli),
        Command::Match(cli) => run_match_command(cli),
    }
}

fn run_convert_command(cli: ConvertCli) -> Result<()> {
    if let Some(target) = cli.list {
        if cli.config.is_some() || cli.paths.len() != 1 {
            anyhow::bail!(
                "--list needs exactly one MMDB path and cannot be combined with --config"
            );
        }
        return run_db_list(target, &cli.paths[0]);
    }
    let jobs = cli.into_jobs()?;

    for job in jobs {
        run_job(job)?;
    }

    Ok(())
}

fn run_match_command(cli: MatchCli) -> Result<()> {
    if cli.paths.is_empty() {
        anyhow::bail!("match needs at least one input path");
    }
    let inputs = cli
        .paths
        .into_iter()
        .map(|path| FileInput {
            path,
            target: cli.input_target.map(Into::into),
            format: cli.input_format.map(Into::into),
            behavior: cli
                .input_behavior
                .map(Into::into)
                .unwrap_or(InputBehaviorMode::Auto),
        })
        .collect::<Vec<_>>();
    let result = match_file_inputs(
        inputs,
        &cli.query,
        MatchOptions {
            input_target: cli.input_target.map(Into::into),
            input_format: cli.input_format.map(Into::into),
            input_behavior: cli
                .input_behavior
                .map(Into::into)
                .unwrap_or(InputBehaviorMode::Auto),
        },
    )?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn run_job(job: ConfigJob) -> Result<()> {
    let ConfigJob::Rules(job) = job else {
        return run_db_job(job);
    };

    run_rule_job(job)
}

fn run_rule_job(job: RuleConfigJob) -> Result<()> {
    if let Some((files, skipped)) =
        convert_file_inputs_to_path_streaming(job.input.clone(), &job.output, job.options)?
    {
        return report_result(files, skipped);
    }

    let result = convert_file_inputs(job.input, job.options)?;
    let (files, skipped) = write_outputs_as_owned(
        result,
        &job.output,
        job.options.output_target,
        job.options.output_format,
    )?;

    report_result(files, skipped)
}
