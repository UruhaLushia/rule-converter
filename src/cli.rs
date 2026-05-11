mod args;
mod db;
mod report;

use anyhow::Result;
use clap::Parser;
use rule_converter::{
    ConfigJob, FileInput, InputBehaviorMode, MatchOptions, RuleConfigJob, convert_file_inputs,
    convert_file_inputs_to_path_streaming, detect_file_type, match_file_inputs,
    write_outputs_as_owned,
};
use serde::Serialize;

use args::{Cli, Command, ConvertCli, DetectCli, ListCli, MatchCli};
use db::{run_db_job, run_db_list};
use report::report_result;

pub fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Convert(cli) => run_convert_command(cli),
        Command::Detect(cli) => run_detect_command(cli),
        Command::List(cli) => run_list_command(cli),
        Command::Match(cli) => run_match_command(cli),
    }
}

fn run_detect_command(cli: DetectCli) -> Result<()> {
    let mut results = Vec::with_capacity(cli.paths.len());
    for path in cli.paths {
        let detected = detect_file_type(&path)?;
        results.push(DetectedFile {
            path: path.display().to_string(),
            kind: detected.kind,
            target: detected.target,
            format: detected.format,
            behavior: detected.behavior,
        });
    }

    if results.len() == 1 {
        println!("{}", serde_json::to_string_pretty(&results[0])?);
    } else {
        println!("{}", serde_json::to_string_pretty(&results)?);
    }
    Ok(())
}

#[derive(Serialize)]
struct DetectedFile {
    path: String,
    kind: String,
    target: String,
    format: String,
    behavior: Option<String>,
}

fn run_convert_command(cli: ConvertCli) -> Result<()> {
    let jobs = cli.into_jobs()?;

    for job in jobs {
        run_job(job)?;
    }

    Ok(())
}

fn run_list_command(cli: ListCli) -> Result<()> {
    run_db_list(&cli.path)
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
            target: None,
            format: None,
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
