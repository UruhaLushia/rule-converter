mod build;
mod common;
mod convert;
mod export;

use anyhow::Result;
use rule_converter::{ConfigJob, DbConfigJob};

pub(super) use common::run_db_list;

pub(super) fn run_db_job(job: ConfigJob) -> Result<()> {
    let ConfigJob::Db(job) = job else {
        unreachable!("checked by caller")
    };

    match job {
        job @ DbConfigJob::Export { .. } => export::run_export_job(job),
        job @ DbConfigJob::Build { .. } => build::run_build_job(job),
        job @ DbConfigJob::Convert { .. } => convert::run_convert_job(job),
    }
}
