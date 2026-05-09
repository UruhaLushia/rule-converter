use std::fs;

use anyhow::Result;
use rule_converter::{
    DbConfigJob, DbTarget, build_asn_mmdb_from_rule_sets, collect_asn_mmdb_rule_sets,
    convert_asn_mmdb, convert_geoip_db_to_memory_filtered, convert_geoip_mmdb_filtered,
    filter_geoip_dat_to_path, filter_geosite_dat_to_path,
};

use super::common::{is_dat, write_db_bytes_output};

pub(super) fn run_convert_job(job: DbConfigJob) -> Result<()> {
    let DbConfigJob::Convert {
        target,
        input_format,
        output_format,
        input,
        output,
        countries,
        asns,
    } = job
    else {
        unreachable!("checked by caller")
    };
    match target {
        DbTarget::Geoip => {
            if is_dat(input_format) && is_dat(output_format) {
                let count = filter_geoip_dat_to_path(input, &output, &countries)?;
                eprintln!(
                    "wrote {count} records to {} (geoip {})",
                    output.display(),
                    output_format.as_str()
                );
                return Ok(());
            }
            if is_dat(input_format) || is_dat(output_format) {
                let raw = fs::read(input)?;
                let db = convert_geoip_db_to_memory_filtered(
                    raw,
                    input_format,
                    &countries,
                    output_format,
                )?;
                write_db_bytes_output(&output, db.count, db.bytes, "geoip", output_format)?;
                return Ok(());
            }
            let count = convert_geoip_mmdb_filtered(input, &output, output_format, &countries)?;
            eprintln!(
                "wrote {count} CIDR records to {} (geoip {})",
                output.display(),
                output_format.as_str()
            );
        }
        DbTarget::Geosite => {
            let count = filter_geosite_dat_to_path(input, &output, &countries)?;
            eprintln!(
                "wrote {count} records to {} (geosite {})",
                output.display(),
                output_format.as_str()
            );
        }
        DbTarget::Asn => {
            let count = if asns.is_empty() {
                convert_asn_mmdb(input, &output)?
            } else {
                let entries = collect_asn_mmdb_rule_sets(input, &asns)?
                    .into_iter()
                    .map(|set| (set.asn, set.output));
                build_asn_mmdb_from_rule_sets(entries, &output)?
            };
            eprintln!("wrote {count} CIDR records to {} (asn)", output.display());
        }
    }
    Ok(())
}
