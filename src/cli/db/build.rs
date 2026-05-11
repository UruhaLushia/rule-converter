use anyhow::Result;
use rule_converter::{
    BehaviorMode, ConvertOptions, DbConfigJob, DbInputPath, DbTarget, InputBehaviorMode,
    OutputFormat, RuleTarget, build_asn_mmdb_from_rule_sets, build_geoip_dat_from_rule_sets,
    build_geoip_mmdb_from_rule_sets, build_geosite_db_to_memory, convert_file_inputs,
};

use super::common::{collect_ip_rule_set, is_dat, write_db_bytes_output};

pub(super) fn run_build_job(job: DbConfigJob) -> Result<()> {
    let DbConfigJob::Build {
        target,
        format,
        input,
        output,
    } = job
    else {
        unreachable!("checked by caller")
    };
    match target {
        DbTarget::Geoip => {
            let mut entries = Vec::new();
            for item in input {
                let DbInputPath::Country { country, input } = item else {
                    anyhow::bail!("GeoIP build needs country paths");
                };
                entries.push((country, collect_ip_rule_set(input)?));
            }
            if is_dat(format) {
                let (count, bytes) = build_geoip_dat_from_rule_sets(entries)?;
                write_db_bytes_output(&output, count, bytes, "geoip", format)?;
                return Ok(());
            }
            let count = build_geoip_mmdb_from_rule_sets(entries, &output, format)?;
            eprintln!(
                "wrote {count} CIDR records to {} (geoip {})",
                output.display(),
                format.as_str()
            );
        }
        DbTarget::Geosite => {
            let mut entries = Vec::new();
            for item in input {
                let DbInputPath::Country { country, input } = item else {
                    anyhow::bail!("Geosite build needs country paths");
                };
                let result = convert_file_inputs(
                    [input],
                    ConvertOptions {
                        input_target: None,
                        input_format: None,
                        input_behavior: InputBehaviorMode::Auto,
                        output_target: RuleTarget::General,
                        output_format: OutputFormat::RuleSet,
                        output_behavior: BehaviorMode::Classical,
                    },
                )?;
                entries.push((country, result));
            }
            let db = build_geosite_db_to_memory(entries, format)?;
            write_db_bytes_output(&output, db.count, db.bytes, "geosite", format)?;
        }
        DbTarget::Asn => {
            let mut entries = Vec::new();
            for item in input {
                let DbInputPath::Asn { asn, input } = item else {
                    anyhow::bail!("ASN build needs asn paths");
                };
                entries.push((asn, collect_ip_rule_set(input)?));
            }
            let count = build_asn_mmdb_from_rule_sets(entries, &output)?;
            eprintln!("wrote {count} CIDR records to {} (asn)", output.display());
        }
    }
    Ok(())
}
