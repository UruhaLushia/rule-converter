use std::fs;

use anyhow::Result;
use rule_converter::{
    BehaviorMode, DbConfigJob, DbTarget, OutputFormat, RuleTarget, collect_asn_mmdb_rule_set,
    collect_asn_mmdb_rule_sets, collect_geoip_dat_rule_set, collect_geoip_dat_rule_sets,
    collect_geoip_mmdb_rule_set, collect_geoip_mmdb_rule_sets, collect_geosite_dat_rule_set,
    collect_geosite_dat_rule_sets, export_asn_mmdb_ipset_to_path, export_asn_mmdb_mrs_to_path,
    export_geoip_dat_ipset_to_dir, export_geoip_mmdb_ipset_to_path, export_geoip_mmdb_mrs_to_path,
    export_geosite_dat_general_ruleset_to_dir, export_geosite_dat_general_ruleset_to_path,
    write_outputs_as_owned,
};

use super::common::*;
use crate::cli::report::report_result;

pub(super) fn run_export_job(job: DbConfigJob) -> Result<()> {
    let DbConfigJob::Export {
        target,
        format,
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
            ensure_db_export_filter_or_dir(&output, !countries.is_empty(), "GeoIP")?;
            if is_dat(format) {
                if output.split
                    && output.target == RuleTarget::General
                    && output.format == OutputFormat::IpSet
                    && output.behavior == BehaviorMode::Ipcidr
                {
                    let files = export_geoip_dat_ipset_to_dir(input, &output.base, &countries)?
                        .into_iter()
                        .map(|file| dat_ipset_output_file(file.count, file.path))
                        .collect();
                    return report_result(files, Vec::new());
                }
                let raw = fs::read(input)?;
                if output.split {
                    for set in collect_geoip_dat_rule_sets(&raw, &countries)? {
                        let base = db_export_base(&output, &set.country);
                        write_db_rule_set_output(&base, set.output, &output)?;
                    }
                } else {
                    let rule_set = collect_geoip_dat_rule_set(&raw, &countries)?;
                    write_db_rule_set_output(&output.base, rule_set, &output)?;
                }
                return Ok(());
            }
            if can_stream_db_ipset(&output) {
                let file = export_geoip_mmdb_ipset_to_path(input, &output.base, &countries)?;
                return report_result(vec![ipset_output_file(file.count, file.path)], Vec::new());
            }
            if can_stream_db_mrs(&output) {
                let file = export_geoip_mmdb_mrs_to_path(input, &output.base, &countries)?;
                return report_result(vec![mrs_output_file(file.count, file.path)], Vec::new());
            }
            if output.split {
                for set in collect_geoip_mmdb_rule_sets(input, &countries)? {
                    let base = db_export_base(&output, &set.country);
                    write_db_rule_set_output(&base, set.output, &output)?;
                }
            } else {
                let rule_set = collect_geoip_mmdb_rule_set(input, &countries)?;
                write_db_rule_set_output(&output.base, rule_set, &output)?;
            }
        }
        DbTarget::Geosite => {
            ensure_db_export_filter_or_dir(&output, !countries.is_empty(), "Geosite")?;
            if is_dat(format) {
                if can_stream_geosite_general_ruleset(&output) {
                    let count = export_geosite_dat_general_ruleset_to_path(
                        input,
                        &output.base,
                        &countries,
                    )?;
                    return report_result(
                        vec![general_ruleset_output_file(count, output.base)],
                        Vec::new(),
                    );
                }
                if output.split
                    && output.target == RuleTarget::General
                    && output.format == OutputFormat::RuleSet
                    && output.behavior == BehaviorMode::Classical
                {
                    let files =
                        export_geosite_dat_general_ruleset_to_dir(input, &output.base, &countries)?
                            .into_iter()
                            .map(|file| general_ruleset_output_file(file.count, file.path))
                            .collect();
                    return report_result(files, Vec::new());
                }
            }
            let raw = fs::read(input)?;
            if output.split {
                for set in collect_geosite_dat_rule_sets(&raw, &countries)? {
                    let base = db_export_base(&output, &set.code);
                    let (files, skipped) = write_outputs_as_owned(
                        set.into_result(),
                        &base,
                        output.target,
                        output.format,
                    )?;
                    report_result(files, skipped)?;
                }
            } else {
                let result = collect_geosite_dat_rule_set(&raw, &countries)?;
                let (files, skipped) =
                    write_outputs_as_owned(result, &output.base, output.target, output.format)?;
                report_result(files, skipped)?;
            }
        }
        DbTarget::Asn => {
            ensure_db_export_filter_or_dir(&output, !asns.is_empty(), "ASN")?;
            if can_stream_db_ipset(&output) {
                let file = export_asn_mmdb_ipset_to_path(input, &output.base, &asns)?;
                return report_result(vec![ipset_output_file(file.count, file.path)], Vec::new());
            }
            if can_stream_db_mrs(&output) {
                let file = export_asn_mmdb_mrs_to_path(input, &output.base, &asns)?;
                return report_result(vec![mrs_output_file(file.count, file.path)], Vec::new());
            }
            if output.split {
                for set in collect_asn_mmdb_rule_sets(input, &asns)? {
                    let base = db_export_base(&output, &set.asn.to_string());
                    write_db_rule_set_output(&base, set.output, &output)?;
                }
            } else {
                let rule_set = collect_asn_mmdb_rule_set(input, &asns)?;
                write_db_rule_set_output(&output.base, rule_set, &output)?;
            }
        }
    }
    Ok(())
}
