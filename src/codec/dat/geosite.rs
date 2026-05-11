mod builder;
mod convert;
mod export;
#[cfg(not(target_arch = "wasm32"))]
mod files;
mod filter;
mod scan;
mod writer;

use crate::api::ConvertResult;
use crate::codec::mihomo::mrs::{DomainSetBuilder, RuleSetOutput};
use crate::rules::{BehaviorMode, RuleTextStore};
use anyhow::{Result, bail};

use super::proto::{GeoSite, for_each_message_field};
use filter::{matches_code, normalize_code, normalize_code_filter};
use scan::{for_each_raw_geosite_entry, scan_geosite_entry_meta};

pub use builder::build_geosite_dat_from_rule_sets;
pub use export::export_geosite_dat_general_ruleset_to_memory;
#[cfg(not(target_arch = "wasm32"))]
pub use export::{
    export_geosite_dat_general_ruleset_to_path, export_geosite_dat_general_ruleset_to_writer,
};
#[cfg(not(target_arch = "wasm32"))]
pub use files::{
    export_geosite_dat_general_ruleset_to_dir, export_geosite_dat_general_ruleset_to_dir_writer,
};
pub use filter::filter_geosite_dat;
#[cfg(not(target_arch = "wasm32"))]
pub use filter::{filter_geosite_dat_to_path, filter_geosite_dat_to_writer};
pub struct GeositeDatRuleSet {
    pub code: String,
    pub output: Option<RuleSetOutput>,
    pub mixed_rules: RuleTextStore,
}

impl GeositeDatRuleSet {
    pub fn into_result(self) -> ConvertResult {
        ConvertResult {
            outputs: self.output.into_iter().collect(),
            mixed_rules: self.mixed_rules,
            sing_box_rules: None,
            output_behavior: BehaviorMode::Classical,
            no_resolve: false,
            skipped: Vec::new(),
        }
    }
}

pub fn list_geosite_dat_codes(input: &[u8]) -> Result<Vec<String>> {
    let mut codes = Vec::new();
    for_each_raw_geosite_entry(input, |raw| {
        let meta = scan_geosite_entry_meta(raw)?;
        if !meta.code.is_empty() {
            codes.push(meta.code);
        }
        Ok(())
    })?;
    codes.sort_unstable();
    codes.dedup();
    Ok(codes)
}

pub fn collect_geosite_dat_rule_set(input: &[u8], codes: &[String]) -> Result<ConvertResult> {
    let sets = collect_geosite_dat_rule_sets(input, codes)?;
    let mut builder = DomainSetBuilder::default();
    let mut outputs = Vec::new();
    let mut mixed_rules = RuleTextStore::default();
    for set in sets {
        if let Some(RuleSetOutput::Domain(domain_set)) = set.output {
            domain_set.for_each_rule(|rule| builder.insert(rule).map_err(io_error_from_anyhow))?;
        }
        for rule in set.mixed_rules.iter() {
            mixed_rules.push(rule);
        }
    }

    if !builder.is_empty() {
        outputs.push(RuleSetOutput::Domain(builder.finish()?));
    }

    Ok(ConvertResult {
        outputs,
        mixed_rules,
        sing_box_rules: None,
        output_behavior: BehaviorMode::Classical,
        no_resolve: false,
        skipped: Vec::new(),
    })
}

pub(super) fn io_error_from_anyhow(err: anyhow::Error) -> std::io::Error {
    std::io::Error::other(err.to_string())
}

pub fn collect_geosite_dat_rule_sets(
    input: &[u8],
    codes: &[String],
) -> Result<Vec<GeositeDatRuleSet>> {
    let filter = normalize_code_filter(codes);
    let mut outputs = Vec::new();

    for_each_geosite_entry(input, |entry, _| {
        if !matches_code(&entry.country_code, &filter) {
            return Ok(());
        }
        let mut builder = DomainSetBuilder::default();
        let mut mixed_rules = RuleTextStore::default();
        convert::push_geosite_entry(&mut builder, &mut mixed_rules, &entry)?;
        if !builder.is_empty() || !mixed_rules.is_empty() {
            let output = if builder.is_empty() {
                None
            } else {
                Some(RuleSetOutput::Domain(builder.finish()?))
            };
            outputs.push(GeositeDatRuleSet {
                code: normalize_code(&entry.country_code),
                output,
                mixed_rules,
            });
        }
        Ok(())
    })?;

    if outputs.is_empty() {
        bail!("geosite dat input does not contain any matching records");
    }
    Ok(outputs)
}

fn for_each_geosite_entry(input: &[u8], f: impl FnMut(GeoSite, &[u8]) -> Result<()>) -> Result<()> {
    for_each_message_field(input, 1, "V2Ray geosite dat", f)
}
