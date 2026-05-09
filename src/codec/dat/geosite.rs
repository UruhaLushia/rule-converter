#[cfg(not(target_arch = "wasm32"))]
use std::fs::{self, File};
use std::io::Write;
#[cfg(not(target_arch = "wasm32"))]
use std::io::{BufReader, BufWriter, Read};
#[cfg(not(target_arch = "wasm32"))]
use std::path::{Path, PathBuf};

use crate::api::ConvertResult;
use crate::codec::mihomo::mrs::{DomainSetBuilder, RuleSetOutput};
use crate::rules::{BehaviorMode, RuleTextStore, classical_to_provider_rule};
use anyhow::{Result, bail};

use super::proto::{
    Domain, DomainType, GeoSite, decode_varint, for_each_message_field, for_each_raw_message_field,
    scan_field, write_message_field, write_raw_message_field,
};
#[cfg(not(target_arch = "wasm32"))]
use super::proto::{for_each_raw_message_field_from_reader, write_raw_message_field_to_writer};

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
    let mut outputs = Vec::new();
    let mut mixed_rules = RuleTextStore::default();
    for set in sets {
        if let Some(output) = set.output {
            outputs.push(output);
        }
        for rule in set.mixed_rules.iter() {
            mixed_rules.push(rule);
        }
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
        push_geosite_entry(&mut builder, &mut mixed_rules, &entry)?;
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

pub fn filter_geosite_dat(input: &[u8], codes: &[String]) -> Result<(usize, Vec<u8>)> {
    let filter = normalize_code_filter(codes);
    let mut count = 0usize;
    let mut output = Vec::new();
    for_each_raw_geosite_entry(input, |raw| {
        let meta = scan_geosite_entry_meta(raw)?;
        if matches_normalized_code(&meta.code, &filter) {
            count += meta.domain_count;
            write_raw_message_field(&mut output, 1, raw)?;
        }
        Ok(())
    })?;
    if count == 0 {
        bail!("geosite dat input does not contain any matching records");
    }
    Ok((count, output))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn filter_geosite_dat_to_path(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    codes: &[String],
) -> Result<usize> {
    let input = input.as_ref();
    let output = output.as_ref();
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let reader = BufReader::new(File::open(input)?);
    let writer = BufWriter::new(File::create(output)?);
    filter_geosite_dat_to_writer(reader, writer, codes)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn filter_geosite_dat_to_writer<R: Read, W: Write>(
    reader: R,
    mut writer: W,
    codes: &[String],
) -> Result<usize> {
    let filter = normalize_code_filter(codes);
    let mut count = 0usize;
    for_each_raw_message_field_from_reader(reader, 1, "V2Ray geosite dat", |raw| {
        let meta = scan_geosite_entry_meta(raw)?;
        if matches_normalized_code(&meta.code, &filter) {
            count += meta.domain_count;
            write_raw_message_field_to_writer(&mut writer, 1, raw)?;
        }
        Ok(())
    })?;
    if count == 0 {
        bail!("geosite dat input does not contain any matching records");
    }
    Ok(count)
}

pub fn export_geosite_dat_general_ruleset_to_memory(
    input: &[u8],
    codes: &[String],
    split: bool,
) -> Result<Vec<(String, usize, Vec<u8>)>> {
    let filter = normalize_code_filter(codes);
    if split {
        let mut outputs = Vec::new();
        for_each_raw_geosite_entry(input, |raw| {
            let meta = scan_geosite_entry_meta(raw)?;
            if !matches_normalized_code(&meta.code, &filter) {
                return Ok(());
            }
            let mut bytes = Vec::new();
            let mut count = 0usize;
            write_geosite_entry_ruleset(raw, &mut bytes, &mut count)?;
            if count > 0 {
                outputs.push((meta.code.to_ascii_lowercase(), count, bytes));
            }
            Ok(())
        })?;
        if outputs.is_empty() {
            bail!("geosite dat input does not contain any matching records");
        }
        return Ok(outputs);
    }

    let mut bytes = Vec::new();
    let mut count = 0usize;
    for_each_raw_geosite_entry(input, |raw| {
        let meta = scan_geosite_entry_meta(raw)?;
        if matches_normalized_code(&meta.code, &filter) {
            write_geosite_entry_ruleset(raw, &mut bytes, &mut count)?;
        }
        Ok(())
    })?;
    if count == 0 {
        bail!("geosite dat input does not contain any matching records");
    }
    Ok(vec![("geosite".to_string(), count, bytes)])
}

#[cfg(not(target_arch = "wasm32"))]
pub fn export_geosite_dat_general_ruleset_to_path(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
    codes: &[String],
) -> Result<usize> {
    let input = input.as_ref();
    let output = output.as_ref();
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let reader = BufReader::new(File::open(input)?);
    let writer = BufWriter::new(File::create(output)?);
    export_geosite_dat_general_ruleset_to_writer(reader, writer, codes)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn export_geosite_dat_general_ruleset_to_writer<R: Read, W: Write>(
    reader: R,
    mut writer: W,
    codes: &[String],
) -> Result<usize> {
    let filter = normalize_code_filter(codes);
    let mut count = 0usize;
    for_each_raw_message_field_from_reader(reader, 1, "V2Ray geosite dat", |raw| {
        let meta = scan_geosite_entry_meta(raw)?;
        if matches_normalized_code(&meta.code, &filter) {
            write_geosite_entry_ruleset(raw, &mut writer, &mut count)?;
        }
        Ok(())
    })?;
    if count == 0 {
        bail!("geosite dat input does not contain any matching records");
    }
    Ok(count)
}

#[cfg(not(target_arch = "wasm32"))]
pub struct DatTextOutputFile {
    pub name: String,
    pub count: usize,
    pub path: PathBuf,
}

#[cfg(not(target_arch = "wasm32"))]
pub fn export_geosite_dat_general_ruleset_to_dir(
    input: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    codes: &[String],
) -> Result<Vec<DatTextOutputFile>> {
    let input = input.as_ref();
    let output_dir = output_dir.as_ref();
    fs::create_dir_all(output_dir)?;
    let reader = BufReader::new(File::open(input)?);
    export_geosite_dat_general_ruleset_to_dir_writer(reader, output_dir, codes)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn export_geosite_dat_general_ruleset_to_dir_writer<R: Read>(
    reader: R,
    output_dir: &Path,
    codes: &[String],
) -> Result<Vec<DatTextOutputFile>> {
    let filter = normalize_code_filter(codes);
    let mut files = Vec::new();
    for_each_raw_message_field_from_reader(reader, 1, "V2Ray geosite dat", |raw| {
        let meta = scan_geosite_entry_meta(raw)?;
        if !matches_normalized_code(&meta.code, &filter) {
            return Ok(());
        }
        let code = meta.code.to_ascii_lowercase();
        let path = output_dir.join(format!("{code}.list"));
        let file = File::create(&path)?;
        let mut writer = BufWriter::new(file);
        let mut count = 0usize;
        write_geosite_entry_ruleset(raw, &mut writer, &mut count)?;
        if count > 0 {
            files.push(DatTextOutputFile {
                name: code,
                count,
                path,
            });
        }
        Ok(())
    })?;
    if files.is_empty() {
        bail!("geosite dat input does not contain any matching records");
    }
    Ok(files)
}

fn write_geosite_entry_ruleset<W: Write>(
    input: &[u8],
    writer: &mut W,
    count: &mut usize,
) -> Result<()> {
    let mut pos = 0usize;
    while pos < input.len() {
        let (tag, wire_type, value_start, value_end) =
            scan_field(input, &mut pos, "V2Ray geosite dat entry")?;
        if (tag, wire_type) != (2, 2) {
            continue;
        }
        let payload_start = length_delimited_payload_start(input, value_start, value_end)?;
        let raw = &input[payload_start..value_end];
        if let Some((kind, value)) = scan_domain_rule(raw)? {
            match kind {
                DomainType::RootDomain => writeln!(writer, "DOMAIN-SUFFIX,{value}")?,
                DomainType::Full => writeln!(writer, "DOMAIN,{value}")?,
                DomainType::Plain => writeln!(writer, "DOMAIN-KEYWORD,{value}")?,
                DomainType::Regex => writeln!(writer, "DOMAIN-REGEX,{value}")?,
            }
            *count += 1;
        }
    }
    Ok(())
}

fn scan_domain_rule(input: &[u8]) -> Result<Option<(DomainType, &str)>> {
    let mut pos = 0usize;
    let mut kind = DomainType::Plain;
    let mut value = None;
    while pos < input.len() {
        let (tag, wire_type, value_start, value_end) =
            scan_field(input, &mut pos, "V2Ray geosite domain")?;
        match (tag, wire_type) {
            (1, 0) => {
                kind = DomainType::try_from(decode_varint(&input[value_start..value_end])? as i32)
                    .unwrap_or(DomainType::Plain);
            }
            (2, 2) => {
                let start = length_delimited_payload_start(input, value_start, value_end)?;
                let text = std::str::from_utf8(&input[start..value_end])?.trim();
                if !text.is_empty() {
                    value = Some(text);
                }
            }
            _ => {}
        }
    }
    Ok(value.map(|value| (kind, value)))
}

fn length_delimited_payload_start(
    input: &[u8],
    value_start: usize,
    value_end: usize,
) -> Result<usize> {
    let len = decode_varint(&input[value_start..value_end])? as usize;
    let mut start = value_start;
    while input.get(start).is_some_and(|byte| byte & 0x80 != 0) {
        start += 1;
    }
    start += 1;
    start
        .checked_add(len)
        .filter(|end| *end == value_end)
        .ok_or_else(|| anyhow::anyhow!("invalid V2Ray geosite length-delimited field"))?;
    Ok(start)
}

pub fn build_geosite_dat_from_rule_sets<I>(entries: I) -> Result<(usize, Vec<u8>)>
where
    I: IntoIterator<Item = (String, ConvertResult)>,
{
    let mut count = 0usize;
    let mut output = Vec::new();

    for (code, result) in entries {
        let code = normalize_code(&code);
        if code.is_empty() {
            bail!("geosite code is empty");
        }
        let mut domain = Vec::new();
        for output in result.outputs {
            if let RuleSetOutput::Domain(set) = output {
                set.for_each_rule(|rule| {
                    if let Some(item) = domain_from_rule(rule) {
                        domain.push(item);
                        count += 1;
                    }
                    Ok(())
                })?;
            }
        }
        for rule in result.mixed_rules.iter() {
            if let Some(item) = domain_from_mixed_rule(rule)? {
                domain.push(item);
                count += 1;
            }
        }
        if !domain.is_empty() {
            write_message_field(
                &mut output,
                1,
                &GeoSite {
                    country_code: code,
                    domain,
                },
            )?;
        }
    }

    if count == 0 {
        bail!("geosite dat output does not contain any domain records");
    }
    Ok((count, output))
}

struct GeositeEntryMeta {
    code: String,
    domain_count: usize,
}

fn for_each_raw_geosite_entry(input: &[u8], f: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
    for_each_raw_message_field(input, 1, "V2Ray geosite dat", f)
}

fn scan_geosite_entry_meta(input: &[u8]) -> Result<GeositeEntryMeta> {
    let mut pos = 0usize;
    let mut code = String::new();
    let mut domain_count = 0usize;
    while pos < input.len() {
        let (tag, wire_type, value_start, value_end) =
            scan_field(input, &mut pos, "V2Ray geosite dat entry")?;
        match (tag, wire_type) {
            (1, 2) => {
                let mut len_pos = value_start;
                let len = decode_varint(&input[value_start..value_end])? as usize;
                while input.get(len_pos).is_some_and(|byte| byte & 0x80 != 0) {
                    len_pos += 1;
                }
                len_pos += 1;
                let end = len_pos
                    .checked_add(len)
                    .filter(|end| *end <= value_end)
                    .ok_or_else(|| anyhow::anyhow!("invalid V2Ray geosite dat code length"))?;
                code = normalize_code(std::str::from_utf8(&input[len_pos..end])?);
            }
            (2, 2) => domain_count += 1,
            _ => {}
        }
    }
    Ok(GeositeEntryMeta { code, domain_count })
}

fn for_each_geosite_entry(input: &[u8], f: impl FnMut(GeoSite, &[u8]) -> Result<()>) -> Result<()> {
    for_each_message_field(input, 1, "V2Ray geosite dat", f)
}

fn push_geosite_entry(
    builder: &mut DomainSetBuilder,
    mixed_rules: &mut RuleTextStore,
    entry: &GeoSite,
) -> Result<()> {
    for domain in &entry.domain {
        match DomainType::try_from(domain.r#type).unwrap_or(DomainType::Plain) {
            DomainType::RootDomain => {
                let value = domain.value.trim();
                if !value.is_empty() {
                    let rule = format!("+.{value}");
                    builder.insert(&rule)?;
                    mixed_rules.push(format!("DOMAIN-SUFFIX,{value}"));
                }
            }
            DomainType::Full => {
                let value = domain.value.trim();
                if !value.is_empty() {
                    builder.insert(value)?;
                    mixed_rules.push(format!("DOMAIN,{value}"));
                }
            }
            DomainType::Plain => {
                let value = domain.value.trim();
                if !value.is_empty() {
                    mixed_rules.push(format!("DOMAIN-KEYWORD,{value}"));
                }
            }
            DomainType::Regex => {
                let value = domain.value.trim();
                if !value.is_empty() {
                    mixed_rules.push(format!("DOMAIN-REGEX,{value}"));
                }
            }
        }
    }
    Ok(())
}

fn domain_from_rule(rule: &str) -> Option<Domain> {
    let rule = rule.trim();
    if let Some(suffix) = rule.strip_prefix("+.") {
        return Some(domain(DomainType::RootDomain, suffix));
    }
    if let Some(suffix) = rule.strip_prefix('.') {
        return Some(domain(DomainType::RootDomain, suffix));
    }
    if rule.is_empty() {
        None
    } else {
        Some(domain(DomainType::Full, rule))
    }
}

fn domain_from_mixed_rule(rule: &str) -> Result<Option<Domain>> {
    let Some(rule) = classical_to_provider_rule(rule)? else {
        return Ok(None);
    };
    let mut parts = rule.splitn(3, ',');
    let Some(kind) = parts.next() else {
        return Ok(None);
    };
    let Some(value) = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let item = match kind.to_ascii_uppercase().as_str() {
        "DOMAIN-KEYWORD" => Some(domain(DomainType::Plain, value)),
        "DOMAIN-REGEX" => Some(domain(DomainType::Regex, value)),
        "DOMAIN" | "DOMAIN-SUFFIX" => None,
        _ => None,
    };
    Ok(item)
}

fn domain(kind: DomainType, value: &str) -> Domain {
    Domain {
        r#type: kind as i32,
        value: value.to_string(),
        attribute: Vec::new(),
    }
}

fn normalize_code_filter(codes: &[String]) -> Option<Vec<String>> {
    if codes.is_empty() {
        return None;
    }
    Some(
        codes
            .iter()
            .map(|code| normalize_code(code))
            .filter(|code| !code.is_empty())
            .collect(),
    )
}

fn normalize_code(code: &str) -> String {
    code.trim().to_ascii_uppercase()
}

fn matches_code(code: &str, filter: &Option<Vec<String>>) -> bool {
    let code = normalize_code(code);
    matches_normalized_code(&code, filter)
}

fn matches_normalized_code(code: &str, filter: &Option<Vec<String>>) -> bool {
    !code.is_empty()
        && filter
            .as_ref()
            .is_none_or(|filter| filter.iter().any(|item| item == code))
}
