mod io;

use std::collections::BTreeMap;

use anyhow::{Result, bail};

use crate::api::ConvertResult;
use crate::codec::dat::GeositeDatRuleSet;
use crate::codec::mihomo::mrs::{DomainSetBuilder, RuleSetOutput};
use crate::rules::{BehaviorMode, RuleTextStore};
use io::{read_items, read_metadata, write_sing_geosite};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum SingGeositeRuleType {
    Domain = 0,
    DomainSuffix = 1,
    DomainKeyword = 2,
    DomainRegex = 3,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct SingGeositeItem {
    kind: SingGeositeRuleType,
    value: String,
}

pub fn list_sing_geosite_codes(input: &[u8]) -> Result<Vec<String>> {
    read_metadata(input).map(|metadata| metadata.into_iter().map(|item| item.code).collect())
}

pub fn filter_sing_geosite(input: &[u8], codes: &[String]) -> Result<(usize, Vec<u8>)> {
    let sets = collect_sing_geosite_rule_sets(input, codes)?;
    build_sing_geosite_from_rule_sets(
        sets.into_iter()
            .map(|set| (set.code.clone(), set.into_result())),
    )
}

pub fn collect_sing_geosite_rule_set(input: &[u8], codes: &[String]) -> Result<ConvertResult> {
    let sets = collect_sing_geosite_rule_sets(input, codes)?;
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

pub fn collect_sing_geosite_rule_sets(
    input: &[u8],
    codes: &[String],
) -> Result<Vec<GeositeDatRuleSet>> {
    let filter = normalize_code_filter(codes);
    let metadata = read_metadata(input)?;
    let mut outputs = Vec::new();
    for item in metadata {
        if !matches_code(&item.code, &filter) {
            continue;
        }
        let items = read_items(input, item.index, item.len)?;
        let mut builder = DomainSetBuilder::default();
        let mut mixed_rules = RuleTextStore::default();
        for item in items {
            push_item(&mut builder, &mut mixed_rules, item)?;
        }
        if !builder.is_empty() || !mixed_rules.is_empty() {
            let output = if builder.is_empty() {
                None
            } else {
                Some(RuleSetOutput::Domain(builder.finish()?))
            };
            outputs.push(GeositeDatRuleSet {
                code: item.code,
                output,
                mixed_rules,
            });
        }
    }
    if outputs.is_empty() {
        bail!("sing-geosite input does not contain any matching records");
    }
    Ok(outputs)
}

pub fn build_sing_geosite_from_rule_sets<I>(entries: I) -> Result<(usize, Vec<u8>)>
where
    I: IntoIterator<Item = (String, ConvertResult)>,
{
    let mut map: BTreeMap<String, Vec<SingGeositeItem>> = BTreeMap::new();
    let mut count = 0usize;
    for (code, result) in entries {
        let code = normalize_code(&code).to_ascii_lowercase();
        if code.is_empty() {
            bail!("sing-geosite code is empty");
        }
        let mut items = Vec::new();
        for output in result.outputs {
            if let RuleSetOutput::Domain(set) = output {
                set.for_each_rule(|rule| {
                    if let Some(item) = item_from_rule(rule) {
                        items.push(item);
                    }
                    Ok(())
                })?;
            }
        }
        for rule in result.mixed_rules.iter() {
            if let Some(item) = item_from_mixed_rule(rule)? {
                items.push(item);
            }
        }
        items.sort_unstable();
        items.dedup();
        count += items.len();
        if !items.is_empty() {
            map.insert(code, items);
        }
    }
    if count == 0 {
        bail!("sing-geosite output does not contain any domain records");
    }
    write_sing_geosite(map, count)
}

fn push_item(
    builder: &mut DomainSetBuilder,
    mixed_rules: &mut RuleTextStore,
    item: SingGeositeItem,
) -> Result<()> {
    let value = item.value.trim();
    if value.is_empty() {
        return Ok(());
    }
    match item.kind {
        SingGeositeRuleType::Domain => {
            builder.insert(value)?;
            mixed_rules.push(format!("DOMAIN,{value}"));
        }
        SingGeositeRuleType::DomainSuffix => {
            let value = value.strip_prefix('.').unwrap_or(value);
            let rule = format!("+.{value}");
            builder.insert(&rule)?;
            mixed_rules.push(format!("DOMAIN-SUFFIX,{value}"));
        }
        SingGeositeRuleType::DomainKeyword => mixed_rules.push(format!("DOMAIN-KEYWORD,{value}")),
        SingGeositeRuleType::DomainRegex => mixed_rules.push(format!("DOMAIN-REGEX,{value}")),
    }
    Ok(())
}

fn item_from_rule(rule: &str) -> Option<SingGeositeItem> {
    let rule = rule.trim();
    if let Some(suffix) = rule.strip_prefix("+.").or_else(|| rule.strip_prefix('.')) {
        return Some(SingGeositeItem {
            kind: SingGeositeRuleType::DomainSuffix,
            value: format!(".{}", suffix.trim_start_matches('.')),
        });
    }
    if rule.is_empty() {
        None
    } else {
        Some(SingGeositeItem {
            kind: SingGeositeRuleType::Domain,
            value: rule.to_string(),
        })
    }
}

fn item_from_mixed_rule(rule: &str) -> Result<Option<SingGeositeItem>> {
    let Some(rule) = crate::rules::classical_to_provider_rule(rule)? else {
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
    let kind = match kind.to_ascii_uppercase().as_str() {
        "DOMAIN" => SingGeositeRuleType::Domain,
        "DOMAIN-SUFFIX" => SingGeositeRuleType::DomainSuffix,
        "DOMAIN-KEYWORD" => SingGeositeRuleType::DomainKeyword,
        "DOMAIN-REGEX" => SingGeositeRuleType::DomainRegex,
        _ => return Ok(None),
    };
    let value = if matches!(kind, SingGeositeRuleType::DomainSuffix) {
        format!(".{}", value.trim_start_matches('.'))
    } else {
        value.to_string()
    };
    Ok(Some(SingGeositeItem { kind, value }))
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
    !code.is_empty()
        && filter
            .as_ref()
            .is_none_or(|filter| filter.iter().any(|item| item == &code))
}

fn io_error_from_anyhow(err: anyhow::Error) -> std::io::Error {
    std::io::Error::other(err.to_string())
}
