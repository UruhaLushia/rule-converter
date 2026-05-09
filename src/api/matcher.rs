use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::BufReader;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use regex::Regex;
use serde::Serialize;
use yaml_rust2::Yaml;

use crate::codec::mihomo::mrs::{Behavior, RuleSetOutput, prefix_contains_ip, read_mrs_stream};
use crate::input::{
    DetectedInput, InputSource, detect_path, detect_payload, expand_file_paths, for_each_rule,
};
use crate::rules::{BehaviorMode, ClassicalKind, InputBehaviorMode};
use crate::{FileInput, InputFormat, RuleTarget};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatchOptions {
    pub input_target: Option<RuleTarget>,
    pub input_format: Option<InputFormat>,
    pub input_behavior: InputBehaviorMode,
}

impl Default for MatchOptions {
    fn default() -> Self {
        Self {
            input_target: None,
            input_format: None,
            input_behavior: InputBehaviorMode::Auto,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchQueryKind {
    Domain,
    Ip,
}

impl MatchQueryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Ip => "ip",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MatchedRule {
    #[serde(serialize_with = "serialize_behavior")]
    pub behavior: Behavior,
    pub rule: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MatchResult {
    pub matched: bool,
    pub query: String,
    pub kind: MatchQueryKind,
    pub rules: Vec<MatchedRule>,
}

pub fn match_payload(
    payload: impl AsRef<[u8]>,
    query: &str,
    options: MatchOptions,
) -> Result<MatchResult> {
    let payload = payload.as_ref();
    let detected = apply_match_options(detect_payload(payload)?, options);
    if detected.target == RuleTarget::Mihomo
        && detected.format == InputFormat::Yaml
        && let Some(result) = match_mihomo_config_payload(payload, query)?
    {
        return Ok(result);
    }
    let mut state = MatchState::new(query);
    if detected.target == RuleTarget::Mihomo && detected.format == InputFormat::Mrs {
        let rule_set = crate::codec::mihomo::mrs::read_mrs(payload)?;
        let count = state.push_mrs_rule_set(&rule_set);
        if count == 0 {
            anyhow::bail!("input does not contain any rules in `rules` or `payload`");
        }
        return Ok(state.finish());
    }
    let count = for_each_rule(
        InputSource::Payload(payload),
        detected.target,
        detected.format,
        |rule| state.push_rule(rule, detected),
    )?;
    if count == 0 {
        anyhow::bail!("input does not contain any rules in `rules` or `payload`");
    }
    Ok(state.finish())
}

pub fn match_file(
    path: impl AsRef<Path>,
    query: &str,
    options: MatchOptions,
) -> Result<MatchResult> {
    match_file_inputs(
        [FileInput {
            path: path.as_ref().to_path_buf(),
            target: options.input_target,
            format: options.input_format,
            behavior: options.input_behavior,
        }],
        query,
        options,
    )
}

pub fn match_files<P, I>(paths: I, query: &str, options: MatchOptions) -> Result<MatchResult>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = P>,
{
    let inputs = paths
        .into_iter()
        .map(|path| FileInput {
            path: path.as_ref().to_path_buf(),
            target: options.input_target,
            format: options.input_format,
            behavior: options.input_behavior,
        })
        .collect::<Vec<_>>();
    match_file_inputs(inputs, query, options)
}

pub fn match_file_inputs<I>(inputs: I, query: &str, options: MatchOptions) -> Result<MatchResult>
where
    I: IntoIterator<Item = FileInput>,
{
    let mut state = MatchState::new(query);
    let mut total = 0usize;
    for input in inputs {
        let expanded = expand_file_paths([input.path])?;
        for path in expanded {
            let item_options = MatchOptions {
                input_target: input.target.or(options.input_target),
                input_format: input.format.or(options.input_format),
                input_behavior: if input.behavior == InputBehaviorMode::Auto {
                    options.input_behavior
                } else {
                    input.behavior
                },
            };
            let detected = detect_match_file_input(&path, item_options)?;
            if detected.target == RuleTarget::Mihomo
                && detected.format == InputFormat::Yaml
                && let Some(result) = match_mihomo_config_path(&path, &mut state)?
            {
                total += result;
                continue;
            }
            if detected.target == RuleTarget::Mihomo && detected.format == InputFormat::Mrs {
                let file = File::open(&path).map(BufReader::new).map_err(|err| {
                    anyhow::anyhow!("failed to read input {}: {err}", path.display())
                })?;
                let rule_set = read_mrs_stream(file)?;
                total += state.push_mrs_rule_set(&rule_set);
                continue;
            }
            total += for_each_rule(
                InputSource::FilePath(&path),
                detected.target,
                detected.format,
                |rule| state.push_rule(rule, detected),
            )?;
        }
    }
    if total == 0 {
        anyhow::bail!("input does not contain any rules in `rules` or `payload`");
    }
    Ok(state.finish())
}

#[derive(Clone)]
struct MihomoProvider {
    path: Option<String>,
    url: Option<String>,
    target: Option<RuleTarget>,
    format: Option<InputFormat>,
    behavior: InputBehaviorMode,
}

fn match_mihomo_config_payload(payload: &[u8], query: &str) -> Result<Option<MatchResult>> {
    let text = std::str::from_utf8(payload).context("failed to parse mihomo config as UTF-8")?;
    let Some(config) = MihomoMatchConfig::parse(text)? else {
        return Ok(None);
    };
    let mut state = MatchState::new(query);
    config.match_from_base(None, &mut state)?;
    Ok(Some(state.finish()))
}

fn match_mihomo_config_path(path: &Path, state: &mut MatchState) -> Result<Option<usize>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("failed to read input {}", path.display()))?;
    let Some(config) = MihomoMatchConfig::parse(&text)? else {
        return Ok(None);
    };
    let base = path.parent().filter(|path| !path.as_os_str().is_empty());
    config.match_from_base(base, state).map(Some)
}

struct MihomoMatchConfig {
    rules: Vec<String>,
    providers: HashMap<String, MihomoProvider>,
}

impl MihomoMatchConfig {
    fn parse(text: &str) -> Result<Option<Self>> {
        let docs = yaml_rust2::YamlLoader::load_from_str(text)
            .map_err(|err| anyhow::anyhow!("failed to parse mihomo config YAML: {err}"))?;
        let Some(doc) = docs.first() else {
            return Ok(None);
        };
        let Some(root) = doc.as_hash() else {
            return Ok(None);
        };
        let Some(providers_yaml) = yaml_get(root, "rule-providers") else {
            return Ok(None);
        };
        let Some(rules_yaml) = yaml_get(root, "rules") else {
            return Ok(None);
        };

        let mut rules = Vec::new();
        if let Some(values) = rules_yaml.as_vec() {
            rules.reserve(values.len());
            for value in values {
                if let Some(rule) = value
                    .as_str()
                    .map(str::trim)
                    .filter(|rule| !rule.is_empty())
                {
                    rules.push(rule.to_string());
                }
            }
        } else {
            return Ok(None);
        }

        let mut providers = HashMap::new();
        if let Some(values) = providers_yaml.as_hash() {
            providers.reserve(values.len());
            for (name, provider_yaml) in values {
                let Some(name) = name.as_str() else {
                    continue;
                };
                if let Some(provider) = parse_mihomo_provider(provider_yaml) {
                    providers.insert(name.to_string(), provider);
                }
            }
        }

        Ok(Some(Self { rules, providers }))
    }

    fn match_from_base(&self, base: Option<&Path>, state: &mut MatchState) -> Result<usize> {
        let mut total = 0usize;
        for rule in &self.rules {
            let Some(parsed) = parse_match_rule(rule) else {
                continue;
            };
            match parsed.kind {
                ClassicalKind::RuleSet => {
                    let Some(name) = parsed.payload else {
                        continue;
                    };
                    let Some(provider) = self.providers.get(name) else {
                        continue;
                    };
                    let before = state.rules.len();
                    total += match_mihomo_provider(provider, base, state)
                        .with_context(|| format!("failed to match rule provider `{name}`"))?;
                    if state.rules.len() > before {
                        state.rules.truncate(before);
                        state.push_matched_rule(
                            match state.query.kind() {
                                MatchQueryKind::Domain => Behavior::Domain,
                                MatchQueryKind::Ip => Behavior::Ipcidr,
                            },
                            rule.clone(),
                        );
                        break;
                    }
                }
                ClassicalKind::Match => {
                    state.push_matched_rule(
                        match state.query.kind() {
                            MatchQueryKind::Domain => Behavior::Domain,
                            MatchQueryKind::Ip => Behavior::Ipcidr,
                        },
                        rule.clone(),
                    );
                    total += 1;
                    break;
                }
                _ => {
                    state.push_rule(
                        rule,
                        DetectedInput {
                            target: RuleTarget::Mihomo,
                            format: InputFormat::Yaml,
                            behavior: BehaviorMode::Classical,
                        },
                    )?;
                    total += 1;
                    if !state.rules.is_empty() {
                        break;
                    }
                }
            }
        }
        Ok(total)
    }
}

fn parse_mihomo_provider(value: &Yaml) -> Option<MihomoProvider> {
    let hash = value.as_hash()?;
    let path = yaml_get_merged_str(hash, "path").map(str::to_string);
    let url = yaml_get_merged_str(hash, "url").map(str::to_string);
    let format = yaml_get_merged_str(hash, "format").and_then(parse_input_format_name);
    let behavior = yaml_get_merged_str(hash, "behavior")
        .and_then(parse_input_behavior_name)
        .unwrap_or(InputBehaviorMode::Auto);
    let target = if format == Some(InputFormat::Mrs) {
        Some(RuleTarget::Mihomo)
    } else {
        yaml_get_merged_str(hash, "target").and_then(parse_rule_target_name)
    };
    Some(MihomoProvider {
        path,
        url,
        target,
        format,
        behavior,
    })
}

fn match_mihomo_provider(
    provider: &MihomoProvider,
    base: Option<&Path>,
    state: &mut MatchState,
) -> Result<usize> {
    if let Some(path) = &provider.path {
        let path = resolve_provider_path(path, base);
        return match_provider_path(provider, &path, state);
    }
    if let Some(url) = &provider.url {
        if let Some(path) = local_path_from_file_url(url) {
            return match_provider_path(provider, &path, state);
        }
        #[cfg(feature = "http")]
        {
            let payload = download_provider_to_memory(url)?;
            return match_provider_payload(provider, &payload, state);
        }
        #[cfg(not(feature = "http"))]
        {
            anyhow::bail!("rule provider URL needs the `http` feature: {url}");
        }
    }
    anyhow::bail!("rule provider missing path or url")
}

fn match_provider_path(
    provider: &MihomoProvider,
    path: &Path,
    state: &mut MatchState,
) -> Result<usize> {
    let options = MatchOptions {
        input_target: provider.target,
        input_format: provider.format,
        input_behavior: provider.behavior,
    };
    let detected = detect_match_file_input(path, options)?;
    if detected.target == RuleTarget::Mihomo && detected.format == InputFormat::Mrs {
        let file = File::open(path)
            .map(BufReader::new)
            .with_context(|| format!("failed to read input {}", path.display()))?;
        let rule_set = read_mrs_stream(file)?;
        return Ok(state.push_mrs_rule_set(&rule_set));
    }
    for_each_rule(
        InputSource::FilePath(path),
        detected.target,
        detected.format,
        |rule| state.push_rule(rule, detected),
    )
}

#[cfg(feature = "http")]
fn match_provider_payload(
    provider: &MihomoProvider,
    payload: &[u8],
    state: &mut MatchState,
) -> Result<usize> {
    let options = MatchOptions {
        input_target: provider.target,
        input_format: provider.format,
        input_behavior: provider.behavior,
    };
    let detected = apply_match_options(detect_payload(payload)?, options);
    if detected.target == RuleTarget::Mihomo && detected.format == InputFormat::Mrs {
        let rule_set = crate::codec::mihomo::mrs::read_mrs(payload)?;
        return Ok(state.push_mrs_rule_set(&rule_set));
    }
    for_each_rule(
        InputSource::Payload(payload),
        detected.target,
        detected.format,
        |rule| state.push_rule(rule, detected),
    )
}

fn resolve_provider_path(path: &str, base: Option<&Path>) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else if let Some(base) = base {
        base.join(path)
    } else {
        path
    }
}

fn local_path_from_file_url(url: &str) -> Option<PathBuf> {
    url.strip_prefix("file://").map(PathBuf::from)
}

#[cfg(feature = "http")]
fn download_provider_to_memory(url: &str) -> Result<Vec<u8>> {
    let mut response = ureq::get(url)
        .call()
        .with_context(|| format!("failed to download rule provider: {url}"))?;
    response
        .body_mut()
        .with_config()
        .limit(64 * 1024 * 1024)
        .read_to_vec()
        .with_context(|| format!("failed to read rule provider response: {url}"))
}

fn yaml_get<'a>(hash: &'a yaml_rust2::yaml::Hash, key: &str) -> Option<&'a Yaml> {
    hash.get(&Yaml::String(key.to_string()))
}

fn yaml_get_merged_str<'a>(hash: &'a yaml_rust2::yaml::Hash, key: &str) -> Option<&'a str> {
    yaml_get(hash, key).and_then(Yaml::as_str).or_else(|| {
        yaml_get(hash, "<<")?
            .as_hash()
            .and_then(|merged| yaml_get_merged_str(merged, key))
    })
}

fn parse_input_format_name(value: &str) -> Option<InputFormat> {
    match value {
        value if value.eq_ignore_ascii_case("mrs") => Some(InputFormat::Mrs),
        value if value.eq_ignore_ascii_case("yaml") || value.eq_ignore_ascii_case("yml") => {
            Some(InputFormat::Yaml)
        }
        value if value.eq_ignore_ascii_case("text") || value.eq_ignore_ascii_case("list") => {
            Some(InputFormat::Text)
        }
        value if value.eq_ignore_ascii_case("srs") => Some(InputFormat::Srs),
        value if value.eq_ignore_ascii_case("json") => Some(InputFormat::Json),
        _ => None,
    }
}

fn parse_input_behavior_name(value: &str) -> Option<InputBehaviorMode> {
    match value {
        value if value.eq_ignore_ascii_case("domain") => Some(InputBehaviorMode::Domain),
        value if value.eq_ignore_ascii_case("ip") || value.eq_ignore_ascii_case("ipcidr") => {
            Some(InputBehaviorMode::Ipcidr)
        }
        value if value.eq_ignore_ascii_case("classical") => Some(InputBehaviorMode::Classical),
        value if value.eq_ignore_ascii_case("auto") => Some(InputBehaviorMode::Auto),
        _ => None,
    }
}

fn parse_rule_target_name(value: &str) -> Option<RuleTarget> {
    match value {
        value if value.eq_ignore_ascii_case("mihomo") || value.eq_ignore_ascii_case("clash") => {
            Some(RuleTarget::Mihomo)
        }
        value if value.eq_ignore_ascii_case("general") => Some(RuleTarget::General),
        value if value.eq_ignore_ascii_case("egern") => Some(RuleTarget::Egern),
        value
            if value.eq_ignore_ascii_case("sing-box") || value.eq_ignore_ascii_case("sing_box") =>
        {
            Some(RuleTarget::SingBox)
        }
        _ => None,
    }
}

enum Query {
    Domain(String),
    Ip(IpAddr),
}

impl Query {
    fn value(&self) -> String {
        match self {
            Self::Domain(value) => value.clone(),
            Self::Ip(value) => value.to_string(),
        }
    }

    fn kind(&self) -> MatchQueryKind {
        match self {
            Self::Domain(_) => MatchQueryKind::Domain,
            Self::Ip(_) => MatchQueryKind::Ip,
        }
    }
}

fn parse_query(query: &str) -> Query {
    let query = query.trim();
    if let Ok(ip) = query.parse::<IpAddr>() {
        return Query::Ip(ip);
    }
    Query::Domain(query.trim_end_matches('.').to_ascii_lowercase())
}

struct MatchState {
    query: Query,
    rules: Vec<MatchedRule>,
}

impl MatchState {
    fn new(query: &str) -> Self {
        Self {
            query: parse_query(query),
            rules: Vec::new(),
        }
    }

    fn push_rule(&mut self, rule: &str, detected: DetectedInput) -> Result<()> {
        match &self.query {
            Query::Domain(domain) => {
                if rule_matches_domain(rule, domain, detected)? {
                    self.push_matched_rule(Behavior::Domain, rule.to_string());
                }
            }
            Query::Ip(ip) => {
                if rule_matches_ip(rule, *ip)? {
                    self.push_matched_rule(Behavior::Ipcidr, rule.to_string());
                }
            }
        }
        Ok(())
    }

    fn push_matched_rule(&mut self, behavior: Behavior, rule: String) {
        self.rules.push(MatchedRule { behavior, rule });
    }

    fn push_mrs_rule_set(&mut self, rule_set: &RuleSetOutput) -> usize {
        let count = rule_set.count();
        match (&self.query, rule_set) {
            (Query::Domain(domain), RuleSetOutput::Domain(set)) => {
                if set.contains_domain(domain) {
                    self.rules.push(MatchedRule {
                        behavior: Behavior::Domain,
                        rule: domain.clone(),
                    });
                }
            }
            (Query::Ip(ip), RuleSetOutput::Ipcidr(set)) => {
                if let Some(rule) = set.matching_prefix(*ip) {
                    self.rules.push(MatchedRule {
                        behavior: Behavior::Ipcidr,
                        rule,
                    });
                }
            }
            _ => {}
        }
        count
    }

    fn finish(self) -> MatchResult {
        MatchResult {
            matched: !self.rules.is_empty(),
            query: self.query.value(),
            kind: self.query.kind(),
            rules: self.rules,
        }
    }
}

fn detect_match_file_input(path: &Path, options: MatchOptions) -> Result<DetectedInput> {
    if let (Some(target), Some(format)) = (options.input_target, options.input_format) {
        return Ok(DetectedInput {
            target,
            format,
            behavior: input_behavior_to_output_mode(options.input_behavior),
        });
    }
    detect_path(path).map(|detected| apply_match_options(detected, options))
}

fn apply_match_options(mut detected: DetectedInput, options: MatchOptions) -> DetectedInput {
    if let Some(target) = options.input_target {
        detected.target = target;
    }
    if let Some(format) = options.input_format {
        detected.format = format;
    }
    if options.input_behavior != InputBehaviorMode::Auto {
        detected.behavior = input_behavior_to_output_mode(options.input_behavior);
    }
    detected
}

fn input_behavior_to_output_mode(behavior: InputBehaviorMode) -> BehaviorMode {
    match behavior {
        InputBehaviorMode::Auto => BehaviorMode::Auto,
        InputBehaviorMode::Domain => BehaviorMode::Domain,
        InputBehaviorMode::Ipcidr => BehaviorMode::Ipcidr,
        InputBehaviorMode::Classical => BehaviorMode::Classical,
    }
}

fn rule_matches_domain(rule: &str, domain: &str, detected: DetectedInput) -> Result<bool> {
    if let Some(parsed) = parse_match_rule(rule) {
        return parsed_rule_matches_domain(parsed, domain);
    }
    if has_classical_marker(rule)
        || matches!(detected.behavior, BehaviorMode::Ipcidr)
        || prefix_contains_ip_query(rule).is_some()
    {
        return Ok(false);
    }
    Ok(plain_domain_rule_matches(rule, domain, detected.target))
}

fn rule_matches_ip(rule: &str, ip: IpAddr) -> Result<bool> {
    if let Some(parsed) = parse_match_rule(rule) {
        return parsed_rule_matches_ip(parsed, ip);
    }
    if has_classical_marker(rule) {
        return Ok(false);
    }
    prefix_contains_ip(rule, ip)
}

#[derive(Clone, Copy)]
struct ParsedMatchRule<'a> {
    kind: ClassicalKind,
    payload: Option<&'a str>,
}

fn parse_match_rule(rule: &str) -> Option<ParsedMatchRule<'_>> {
    let (kind, rest) = split_first_top_level_field(rule);
    let kind = parse_match_kind(kind.trim())?;
    let payload = if kind == ClassicalKind::Match {
        None
    } else {
        let (payload, _) = split_first_top_level_field(rest?);
        Some(payload.trim()).filter(|value| !value.is_empty())
    };
    Some(ParsedMatchRule { kind, payload })
}

fn split_first_top_level_field(value: &str) -> (&str, Option<&str>) {
    let mut depth = 0usize;
    for (index, ch) in value.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => return (&value[..index], Some(&value[index + ch.len_utf8()..])),
            _ => {}
        }
    }
    (value, None)
}

fn parse_match_kind(value: &str) -> Option<ClassicalKind> {
    if value.eq_ignore_ascii_case("DOMAIN") {
        Some(ClassicalKind::Domain)
    } else if value.eq_ignore_ascii_case("DOMAIN-SUFFIX") {
        Some(ClassicalKind::DomainSuffix)
    } else if value.eq_ignore_ascii_case("DOMAIN-KEYWORD") {
        Some(ClassicalKind::DomainKeyword)
    } else if value.eq_ignore_ascii_case("DOMAIN-REGEX") {
        Some(ClassicalKind::DomainRegex)
    } else if value.eq_ignore_ascii_case("DOMAIN-WILDCARD") {
        Some(ClassicalKind::DomainWildcard)
    } else if value.eq_ignore_ascii_case("IP-CIDR") || value.eq_ignore_ascii_case("IP-CIDR6") {
        Some(ClassicalKind::Ipcidr)
    } else if value.eq_ignore_ascii_case("SRC-IP-CIDR") {
        Some(ClassicalKind::SrcIpcidr)
    } else if value.eq_ignore_ascii_case("RULE-SET") {
        Some(ClassicalKind::RuleSet)
    } else if value.eq_ignore_ascii_case("MATCH") {
        Some(ClassicalKind::Match)
    } else {
        None
    }
}

fn has_classical_marker(rule: &str) -> bool {
    let (kind, rest) = split_first_top_level_field(rule);
    let kind = kind.trim();
    rest.is_some()
        && !kind.is_empty()
        && kind
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && kind
            .bytes()
            .any(|byte| byte.is_ascii_uppercase() || byte == b'-')
}

fn prefix_contains_ip_query(rule: &str) -> Option<()> {
    rule.trim().split_once('/')?;
    Some(())
}

fn plain_domain_rule_matches(rule: &str, domain: &str, target: RuleTarget) -> bool {
    let rule = normalize_domain_text(rule);
    let rule = rule.as_ref();
    if rule.is_empty() {
        return false;
    }
    if target == RuleTarget::Mihomo {
        if let Some(suffix) = rule.strip_prefix("+.") {
            return domain_matches_suffix(domain, suffix);
        }
        if let Some(suffix) = rule.strip_prefix('.') {
            return domain
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.') && !prefix.is_empty());
        }
        return domain == rule;
    }
    if let Some(suffix) = rule.strip_prefix("+.").or_else(|| rule.strip_prefix('.')) {
        return domain_matches_suffix(domain, suffix);
    }
    domain == rule
}

fn parsed_rule_matches_domain(parsed: ParsedMatchRule<'_>, domain: &str) -> Result<bool> {
    let Some(payload) = parsed.payload else {
        return Ok(false);
    };
    let payload = normalize_domain_text(payload);
    let payload = payload.as_ref();

    match parsed.kind {
        ClassicalKind::Domain => Ok(domain == payload),
        ClassicalKind::DomainSuffix => Ok(domain_matches_suffix(domain, payload)),
        ClassicalKind::DomainKeyword => Ok(domain.contains(payload)),
        ClassicalKind::DomainRegex => Ok(Regex::new(payload)?.is_match(domain)),
        ClassicalKind::DomainWildcard => Ok(wildcard_match(payload, domain)),
        _ => Ok(false),
    }
}

fn parsed_rule_matches_ip(parsed: ParsedMatchRule<'_>, ip: IpAddr) -> Result<bool> {
    let Some(payload) = parsed.payload else {
        return Ok(false);
    };
    match parsed.kind {
        ClassicalKind::Ipcidr | ClassicalKind::SrcIpcidr => prefix_contains_ip(payload.trim(), ip),
        _ => Ok(false),
    }
}

fn normalize_domain_text(value: &str) -> Cow<'_, str> {
    let value = value.trim().trim_end_matches('.');
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(value.to_ascii_lowercase())
    } else {
        Cow::Borrowed(value)
    }
}

fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    let suffix = suffix.trim_start_matches('.');
    domain == suffix
        || domain
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut p, mut v) = (0usize, 0usize);
    let mut star = None;
    let mut star_match = 0usize;

    while v < value.len() {
        if p < pattern.len() && (pattern[p] == value[v] || pattern[p] == b'?') {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            star_match = v;
        } else if let Some(star_pos) = star {
            p = star_pos + 1;
            star_match += 1;
            v = star_match;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

fn serialize_behavior<S>(behavior: &Behavior, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(behavior.as_str())
}
