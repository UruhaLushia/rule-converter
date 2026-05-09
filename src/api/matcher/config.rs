use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use super::provider::{MihomoProvider, match_mihomo_provider, parse_mihomo_provider, yaml_get};
use super::rule::parse_match_rule;
use super::state::MatchState;
use super::{MatchQueryKind, MatchResult};
use crate::codec::mihomo::mrs::Behavior;
use crate::input::DetectedInput;
use crate::rules::{BehaviorMode, ClassicalKind};
use crate::{InputFormat, RuleTarget};

pub(super) fn match_mihomo_config_payload(
    payload: &[u8],
    query: &str,
) -> Result<Option<MatchResult>> {
    let text = std::str::from_utf8(payload).context("failed to parse mihomo config as UTF-8")?;
    let Some(config) = MihomoMatchConfig::parse(text)? else {
        return Ok(None);
    };
    let mut state = MatchState::new(query);
    config.match_from_base(None, &mut state)?;
    Ok(Some(state.finish()))
}

pub(super) fn match_mihomo_config_path(
    path: &Path,
    state: &mut MatchState,
) -> Result<Option<usize>> {
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
