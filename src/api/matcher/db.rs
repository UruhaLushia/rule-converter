use std::path::Path;

use anyhow::Result;

use super::state::MatchState;
use super::{MatchInputFormat, MatchInputTarget, MatchOptions, MatchResult};
use crate::codec::dat::{DatKind, GeositeDatRuleSet, detect_dat_kind};
use crate::input::DetectedInput;
use crate::rules::BehaviorMode;
use crate::{InputFormat, RuleTarget};

pub(super) fn match_db_payload(
    payload: &[u8],
    query: &str,
    options: MatchOptions,
) -> Result<Option<MatchResult>> {
    let Some(kind) = detect_db_input(payload, options) else {
        return Ok(None);
    };
    let mut state = MatchState::new(query);
    let count = push_db_payload(payload, kind, &mut state)?;
    if count == 0 {
        anyhow::bail!("input does not contain any rules in `rules` or `payload`");
    }
    Ok(Some(state.finish()))
}

pub(super) fn match_db_file(
    path: &Path,
    options: MatchOptions,
    state: &mut MatchState,
) -> Result<Option<usize>> {
    let bytes = if should_read_file_for_db_detection(options) {
        Some(
            std::fs::read(path)
                .map_err(|err| anyhow::anyhow!("failed to read input {}: {err}", path.display()))?,
        )
    } else {
        None
    };
    let kind = if let Some(bytes) = bytes.as_deref() {
        detect_db_input(bytes, options)
    } else {
        explicit_db_input_kind(options)
    };
    let Some(kind) = kind else {
        return Ok(None);
    };
    let bytes = match bytes {
        Some(bytes) => bytes,
        None => std::fs::read(path)
            .map_err(|err| anyhow::anyhow!("failed to read input {}: {err}", path.display()))?,
    };
    push_db_payload(&bytes, kind, state).map(Some)
}

fn should_read_file_for_db_detection(options: MatchOptions) -> bool {
    explicit_db_input_kind(options).is_some()
        || (options.input_target.is_none()
            && matches!(options.input_format, None | Some(MatchInputFormat::Dat)))
}

fn detect_db_input(payload: &[u8], options: MatchOptions) -> Option<MatchInputTarget> {
    if let Some(kind) = explicit_db_input_kind(options) {
        return Some(kind);
    }
    if options.input_target.is_none()
        && matches!(options.input_format, None | Some(MatchInputFormat::Dat))
    {
        return match detect_dat_kind(payload) {
            Some(DatKind::Geoip) => Some(MatchInputTarget::Geoip),
            Some(DatKind::Geosite) => Some(MatchInputTarget::Geosite),
            None => None,
        };
    }
    None
}

fn explicit_db_input_kind(options: MatchOptions) -> Option<MatchInputTarget> {
    match (options.input_target, options.input_format) {
        (Some(MatchInputTarget::Geoip), _) => Some(MatchInputTarget::Geoip),
        (Some(MatchInputTarget::Geosite), _) => Some(MatchInputTarget::Geosite),
        (Some(MatchInputTarget::Asn), _) => Some(MatchInputTarget::Asn),
        _ => None,
    }
}

fn push_db_payload(
    payload: &[u8],
    kind: MatchInputTarget,
    state: &mut MatchState,
) -> Result<usize> {
    let rule_set = match kind {
        MatchInputTarget::Geoip => crate::codec::dat::collect_geoip_dat_rule_set(payload, &[])?,
        MatchInputTarget::Geosite => {
            return push_geosite_dat_payload(payload, state);
        }
        MatchInputTarget::Asn => {
            crate::codec::db::collect_asn_mmdb_rule_set_from_bytes(payload, &[])?
        }
        MatchInputTarget::Rule(_) => return Ok(0),
    };
    Ok(state.push_mrs_rule_set(&rule_set))
}

fn push_geosite_dat_payload(payload: &[u8], state: &mut MatchState) -> Result<usize> {
    let sets = crate::codec::dat::collect_geosite_dat_rule_sets(payload, &[])?;
    let mut total = 0usize;
    for set in sets {
        total += push_geosite_dat_set(set, state)?;
    }
    Ok(total)
}

fn push_geosite_dat_set(set: GeositeDatRuleSet, state: &mut MatchState) -> Result<usize> {
    let code = set.code;
    let detected = DetectedInput {
        target: RuleTarget::General,
        format: InputFormat::Text,
        behavior: BehaviorMode::Classical,
    };
    let mut total = 0usize;
    for rule in set.mixed_rules.iter() {
        total += 1;
        state.push_rule_with_context(rule, detected, "geosite", &code)?;
    }
    Ok(total)
}
