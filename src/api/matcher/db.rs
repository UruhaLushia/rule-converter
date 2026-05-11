use std::path::Path;

use anyhow::Result;

use super::state::MatchState;
use super::{MatchInputFormat, MatchInputTarget, MatchOptions, MatchResult};
use crate::codec::dat::{DatKind, GeositeDatRuleSet, detect_dat_kind};
use crate::codec::db::MmdbFormat;
use crate::input::DetectedInput;
use crate::rules::BehaviorMode;
use crate::{InputFormat, RuleTarget};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DbInputKind {
    Geoip(MmdbFormat),
    Geosite,
    Asn,
}

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
            && matches!(
                options.input_format,
                None | Some(MatchInputFormat::Dat | MatchInputFormat::SingGeosite)
            ))
}

fn detect_db_input(payload: &[u8], options: MatchOptions) -> Option<DbInputKind> {
    if let Some(kind) = explicit_db_input_kind(options) {
        return Some(kind);
    }
    if options.input_target.is_some() {
        return None;
    }
    if matches!(options.input_format, None | Some(MatchInputFormat::Dat))
        && let Some(kind) = match detect_dat_kind(payload) {
            Some(DatKind::Geoip) => Some(DbInputKind::Geoip(MmdbFormat::Dat)),
            Some(DatKind::Geosite) => Some(DbInputKind::Geosite),
            None => None,
        }
    {
        return Some(kind);
    }
    if matches!(
        options.input_format,
        None | Some(MatchInputFormat::SingGeosite)
    ) && crate::codec::db::list_sing_geosite_codes(payload).is_ok_and(|codes| !codes.is_empty())
    {
        return Some(DbInputKind::Geosite);
    }
    if matches!(options.input_format, None | Some(MatchInputFormat::Mmdb))
        && let Ok(detected) = crate::detect_payload_type(payload)
    {
        return match (detected.target.as_str(), detected.format.as_str()) {
            ("geoip", "sing-db") => Some(DbInputKind::Geoip(MmdbFormat::SingDb)),
            ("geoip", "metadb") => Some(DbInputKind::Geoip(MmdbFormat::MetaDb)),
            ("geoip", _) => Some(DbInputKind::Geoip(MmdbFormat::Mmdb)),
            ("asn", _) => Some(DbInputKind::Asn),
            _ => None,
        };
    }
    None
}

fn explicit_db_input_kind(options: MatchOptions) -> Option<DbInputKind> {
    match (options.input_target, options.input_format) {
        (Some(MatchInputTarget::Geoip), Some(MatchInputFormat::Dat)) => {
            Some(DbInputKind::Geoip(MmdbFormat::Dat))
        }
        (Some(MatchInputTarget::Geoip), _) => Some(DbInputKind::Geoip(MmdbFormat::Mmdb)),
        (Some(MatchInputTarget::Geosite), _) => Some(DbInputKind::Geosite),
        (Some(MatchInputTarget::Asn), _) => Some(DbInputKind::Asn),
        _ => None,
    }
}

fn push_db_payload(payload: &[u8], kind: DbInputKind, state: &mut MatchState) -> Result<usize> {
    match kind {
        DbInputKind::Geoip(MmdbFormat::Dat) => push_geoip_dat_payload(payload, state),
        DbInputKind::Geoip(_) => push_geoip_mmdb_payload(payload, state),
        DbInputKind::Geosite => push_geosite_payload(payload, state),
        DbInputKind::Asn => push_asn_payload(payload, state),
    }
}

fn push_geoip_dat_payload(payload: &[u8], state: &mut MatchState) -> Result<usize> {
    let sets = crate::codec::dat::collect_geoip_dat_rule_sets(payload, &[])?;
    let mut total = 0usize;
    for set in sets {
        total += state.push_mrs_rule_set_with_context(&set.output, "geoip", &set.country);
    }
    Ok(total)
}

fn push_geoip_mmdb_payload(payload: &[u8], state: &mut MatchState) -> Result<usize> {
    let sets = crate::codec::db::collect_geoip_mmdb_rule_sets_from_bytes(payload, &[])?;
    let mut total = 0usize;
    for set in sets {
        total += state.push_mrs_rule_set_with_context(&set.output, "geoip", &set.country);
    }
    Ok(total)
}

fn push_asn_payload(payload: &[u8], state: &mut MatchState) -> Result<usize> {
    let sets = crate::codec::db::collect_asn_mmdb_rule_sets_from_bytes(payload, &[])?;
    let mut total = 0usize;
    for set in sets {
        let asn = format!("AS{}", set.asn);
        total += state.push_mrs_rule_set_with_context(&set.output, "asn", &asn);
    }
    Ok(total)
}

fn push_geosite_payload(payload: &[u8], state: &mut MatchState) -> Result<usize> {
    let sets = crate::codec::dat::collect_geosite_dat_rule_sets(payload, &[])
        .or_else(|_| crate::codec::db::collect_sing_geosite_rule_sets(payload, &[]))?;
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
