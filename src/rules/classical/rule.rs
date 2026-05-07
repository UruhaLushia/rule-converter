use anyhow::{Result, anyhow};

use super::{ClassicalKind, option_start, parse_kind, split_top_level_commas};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassicalRule<'a> {
    pub kind: ClassicalKind,
    pub payload: Option<&'a str>,
    pub no_resolve: bool,
    pub src: bool,
}

impl<'a> ClassicalRule<'a> {
    pub fn parse(rule: &'a str) -> Result<Self> {
        let fields = split_top_level_commas(rule);
        let kind = fields
            .first()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .and_then(parse_kind)
            .ok_or_else(|| anyhow!("unsupported classical rule type"))?;

        let payload = if kind == ClassicalKind::Match {
            None
        } else {
            Some(
                fields
                    .get(1)
                    .map(|value| value.trim())
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| anyhow!("empty classical rule payload"))?,
            )
        };
        let option_start = option_start(&fields);
        let no_resolve = fields
            .iter()
            .skip(option_start)
            .any(|part| part.trim().eq_ignore_ascii_case("no-resolve"));
        let src = fields
            .iter()
            .skip(option_start)
            .any(|part| part.trim().eq_ignore_ascii_case("src"));

        Ok(Self {
            kind,
            payload,
            no_resolve,
            src,
        })
    }
}
