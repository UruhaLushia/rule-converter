use std::io::{BufRead, Cursor};

use anyhow::{Result, bail};
use yaml_rust2::parser::{Event, Parser};

use super::chars::BufReadChars;
use super::extractor::RuleSetExtractor;

pub fn parse_ruleset(raw: &[u8]) -> Result<Vec<String>> {
    let mut rules = Vec::new();
    for_each_ruleset_rule(Cursor::new(raw), |rule| {
        rules.push(rule.to_string());
        Ok(())
    })?;
    Ok(rules)
}

pub fn for_each_ruleset_rule<R: BufRead>(
    reader: R,
    f: impl FnMut(&str) -> Result<()>,
) -> Result<usize> {
    let mut extractor = RuleSetExtractor::new(f);
    let mut chars = BufReadChars::new(reader);
    let mut parser = Parser::new(&mut chars);

    loop {
        let (event, _mark) = parser
            .next_token()
            .map_err(|err| anyhow::anyhow!("failed to parse Egern ruleset YAML: {err}"))?;
        let done = event == Event::StreamEnd;
        extractor.on_event(event)?;
        if done {
            break;
        }
    }
    extractor.finish()?;
    drop(parser);

    if let Some(err) = chars.error.take() {
        return Err(err);
    }

    if extractor.count == 0 {
        bail!("Egern ruleset must contain supported set fields");
    }
    Ok(extractor.count)
}
