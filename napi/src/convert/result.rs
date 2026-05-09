use std::collections::HashMap;

use napi::bindgen_prelude::{Buffer, Result};

use crate::types::{AnyBufferResult, AnyOutputInfo, AnyStringResult, SkippedRule};

pub(super) fn any_buffer_result_to_string(result: AnyBufferResult) -> Result<AnyStringResult> {
    let mut outputs = HashMap::with_capacity(result.outputs.len());
    for (name, buffer) in result.outputs {
        let text = String::from_utf8(buffer.to_vec()).map_err(|err| {
            napi::Error::from_reason(format!("output {name} is not valid UTF-8: {err}"))
        })?;
        outputs.insert(name, text);
    }
    Ok(AnyStringResult {
        kind: result.kind,
        outputs,
        info: result.info,
        skipped: result.skipped,
    })
}

pub(super) fn any_rules_result(
    outputs: Vec<rule_converter::MemoryOutput>,
    skipped: Vec<rule_converter::SkippedRule>,
) -> AnyBufferResult {
    let mut values = HashMap::with_capacity(outputs.len());
    let mut info = HashMap::with_capacity(outputs.len());
    for output in outputs {
        let name = output.behavior.as_str().to_string();
        info.insert(
            name.clone(),
            AnyOutputInfo {
                behavior: Some(output.behavior.as_str().to_string()),
                format: output.format.as_str().to_string(),
                count: output.count as u32,
            },
        );
        values.insert(name, Buffer::from(output.bytes));
    }
    AnyBufferResult {
        kind: "rules".to_string(),
        outputs: values,
        info,
        skipped: map_skipped(skipped),
    }
}

pub(super) fn any_db_rules_result(outputs: Vec<rule_converter::DbMemoryOutput>) -> AnyBufferResult {
    let mut values = HashMap::with_capacity(outputs.len());
    let mut info = HashMap::with_capacity(outputs.len());
    for output in outputs {
        let name = output.name;
        info.insert(
            name.clone(),
            AnyOutputInfo {
                behavior: Some(output.behavior.as_str().to_string()),
                format: output.format.as_str().to_string(),
                count: output.count as u32,
            },
        );
        values.insert(name, Buffer::from(output.bytes));
    }
    AnyBufferResult {
        kind: "rules".to_string(),
        outputs: values,
        info,
        skipped: Vec::new(),
    }
}

pub(super) fn any_db_result(output: rule_converter::DbBytesOutput) -> AnyBufferResult {
    let format = output.format.as_str().to_string();
    let count = output.count as u32;
    AnyBufferResult {
        kind: "db".to_string(),
        outputs: HashMap::from([("db".to_string(), Buffer::from(output.bytes))]),
        info: HashMap::from([(
            "db".to_string(),
            AnyOutputInfo {
                behavior: None,
                format,
                count,
            },
        )]),
        skipped: Vec::new(),
    }
}

pub(super) fn any_db_string_result(output: rule_converter::DbStringOutput) -> AnyStringResult {
    let name = output.name;
    let format = output.format.as_str().to_string();
    let behavior = output.behavior.as_str().to_string();
    let count = output.count as u32;
    AnyStringResult {
        kind: "rules".to_string(),
        outputs: HashMap::from([(name.clone(), output.text)]),
        info: HashMap::from([(
            name,
            AnyOutputInfo {
                behavior: Some(behavior),
                format,
                count,
            },
        )]),
        skipped: Vec::new(),
    }
}

fn map_skipped(skipped: Vec<rule_converter::SkippedRule>) -> Vec<SkippedRule> {
    skipped
        .into_iter()
        .map(|item| SkippedRule {
            rule: item.rule,
            reason: item.reason,
        })
        .collect()
}
