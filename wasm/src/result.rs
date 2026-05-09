use std::collections::BTreeMap;

use js_sys::{Object, Reflect, Uint8Array};
use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::error::to_js_error;
use crate::types::{AnyOutputInfo, AnyStringResult, DbRuleOutput, SkippedRule};

pub(crate) fn any_db_rules_to_js(
    outputs: Vec<rule_converter::DbMemoryOutput>,
) -> Result<JsValue, JsValue> {
    let mut values = BTreeMap::new();
    let mut info = BTreeMap::new();
    for output in outputs {
        let name = output.name;
        info.insert(
            name.clone(),
            AnyOutputInfo {
                behavior: Some(output.behavior.as_str().to_string()),
                format: output.format.as_str().to_string(),
                count: output.count,
            },
        );
        values.insert(name, output.bytes);
    }
    any_parts_to_js("rules", values, info, Vec::new())
}

pub(crate) fn any_rules_to_js(
    outputs: Vec<DbRuleOutput>,
    skipped: Vec<rule_converter::SkippedRule>,
) -> Result<JsValue, JsValue> {
    let mut values = BTreeMap::new();
    let mut info = BTreeMap::new();
    for output in outputs {
        let name = output.name;
        info.insert(
            name.clone(),
            AnyOutputInfo {
                behavior: Some(output.behavior),
                format: output.format,
                count: output.count,
            },
        );
        values.insert(name, output.bytes);
    }
    any_parts_to_js("rules", values, info, skipped)
}

pub(crate) fn any_db_to_js(output: rule_converter::DbBytesOutput) -> Result<JsValue, JsValue> {
    any_parts_to_js(
        "db",
        BTreeMap::from([("db".to_string(), output.bytes)]),
        BTreeMap::from([(
            "db".to_string(),
            AnyOutputInfo {
                behavior: None,
                format: output.format.as_str().to_string(),
                count: output.count,
            },
        )]),
        Vec::new(),
    )
}

pub(crate) fn any_db_string_to_js(
    output: rule_converter::DbStringOutput,
) -> Result<JsValue, JsValue> {
    let name = output.name;
    any_to_value(&AnyStringResult {
        kind: "rules".to_string(),
        outputs: BTreeMap::from([(name.clone(), output.text)]),
        info: BTreeMap::from([(
            name,
            AnyOutputInfo {
                behavior: Some(output.behavior.as_str().to_string()),
                format: output.format.as_str().to_string(),
                count: output.count,
            },
        )]),
        skipped: Vec::new(),
    })
}

pub(crate) fn any_parts_to_js(
    kind: &str,
    outputs: BTreeMap<String, Vec<u8>>,
    info: BTreeMap<String, AnyOutputInfo>,
    skipped: Vec<rule_converter::SkippedRule>,
) -> Result<JsValue, JsValue> {
    let result = Object::new();
    set_prop(&result, "kind", &JsValue::from_str(kind))?;

    let output_object = Object::new();
    for (name, bytes) in outputs {
        let bytes_value = Uint8Array::new_with_length(bytes.len() as u32);
        bytes_value.copy_from(&bytes);
        set_prop(&output_object, &name, bytes_value.as_ref())?;
    }
    set_prop(&result, "outputs", output_object.as_ref())?;

    set_prop(&result, "info", &any_to_value(&info)?)?;
    set_prop(
        &result,
        "skipped",
        &any_to_value(
            &skipped
                .into_iter()
                .map(|item| SkippedRule {
                    rule: item.rule,
                    reason: item.reason,
                })
                .collect::<Vec<_>>(),
        )?,
    )?;
    Ok(result.into())
}
pub(crate) fn any_js_to_string(value: JsValue) -> Result<JsValue, JsValue> {
    let kind = Reflect::get(&value, &JsValue::from_str("kind"))?
        .as_string()
        .ok_or_else(|| to_js_error("missing result kind"))?;
    let outputs_value = Reflect::get(&value, &JsValue::from_str("outputs"))?;
    let info: BTreeMap<String, AnyOutputInfo> =
        serde_wasm_bindgen::from_value(Reflect::get(&value, &JsValue::from_str("info"))?)
            .map_err(to_js_error)?;
    let skipped: Vec<SkippedRule> =
        serde_wasm_bindgen::from_value(Reflect::get(&value, &JsValue::from_str("skipped"))?)
            .map_err(to_js_error)?;

    let output_object = Object::from(outputs_value);
    let names = Object::keys(&output_object);
    let mut outputs = BTreeMap::new();
    for index in 0..names.length() {
        let name = names
            .get(index)
            .as_string()
            .ok_or_else(|| to_js_error("output key is not a string"))?;
        let bytes =
            Uint8Array::new(&Reflect::get(&output_object, &JsValue::from_str(&name))?).to_vec();
        let text = String::from_utf8(bytes)
            .map_err(|err| to_js_error(format!("output {name} is not valid UTF-8: {err}")))?;
        outputs.insert(name, text);
    }
    any_to_value(&AnyStringResult {
        kind,
        outputs,
        info,
        skipped,
    })
}

pub(crate) fn set_prop(target: &Object, key: &str, value: &JsValue) -> Result<(), JsValue> {
    Reflect::set(target, &JsValue::from_str(key), value).map(|_| ())
}
pub(crate) fn any_to_value<T: Serialize + ?Sized>(value: &T) -> Result<JsValue, JsValue> {
    value
        .serialize(
            &serde_wasm_bindgen::Serializer::new()
                .serialize_maps_as_objects(true)
                .serialize_missing_as_null(true),
        )
        .map_err(to_js_error)
}
