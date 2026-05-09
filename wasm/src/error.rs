use wasm_bindgen::prelude::*;

pub(crate) fn to_js_error(err: impl std::fmt::Display) -> JsValue {
    js_sys::Error::new(&err.to_string()).into()
}
