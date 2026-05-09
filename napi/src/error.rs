pub(crate) fn to_napi_error(err: anyhow::Error) -> napi::Error {
    napi::Error::from_reason(err.to_string())
}
