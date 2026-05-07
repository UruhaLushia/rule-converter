use napi::bindgen_prelude::{Either, Result, Uint8Array};

type BehaviorOption = String;
type InputFormatOption = String;
type OutputFormatOption = String;
type RuleTargetOption = String;
type OutputBehavior = String;
use napi_derive::napi;
use rule_converter::{
    BehaviorMode, InputBehaviorMode, InputFormat, OutputFormat, RuleTarget, convert_files,
    convert_payload, write_outputs_as_owned,
};

type FileInput = Either<String, Vec<String>>;

#[napi(object)]
pub struct ConvertOptions {
    #[napi(ts_type = "'mihomo' | 'general' | 'egern' | 'sing-box'")]
    pub input_target: Option<RuleTargetOption>,
    #[napi(ts_type = "'yaml' | 'mrs' | 'text' | 'json' | 'srs'")]
    pub input_format: Option<InputFormatOption>,
    #[napi(ts_type = "'auto' | 'domain' | 'ip' | 'classical'")]
    pub input_behavior: Option<BehaviorOption>,
    #[napi(ts_type = "'mihomo' | 'general' | 'egern' | 'sing-box'")]
    pub output_target: Option<RuleTargetOption>,
    #[napi(
        ts_type = "'mrs' | 'text' | 'yaml' | 'json' | 'srs' | 'domainset' | 'ruleset' | 'ipset'"
    )]
    pub output_format: Option<OutputFormatOption>,
    #[napi(ts_type = "'domain' | 'ip' | 'classical'")]
    pub output_behavior: Option<BehaviorOption>,
}

#[napi(object)]
pub struct ConvertOutput {
    #[napi(ts_type = "'domain' | 'ip'")]
    pub behavior: OutputBehavior,
    pub count: u32,
    pub bytes: Uint8Array,
}

#[napi(object)]
pub struct WrittenOutput {
    #[napi(ts_type = "'domain' | 'ip'")]
    pub behavior: OutputBehavior,
    pub count: u32,
    pub path: String,
}

#[napi(object)]
pub struct SkippedRule {
    pub rule: String,
    pub reason: String,
}

#[napi(object)]
pub struct ConvertResult {
    pub outputs: Vec<ConvertOutput>,
    pub skipped: Vec<SkippedRule>,
}

#[napi(object)]
pub struct WriteResult {
    pub outputs: Vec<WrittenOutput>,
    pub skipped: Vec<SkippedRule>,
}

#[napi]
pub fn convert_payload_to_mrs(
    payload: Uint8Array,
    options: Option<ConvertOptions>,
) -> Result<ConvertResult> {
    let options = parse_options(options)?;
    ensure_mrs_behavior(options.output_behavior)?;
    let result = convert_payload(payload.as_ref(), options).map_err(to_napi_error)?;

    let outputs = result
        .outputs
        .iter()
        .map(|output| {
            let bytes = output.to_mrs_bytes().map_err(to_napi_error)?;
            Ok(ConvertOutput {
                behavior: output.behavior().as_str().to_string(),
                count: output.count() as u32,
                bytes: Uint8Array::from(bytes),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ConvertResult {
        outputs,
        skipped: map_skipped(result.skipped),
    })
}

#[napi]
pub fn convert_payload_string_to_mrs(
    payload: String,
    options: Option<ConvertOptions>,
) -> Result<ConvertResult> {
    convert_payload_to_mrs(Uint8Array::from(payload.into_bytes()), options)
}

#[napi]
pub fn convert_file_to_mrs(
    #[napi(ts_arg_type = "string | string[]")] input: FileInput,
    options: Option<ConvertOptions>,
) -> Result<ConvertResult> {
    let options = parse_options(options)?;
    ensure_mrs_behavior(options.output_behavior)?;
    let input = normalize_file_input(input)?;
    let result = convert_files(&input, options).map_err(to_napi_error)?;

    let outputs = result
        .outputs
        .iter()
        .map(|output| {
            let bytes = output.to_mrs_bytes().map_err(to_napi_error)?;
            Ok(ConvertOutput {
                behavior: output.behavior().as_str().to_string(),
                count: output.count() as u32,
                bytes: Uint8Array::from(bytes),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ConvertResult {
        outputs,
        skipped: map_skipped(result.skipped),
    })
}

#[napi]
pub fn convert_file_to_path(
    #[napi(ts_arg_type = "string | string[]")] input: FileInput,
    output: String,
    options: Option<ConvertOptions>,
) -> Result<WriteResult> {
    let options = parse_options(options)?;
    let input = normalize_file_input(input)?;
    let result = convert_files(&input, options).map_err(to_napi_error)?;
    let (files, skipped) = write_outputs_as_owned(
        result,
        &output,
        options.output_target,
        options.output_format,
    )
    .map_err(to_napi_error)?;
    let outputs = files
        .into_iter()
        .map(|file| WrittenOutput {
            behavior: file.behavior.as_str().to_string(),
            count: file.count as u32,
            path: file.path.display().to_string(),
        })
        .collect();

    Ok(WriteResult {
        outputs,
        skipped: map_skipped(skipped),
    })
}

fn normalize_file_input(input: FileInput) -> Result<Vec<String>> {
    let paths = match input {
        Either::A(path) => vec![path],
        Either::B(paths) => paths,
    };
    if paths.is_empty() {
        return Err(napi::Error::from_reason("input list must not be empty"));
    }
    Ok(paths)
}

fn parse_options(options: Option<ConvertOptions>) -> Result<rule_converter::ConvertOptions> {
    let Some(options) = options else {
        return Ok(rule_converter::ConvertOptions::default());
    };

    let input_target = match options.input_target.as_deref() {
        Some(value) => Some(RuleTarget::parse_arg(value).map_err(to_napi_error)?),
        None => None,
    };
    let input_format = match options.input_format.as_deref() {
        Some(value) => Some(InputFormat::parse_arg(value).map_err(to_napi_error)?),
        None => None,
    };
    let input_behavior = match options.input_behavior.as_deref() {
        Some(value) => InputBehaviorMode::parse_arg(value).map_err(to_napi_error)?,
        None => InputBehaviorMode::Auto,
    };
    let output_target = match options.output_target.as_deref() {
        Some(value) => RuleTarget::parse_arg(value).map_err(to_napi_error)?,
        None => RuleTarget::Mihomo,
    };
    let output_format = match options.output_format.as_deref() {
        Some(value) => OutputFormat::parse_arg(value).map_err(to_napi_error)?,
        None => OutputFormat::Mrs,
    };
    let output_behavior = match options.output_behavior.as_deref() {
        Some(value) => BehaviorMode::parse_arg(value).map_err(to_napi_error)?,
        None => BehaviorMode::Domain,
    };

    Ok(rule_converter::ConvertOptions {
        input_target,
        input_format,
        input_behavior,
        output_target,
        output_format,
        output_behavior,
    })
}

fn ensure_mrs_behavior(behavior: BehaviorMode) -> Result<()> {
    if behavior == BehaviorMode::Classical {
        return Err(napi::Error::from_reason(
            "MRS output does not support classical behavior; use domain or ip",
        ));
    }
    Ok(())
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

fn to_napi_error(err: anyhow::Error) -> napi::Error {
    napi::Error::from_reason(err.to_string())
}
