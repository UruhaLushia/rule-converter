use napi::bindgen_prelude::{Buffer, Either, Result, Uint8Array};

type BehaviorOption = String;
type InputFormatOption = String;
type OutputFormatOption = String;
type RuleTargetOption = String;
type OutputBehavior = String;
use napi_derive::napi;
use rule_converter::{
    BehaviorMode, InputBehaviorMode, InputFormat, OutputFormat, RuleTarget, convert_files,
    convert_files_to_path_streaming, convert_payload, default_output_behavior,
    write_outputs_as_owned, write_outputs_as_to_memory_owned,
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
    #[napi(ts_type = "'auto' | 'domain' | 'ip' | 'classical'")]
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
pub struct ConvertStringOutput {
    #[napi(ts_type = "'domain' | 'ip'")]
    pub behavior: OutputBehavior,
    pub count: u32,
    pub text: String,
}

#[napi(object)]
pub struct ConvertBufferOutput {
    #[napi(ts_type = "'domain' | 'ip'")]
    pub behavior: OutputBehavior,
    pub count: u32,
    #[napi(ts_type = "Uint8Array")]
    pub buffer: Buffer,
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
pub struct ConvertStringResult {
    pub outputs: Vec<ConvertStringOutput>,
    pub skipped: Vec<SkippedRule>,
}

#[napi(object)]
pub struct ConvertBufferResult {
    pub outputs: Vec<ConvertBufferOutput>,
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
    convert_result_to_mrs(result)
}

#[napi]
pub fn convert_payload_string_to_mrs(
    payload: String,
    options: Option<ConvertOptions>,
) -> Result<ConvertResult> {
    let options = parse_options(options)?;
    ensure_mrs_behavior(options.output_behavior)?;
    let result = convert_payload(payload.as_bytes(), options).map_err(to_napi_error)?;
    convert_result_to_mrs(result)
}

#[napi]
pub fn convert_payload_to_buffer(
    payload: Uint8Array,
    options: Option<ConvertOptions>,
) -> Result<ConvertBufferResult> {
    let options = parse_options(options)?;
    let output_target = options.output_target;
    let output_format = options.output_format;
    let result = convert_payload(payload.as_ref(), options).map_err(to_napi_error)?;
    convert_result_to_buffer(result, output_target, output_format)
}

#[napi]
pub fn convert_payload_string_to_buffer(
    payload: String,
    options: Option<ConvertOptions>,
) -> Result<ConvertBufferResult> {
    let options = parse_options(options)?;
    let output_target = options.output_target;
    let output_format = options.output_format;
    let result = convert_payload(payload.as_bytes(), options).map_err(to_napi_error)?;
    convert_result_to_buffer(result, output_target, output_format)
}

#[napi]
pub fn convert_payload_to_string(
    payload: Uint8Array,
    options: Option<ConvertOptions>,
) -> Result<ConvertStringResult> {
    let options = parse_options(options)?;
    ensure_text_output(options.output_format)?;
    let output_target = options.output_target;
    let output_format = options.output_format;
    let result = convert_payload(payload.as_ref(), options).map_err(to_napi_error)?;
    convert_result_to_string(result, output_target, output_format)
}

#[napi]
pub fn convert_payload_string_to_string(
    payload: String,
    options: Option<ConvertOptions>,
) -> Result<ConvertStringResult> {
    let options = parse_options(options)?;
    ensure_text_output(options.output_format)?;
    let output_target = options.output_target;
    let output_format = options.output_format;
    let result = convert_payload(payload.as_bytes(), options).map_err(to_napi_error)?;
    convert_result_to_string(result, output_target, output_format)
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
pub fn convert_file_to_buffer(
    #[napi(ts_arg_type = "string | string[]")] input: FileInput,
    options: Option<ConvertOptions>,
) -> Result<ConvertBufferResult> {
    let options = parse_options(options)?;
    let output_target = options.output_target;
    let output_format = options.output_format;
    let input = normalize_file_input(input)?;
    let result = convert_files(&input, options).map_err(to_napi_error)?;
    convert_result_to_buffer(result, output_target, output_format)
}

#[napi]
pub fn convert_file_to_string(
    #[napi(ts_arg_type = "string | string[]")] input: FileInput,
    options: Option<ConvertOptions>,
) -> Result<ConvertStringResult> {
    let options = parse_options(options)?;
    ensure_text_output(options.output_format)?;
    let output_target = options.output_target;
    let output_format = options.output_format;
    let input = normalize_file_input(input)?;
    let result = convert_files(&input, options).map_err(to_napi_error)?;
    convert_result_to_string(result, output_target, output_format)
}

#[napi]
pub fn convert_file_to_path(
    #[napi(ts_arg_type = "string | string[]")] input: FileInput,
    output: String,
    options: Option<ConvertOptions>,
) -> Result<WriteResult> {
    let options = parse_options(options)?;
    let input = normalize_file_input(input)?;
    let (files, skipped) = if let Some(result) =
        convert_files_to_path_streaming(&input, &output, options).map_err(to_napi_error)?
    {
        result
    } else {
        let result = convert_files(&input, options).map_err(to_napi_error)?;
        write_outputs_as_owned(
            result,
            &output,
            options.output_target,
            options.output_format,
        )
        .map_err(to_napi_error)?
    };
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
        None => default_output_behavior(output_target, output_format),
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

fn ensure_text_output(format: OutputFormat) -> Result<()> {
    if matches!(format, OutputFormat::Mrs | OutputFormat::Srs) {
        return Err(napi::Error::from_reason(
            "string output only supports text formats; use convertPayloadToBuffer or convertFileToBuffer for binary output",
        ));
    }
    Ok(())
}

fn convert_result_to_buffer(
    result: rule_converter::ConvertResult,
    target: RuleTarget,
    format: OutputFormat,
) -> Result<ConvertBufferResult> {
    let (outputs, skipped) =
        write_outputs_as_to_memory_owned(result, target, format).map_err(to_napi_error)?;
    let outputs = outputs
        .into_iter()
        .map(|output| ConvertBufferOutput {
            behavior: output.behavior.as_str().to_string(),
            count: output.count as u32,
            buffer: Buffer::from(output.bytes),
        })
        .collect();

    Ok(ConvertBufferResult {
        outputs,
        skipped: map_skipped(skipped),
    })
}

fn convert_result_to_mrs(result: rule_converter::ConvertResult) -> Result<ConvertResult> {
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

fn convert_result_to_string(
    result: rule_converter::ConvertResult,
    target: RuleTarget,
    format: OutputFormat,
) -> Result<ConvertStringResult> {
    let (outputs, skipped) =
        write_outputs_as_to_memory_owned(result, target, format).map_err(to_napi_error)?;
    let outputs = outputs
        .into_iter()
        .map(|output| {
            let text = String::from_utf8(output.bytes).map_err(|err| {
                napi::Error::from_reason(format!("output is not valid UTF-8: {err}"))
            })?;
            Ok(ConvertStringOutput {
                behavior: output.behavior.as_str().to_string(),
                count: output.count as u32,
                text,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(ConvertStringResult {
        outputs,
        skipped: map_skipped(skipped),
    })
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
