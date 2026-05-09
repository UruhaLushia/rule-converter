use std::collections::HashMap;

use napi::bindgen_prelude::{Buffer, Result, Uint8Array};
use napi_derive::napi;
use rule_converter::{
    BehaviorMode, ConvertOptions as CoreConvertOptions, FileInput as CoreFileInput,
    InputBehaviorMode, InputFormat, MmdbFormat, OutputFormat, RuleSetOutput, RuleTarget,
    build_asn_mmdb_to_memory, build_geoip_mmdb_to_memory, convert_asn_mmdb_file_to_memory_filtered,
    convert_asn_mmdb_to_memory_filtered, convert_file_inputs,
    convert_geoip_mmdb_file_to_memory_filtered, convert_geoip_mmdb_to_memory_filtered,
    convert_payload, default_output_behavior, export_asn_mmdb_file_to_memory,
    export_asn_mmdb_to_memory, export_geoip_mmdb_file_to_memory, export_geoip_mmdb_to_memory,
    list_asn_mmdb_asns, list_asn_mmdb_asns_from_bytes, list_geoip_mmdb_countries,
    list_geoip_mmdb_countries_from_bytes, write_outputs_as_to_memory_owned,
};

type AnyFormatOption = String;
type AnyTargetOption = String;
type BehaviorOption = String;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AnyTarget {
    Rule(Option<RuleTarget>),
    Geoip,
    Asn,
}

#[napi(object)]
pub struct AnyConvertOptions {
    #[napi(ts_type = "'mihomo' | 'general' | 'egern' | 'sing-box' | 'geoip' | 'asn'")]
    pub input_target: Option<AnyTargetOption>,
    #[napi(
        ts_type = "'yaml' | 'mrs' | 'text' | 'json' | 'srs' | 'domainset' | 'ruleset' | 'ipset' | 'mmdb' | 'sing-db' | 'metadb'"
    )]
    pub input_format: Option<AnyFormatOption>,
    #[napi(ts_type = "'auto' | 'domain' | 'ip' | 'classical'")]
    pub input_behavior: Option<BehaviorOption>,
    #[napi(ts_type = "'mihomo' | 'general' | 'egern' | 'sing-box' | 'geoip' | 'asn'")]
    pub output_target: Option<AnyTargetOption>,
    #[napi(
        ts_type = "'mrs' | 'text' | 'yaml' | 'json' | 'srs' | 'domainset' | 'ruleset' | 'ipset' | 'mmdb' | 'sing-db' | 'metadb'"
    )]
    pub output_format: Option<AnyFormatOption>,
    #[napi(ts_type = "'auto' | 'domain' | 'ip' | 'classical'")]
    pub output_behavior: Option<BehaviorOption>,
    pub countries: Option<Vec<String>>,
    pub asns: Option<Vec<u32>>,
    pub split: Option<bool>,
    pub country: Option<String>,
    pub asn: Option<u32>,
}

#[napi(object)]
pub struct AnyOutputInfo {
    pub behavior: Option<String>,
    pub format: String,
    pub count: u32,
}

#[napi(object)]
pub struct SkippedRule {
    pub rule: String,
    pub reason: String,
}

#[napi(object)]
pub struct AnyBufferResult {
    #[napi(ts_type = "'rules' | 'db'")]
    pub kind: String,
    #[napi(ts_type = "Record<string, Uint8Array>")]
    pub outputs: HashMap<String, Buffer>,
    pub info: HashMap<String, AnyOutputInfo>,
    pub skipped: Vec<SkippedRule>,
}

#[napi(object)]
pub struct AnyStringResult {
    #[napi(ts_type = "'rules' | 'db'")]
    pub kind: String,
    pub outputs: HashMap<String, String>,
    pub info: HashMap<String, AnyOutputInfo>,
    pub skipped: Vec<SkippedRule>,
}

impl Default for AnyConvertOptions {
    fn default() -> Self {
        Self {
            input_target: None,
            input_format: None,
            input_behavior: None,
            output_target: None,
            output_format: None,
            output_behavior: None,
            countries: None,
            asns: None,
            split: None,
            country: None,
            asn: None,
        }
    }
}

#[napi]
pub fn buf_to_buf(
    input: Uint8Array,
    options: Option<AnyConvertOptions>,
) -> Result<AnyBufferResult> {
    convert_any_payload_to_buffer(input.as_ref(), options)
}

#[napi]
pub fn str_to_buf(input: String, options: Option<AnyConvertOptions>) -> Result<AnyBufferResult> {
    convert_any_payload_to_buffer(input.as_bytes(), options)
}

#[napi]
pub fn file_to_buf(input: String, options: Option<AnyConvertOptions>) -> Result<AnyBufferResult> {
    convert_any_file_to_buffer(input, options)
}

#[napi]
pub fn buf_to_str(
    input: Uint8Array,
    options: Option<AnyConvertOptions>,
) -> Result<AnyStringResult> {
    any_buffer_result_to_string(buf_to_buf(input, options)?)
}

#[napi]
pub fn str_to_str(input: String, options: Option<AnyConvertOptions>) -> Result<AnyStringResult> {
    any_buffer_result_to_string(str_to_buf(input, options)?)
}

#[napi]
pub fn file_to_str(input: String, options: Option<AnyConvertOptions>) -> Result<AnyStringResult> {
    any_buffer_result_to_string(file_to_buf(input, options)?)
}

#[napi]
pub fn list_geoip_countries(input: String) -> Result<Vec<String>> {
    list_geoip_mmdb_countries(input).map_err(to_napi_error)
}

#[napi]
pub fn list_geoip_countries_from_buffer(input: Uint8Array) -> Result<Vec<String>> {
    list_geoip_mmdb_countries_from_bytes(input.as_ref()).map_err(to_napi_error)
}

#[napi]
pub fn list_asn_numbers(input: String) -> Result<Vec<u32>> {
    list_asn_mmdb_asns(input).map_err(to_napi_error)
}

#[napi]
pub fn list_asn_numbers_from_buffer(input: Uint8Array) -> Result<Vec<u32>> {
    list_asn_mmdb_asns_from_bytes(input.as_ref()).map_err(to_napi_error)
}

fn convert_any_file_to_buffer(
    input: String,
    options: Option<AnyConvertOptions>,
) -> Result<AnyBufferResult> {
    let options = options.unwrap_or_default();
    match parse_any_input_target(options.input_target.as_deref())? {
        AnyTarget::Rule(input_target) => {
            convert_rule_file_any_to_buffer(input, input_target, options)
        }
        AnyTarget::Geoip => convert_geoip_file_any_to_buffer(input, options),
        AnyTarget::Asn => convert_asn_file_any_to_buffer(input, options),
    }
}

fn convert_any_payload_to_buffer(
    payload: &[u8],
    options: Option<AnyConvertOptions>,
) -> Result<AnyBufferResult> {
    convert_any_payload_to_buffer_with_options(payload, options.unwrap_or_default())
}

fn convert_any_payload_to_buffer_with_options(
    payload: &[u8],
    options: AnyConvertOptions,
) -> Result<AnyBufferResult> {
    match parse_any_input_target(options.input_target.as_deref())? {
        AnyTarget::Rule(input_target) => {
            convert_rule_payload_any_to_buffer(payload, input_target, options)
        }
        AnyTarget::Geoip => convert_geoip_payload_any_to_buffer(payload, options),
        AnyTarget::Asn => convert_asn_payload_any_to_buffer(payload, options),
    }
}

fn convert_rule_payload_any_to_buffer(
    payload: &[u8],
    input_target: Option<RuleTarget>,
    options: AnyConvertOptions,
) -> Result<AnyBufferResult> {
    match parse_any_output_target(options.output_target.as_deref())? {
        AnyTarget::Rule(output_target) => {
            let output_target = output_target.unwrap_or(RuleTarget::Mihomo);
            let output_format = parse_rule_output_format(options.output_format.as_deref())?
                .unwrap_or(OutputFormat::Mrs);
            let output_behavior = parse_output_behavior(options.output_behavior.as_deref())?
                .unwrap_or_else(|| default_output_behavior(output_target, output_format));
            let input_format = parse_rule_input_format(options.input_format.as_deref())?;
            let input_behavior = parse_input_behavior(options.input_behavior)?;
            let result = convert_payload(
                payload,
                CoreConvertOptions {
                    input_target,
                    input_format,
                    input_behavior,
                    output_target,
                    output_format,
                    output_behavior,
                },
            )
            .map_err(to_napi_error)?;
            let (outputs, skipped) =
                write_outputs_as_to_memory_owned(result, output_target, output_format)
                    .map_err(to_napi_error)?;
            Ok(any_rules_result(outputs, skipped))
        }
        AnyTarget::Geoip => {
            let country = options
                .country
                .ok_or_else(|| napi::Error::from_reason("geoip DB output needs country"))?;
            let output_format = parse_db_format_value(options.output_format.as_deref())?
                .unwrap_or(MmdbFormat::Mmdb);
            let rule_set = collect_ip_rule_set_from_payload(
                payload,
                input_target.map(|target| target.as_str().to_string()),
                options.input_format,
                options.input_behavior,
            )?;
            let output = build_geoip_mmdb_to_memory([(country, rule_set)], output_format)
                .map_err(to_napi_error)?;
            Ok(any_db_result(output))
        }
        AnyTarget::Asn => {
            let asn = options
                .asn
                .ok_or_else(|| napi::Error::from_reason("asn DB output needs asn"))?;
            validate_asn_output_format(options.output_format.as_deref())?;
            let rule_set = collect_ip_rule_set_from_payload(
                payload,
                input_target.map(|target| target.as_str().to_string()),
                options.input_format,
                options.input_behavior,
            )?;
            let output = build_asn_mmdb_to_memory([(asn, rule_set)]).map_err(to_napi_error)?;
            Ok(any_db_result(output))
        }
    }
}

fn convert_rule_file_any_to_buffer(
    input: String,
    input_target: Option<RuleTarget>,
    options: AnyConvertOptions,
) -> Result<AnyBufferResult> {
    match parse_any_output_target(options.output_target.as_deref())? {
        AnyTarget::Rule(output_target) => {
            let output_target = output_target.unwrap_or(RuleTarget::Mihomo);
            let output_format = parse_rule_output_format(options.output_format.as_deref())?
                .unwrap_or(OutputFormat::Mrs);
            let output_behavior = parse_output_behavior(options.output_behavior.as_deref())?
                .unwrap_or_else(|| default_output_behavior(output_target, output_format));
            let input_format = parse_rule_input_format(options.input_format.as_deref())?;
            let input_behavior = parse_input_behavior(options.input_behavior)?;
            let result = convert_file_inputs(
                [CoreFileInput {
                    path: input.into(),
                    target: input_target,
                    format: input_format,
                    behavior: input_behavior,
                }],
                CoreConvertOptions {
                    input_target,
                    input_format,
                    input_behavior,
                    output_target,
                    output_format,
                    output_behavior,
                },
            )
            .map_err(to_napi_error)?;
            let (outputs, skipped) =
                write_outputs_as_to_memory_owned(result, output_target, output_format)
                    .map_err(to_napi_error)?;
            Ok(any_rules_result(outputs, skipped))
        }
        AnyTarget::Geoip => {
            let country = options
                .country
                .ok_or_else(|| napi::Error::from_reason("geoip DB output needs country"))?;
            let output_format = parse_db_format_value(options.output_format.as_deref())?
                .unwrap_or(MmdbFormat::Mmdb);
            let rule_set = collect_ip_rule_set_from_file(
                input,
                input_target.map(|target| target.as_str().to_string()),
                options.input_format,
                options.input_behavior,
            )?;
            let output = build_geoip_mmdb_to_memory([(country, rule_set)], output_format)
                .map_err(to_napi_error)?;
            Ok(any_db_result(output))
        }
        AnyTarget::Asn => {
            let asn = options
                .asn
                .ok_or_else(|| napi::Error::from_reason("asn DB output needs asn"))?;
            validate_asn_output_format(options.output_format.as_deref())?;
            let rule_set = collect_ip_rule_set_from_file(
                input,
                input_target.map(|target| target.as_str().to_string()),
                options.input_format,
                options.input_behavior,
            )?;
            let output = build_asn_mmdb_to_memory([(asn, rule_set)]).map_err(to_napi_error)?;
            Ok(any_db_result(output))
        }
    }
}

fn convert_geoip_file_any_to_buffer(
    input: String,
    options: AnyConvertOptions,
) -> Result<AnyBufferResult> {
    match parse_any_output_target(options.output_target.as_deref())? {
        AnyTarget::Rule(output_target) => {
            let output_target = output_target.unwrap_or(RuleTarget::General);
            let output_format = parse_rule_output_format(options.output_format.as_deref())?
                .unwrap_or(OutputFormat::IpSet);
            let output_behavior = parse_output_behavior(options.output_behavior.as_deref())?
                .unwrap_or_else(|| default_output_behavior(output_target, output_format));
            let countries = options.countries.unwrap_or_default();
            let split = options.split.unwrap_or(true);
            let outputs = export_geoip_mmdb_file_to_memory(
                input,
                &countries,
                split,
                output_target,
                output_format,
                output_behavior,
            )
            .map_err(to_napi_error)?;
            Ok(any_db_rules_result(outputs))
        }
        AnyTarget::Geoip => {
            let output_format = parse_db_format_value(options.output_format.as_deref())?
                .unwrap_or(MmdbFormat::Mmdb);
            let countries = options.countries.unwrap_or_default();
            let output =
                convert_geoip_mmdb_file_to_memory_filtered(input, &countries, output_format)
                    .map_err(to_napi_error)?;
            Ok(any_db_result(output))
        }
        AnyTarget::Asn => Err(napi::Error::from_reason(
            "cannot convert geoip DB to asn DB",
        )),
    }
}

fn convert_asn_file_any_to_buffer(
    input: String,
    options: AnyConvertOptions,
) -> Result<AnyBufferResult> {
    match parse_any_output_target(options.output_target.as_deref())? {
        AnyTarget::Rule(output_target) => {
            let output_target = output_target.unwrap_or(RuleTarget::General);
            let output_format = parse_rule_output_format(options.output_format.as_deref())?
                .unwrap_or(OutputFormat::IpSet);
            let output_behavior = parse_output_behavior(options.output_behavior.as_deref())?
                .unwrap_or_else(|| default_output_behavior(output_target, output_format));
            let asns = options.asns.unwrap_or_default();
            let split = options.split.unwrap_or(true);
            let outputs = export_asn_mmdb_file_to_memory(
                input,
                &asns,
                split,
                output_target,
                output_format,
                output_behavior,
            )
            .map_err(to_napi_error)?;
            Ok(any_db_rules_result(outputs))
        }
        AnyTarget::Asn => {
            validate_asn_output_format(options.output_format.as_deref())?;
            let asns = options.asns.unwrap_or_default();
            let output =
                convert_asn_mmdb_file_to_memory_filtered(input, &asns).map_err(to_napi_error)?;
            Ok(any_db_result(output))
        }
        AnyTarget::Geoip => Err(napi::Error::from_reason(
            "cannot convert asn DB to geoip DB",
        )),
    }
}

fn convert_geoip_payload_any_to_buffer(
    payload: &[u8],
    options: AnyConvertOptions,
) -> Result<AnyBufferResult> {
    match parse_any_output_target(options.output_target.as_deref())? {
        AnyTarget::Rule(output_target) => {
            let output_target = output_target.unwrap_or(RuleTarget::General);
            let output_format = parse_rule_output_format(options.output_format.as_deref())?
                .unwrap_or(OutputFormat::IpSet);
            let output_behavior = parse_output_behavior(options.output_behavior.as_deref())?
                .unwrap_or_else(|| default_output_behavior(output_target, output_format));
            let countries = options.countries.unwrap_or_default();
            let split = options.split.unwrap_or(true);
            let outputs = export_geoip_mmdb_to_memory(
                payload,
                &countries,
                split,
                output_target,
                output_format,
                output_behavior,
            )
            .map_err(to_napi_error)?;
            Ok(any_db_rules_result(outputs))
        }
        AnyTarget::Geoip => {
            let output_format = parse_db_format_value(options.output_format.as_deref())?
                .unwrap_or(MmdbFormat::Mmdb);
            let countries = options.countries.unwrap_or_default();
            let output = convert_geoip_mmdb_to_memory_filtered(payload, &countries, output_format)
                .map_err(to_napi_error)?;
            Ok(any_db_result(output))
        }
        AnyTarget::Asn => Err(napi::Error::from_reason(
            "cannot convert geoip DB to asn DB",
        )),
    }
}

fn convert_asn_payload_any_to_buffer(
    payload: &[u8],
    options: AnyConvertOptions,
) -> Result<AnyBufferResult> {
    match parse_any_output_target(options.output_target.as_deref())? {
        AnyTarget::Rule(output_target) => {
            let output_target = output_target.unwrap_or(RuleTarget::General);
            let output_format = parse_rule_output_format(options.output_format.as_deref())?
                .unwrap_or(OutputFormat::IpSet);
            let output_behavior = parse_output_behavior(options.output_behavior.as_deref())?
                .unwrap_or_else(|| default_output_behavior(output_target, output_format));
            let asns = options.asns.unwrap_or_default();
            let split = options.split.unwrap_or(true);
            let outputs = export_asn_mmdb_to_memory(
                payload,
                &asns,
                split,
                output_target,
                output_format,
                output_behavior,
            )
            .map_err(to_napi_error)?;
            Ok(any_db_rules_result(outputs))
        }
        AnyTarget::Asn => {
            validate_asn_output_format(options.output_format.as_deref())?;
            let asns = options.asns.unwrap_or_default();
            let output =
                convert_asn_mmdb_to_memory_filtered(payload, &asns).map_err(to_napi_error)?;
            Ok(any_db_result(output))
        }
        AnyTarget::Geoip => Err(napi::Error::from_reason(
            "cannot convert asn DB to geoip DB",
        )),
    }
}

fn collect_ip_rule_set_from_file(
    path: String,
    input_target: Option<String>,
    input_format: Option<String>,
    input_behavior: Option<String>,
) -> Result<RuleSetOutput> {
    let result = convert_file_inputs(
        [CoreFileInput {
            path: path.into(),
            target: parse_optional_rule_target(input_target)?,
            format: parse_optional_input_format(input_format)?,
            behavior: parse_input_behavior(input_behavior)?,
        }],
        ipset_convert_options(),
    )
    .map_err(to_napi_error)?;
    extract_ip_rule_set(result)
}

fn collect_ip_rule_set_from_payload(
    payload: &[u8],
    input_target: Option<String>,
    input_format: Option<String>,
    input_behavior: Option<String>,
) -> Result<RuleSetOutput> {
    let mut options = ipset_convert_options();
    options.input_target = parse_optional_rule_target(input_target)?;
    options.input_format = parse_optional_input_format(input_format)?;
    options.input_behavior = parse_input_behavior(input_behavior)?;
    let result = convert_payload(payload, options).map_err(to_napi_error)?;
    extract_ip_rule_set(result)
}

fn ipset_convert_options() -> CoreConvertOptions {
    CoreConvertOptions {
        input_target: None,
        input_format: None,
        input_behavior: InputBehaviorMode::Auto,
        output_target: RuleTarget::General,
        output_format: OutputFormat::IpSet,
        output_behavior: BehaviorMode::Ipcidr,
    }
}

fn extract_ip_rule_set(result: rule_converter::ConvertResult) -> Result<RuleSetOutput> {
    for output in result.outputs {
        if matches!(output, RuleSetOutput::Ipcidr(_)) {
            return Ok(output);
        }
    }
    Err(napi::Error::from_reason(
        "DB build input does not contain any IP CIDR rules",
    ))
}

fn any_buffer_result_to_string(result: AnyBufferResult) -> Result<AnyStringResult> {
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

fn any_rules_result(
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

fn any_db_rules_result(outputs: Vec<rule_converter::DbMemoryOutput>) -> AnyBufferResult {
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

fn any_db_result(output: rule_converter::DbBytesOutput) -> AnyBufferResult {
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

fn parse_any_input_target(value: Option<&str>) -> Result<AnyTarget> {
    parse_any_target(value, true)
}

fn parse_any_output_target(value: Option<&str>) -> Result<AnyTarget> {
    parse_any_target(value, false)
}

fn parse_any_target(value: Option<&str>, allow_auto_rule_input: bool) -> Result<AnyTarget> {
    match value {
        Some("geoip") => Ok(AnyTarget::Geoip),
        Some("asn") => Ok(AnyTarget::Asn),
        Some(value) => Ok(AnyTarget::Rule(Some(
            RuleTarget::parse_arg(value).map_err(to_napi_error)?,
        ))),
        None if allow_auto_rule_input => Ok(AnyTarget::Rule(None)),
        None => Ok(AnyTarget::Rule(Some(RuleTarget::Mihomo))),
    }
}

fn parse_rule_input_format(value: Option<&str>) -> Result<Option<InputFormat>> {
    value
        .map(InputFormat::parse_arg)
        .transpose()
        .map_err(to_napi_error)
}

fn parse_rule_output_format(value: Option<&str>) -> Result<Option<OutputFormat>> {
    value
        .map(OutputFormat::parse_arg)
        .transpose()
        .map_err(to_napi_error)
}

fn parse_output_behavior(value: Option<&str>) -> Result<Option<BehaviorMode>> {
    value
        .map(BehaviorMode::parse_arg)
        .transpose()
        .map_err(to_napi_error)
}

fn parse_db_format_value(value: Option<&str>) -> Result<Option<MmdbFormat>> {
    value
        .map(MmdbFormat::parse)
        .transpose()
        .map_err(to_napi_error)
}

fn validate_asn_output_format(value: Option<&str>) -> Result<()> {
    if let Some(format) = parse_db_format_value(value)? {
        if format != MmdbFormat::Mmdb {
            return Err(napi::Error::from_reason(
                "ASN target only supports mmdb format",
            ));
        }
    }
    Ok(())
}

fn parse_optional_rule_target(value: Option<String>) -> Result<Option<RuleTarget>> {
    value
        .as_deref()
        .map(RuleTarget::parse_arg)
        .transpose()
        .map_err(to_napi_error)
}

fn parse_optional_input_format(value: Option<String>) -> Result<Option<InputFormat>> {
    value
        .as_deref()
        .map(InputFormat::parse_arg)
        .transpose()
        .map_err(to_napi_error)
}

fn parse_input_behavior(value: Option<String>) -> Result<InputBehaviorMode> {
    value
        .as_deref()
        .map(InputBehaviorMode::parse_arg)
        .transpose()
        .map_err(to_napi_error)
        .map(|value| value.unwrap_or(InputBehaviorMode::Auto))
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
