use std::fs::{self, File};
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::RuleTarget;
use crate::codec::mihomo::mrs::{Behavior, parse_prefix, read_mrs_stream};
use crate::codec::sing_box::RuleStore;
use crate::codec::{generic, mihomo};
use crate::input::{
    DetectedInput, InputFormat, InputSource, detect_path, detect_payload, expand_file_paths,
    for_each_rule,
};
use crate::output::{
    MemoryOutput, OutputFile, OutputFormat, OutputTarget, RuleSetOutput,
    resolve_output_path_for_target, write_owned_sing_box_rule_set,
    write_owned_sing_box_rule_set_to_memory, write_rule_sets, write_rule_sets_to_memory,
};
use crate::rules::{
    BehaviorMode, Converter, InputBehaviorMode, RuleTextStore, classical_to_domain,
    classical_to_ipcidr, classical_to_provider_rule, looks_classical,
};

mod db;
mod matcher;
pub use db::*;
pub use matcher::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConvertOptions {
    pub input_target: Option<RuleTarget>,
    pub input_format: Option<InputFormat>,
    pub input_behavior: InputBehaviorMode,
    pub output_target: RuleTarget,
    pub output_format: OutputFormat,
    pub output_behavior: BehaviorMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileInput {
    pub path: PathBuf,
    pub target: Option<RuleTarget>,
    pub format: Option<InputFormat>,
    pub behavior: InputBehaviorMode,
}

impl FileInput {
    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            target: None,
            format: None,
            behavior: InputBehaviorMode::Auto,
        }
    }
}

impl Default for ConvertOptions {
    fn default() -> Self {
        Self {
            input_target: None,
            input_format: None,
            input_behavior: InputBehaviorMode::Auto,
            output_target: RuleTarget::Mihomo,
            output_format: OutputFormat::Mrs,
            output_behavior: BehaviorMode::Auto,
        }
    }
}

pub fn default_output_behavior(
    output_target: RuleTarget,
    output_format: OutputFormat,
) -> BehaviorMode {
    match (output_target, output_format) {
        (RuleTarget::General, OutputFormat::IpSet) => BehaviorMode::Ipcidr,
        (RuleTarget::General, OutputFormat::DomainSet) => BehaviorMode::Domain,
        (RuleTarget::Mihomo, OutputFormat::Mrs) => BehaviorMode::Auto,
        _ => BehaviorMode::Classical,
    }
}

fn normalize_options(mut options: ConvertOptions) -> ConvertOptions {
    options.output_behavior = normalize_output_behavior(
        options.output_target,
        options.output_format,
        options.output_behavior,
    );
    options
}

fn normalize_output_behavior(
    output_target: RuleTarget,
    output_format: OutputFormat,
    output_behavior: BehaviorMode,
) -> BehaviorMode {
    match (output_target, output_format) {
        (RuleTarget::General, OutputFormat::DomainSet) => BehaviorMode::Domain,
        (RuleTarget::General, OutputFormat::IpSet) => BehaviorMode::Ipcidr,
        _ => output_behavior,
    }
}

fn resolve_output_behavior(
    options: ConvertOptions,
    input_behavior: InputBehaviorMode,
) -> Result<BehaviorMode> {
    let behavior = normalize_output_behavior(
        options.output_target,
        options.output_format,
        options.output_behavior,
    );
    if behavior != BehaviorMode::Auto {
        return Ok(behavior);
    }

    match (options.output_target, options.output_format, input_behavior) {
        (
            RuleTarget::Mihomo,
            OutputFormat::Mrs | OutputFormat::Text | OutputFormat::Yaml,
            InputBehaviorMode::Domain,
        ) => Ok(BehaviorMode::Domain),
        (
            RuleTarget::Mihomo,
            OutputFormat::Mrs | OutputFormat::Text | OutputFormat::Yaml,
            InputBehaviorMode::Ipcidr,
        ) => Ok(BehaviorMode::Ipcidr),
        (RuleTarget::Mihomo, OutputFormat::Mrs, _) => bail!(
            "mihomo MRS output needs explicit output behavior for mixed/classical input; use domain or ip"
        ),
        _ => Ok(default_output_behavior(
            options.output_target,
            options.output_format,
        )),
    }
}

fn options_with_output_behavior(
    mut options: ConvertOptions,
    output_behavior: BehaviorMode,
) -> ConvertOptions {
    options.output_behavior = output_behavior;
    options
}

pub struct ConvertResult {
    pub outputs: Vec<RuleSetOutput>,
    pub mixed_rules: RuleTextStore,
    pub sing_box_rules: Option<RuleStore>,
    pub output_behavior: BehaviorMode,
    pub no_resolve: bool,
    pub skipped: Vec<SkippedRule>,
}

impl ConvertResult {
    pub fn is_empty(&self) -> bool {
        self.outputs.is_empty()
            && self.mixed_rules.is_empty()
            && self.sing_box_rules.as_ref().is_none_or(RuleStore::is_empty)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkippedRule {
    pub rule: String,
    pub reason: String,
}

impl SkippedRule {
    pub fn new(rule: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            rule: rule.into(),
            reason: reason.into(),
        }
    }
}

pub fn convert_payload(
    payload: impl AsRef<[u8]>,
    options: ConvertOptions,
) -> Result<ConvertResult> {
    let options = normalize_options(options);
    let payload = payload.as_ref();
    let detected = apply_input_options(detect_payload(payload)?, options);
    let input_behavior = effective_input_behavior(detected);
    let output_behavior = resolve_output_behavior(options, input_behavior)?;
    let options = options_with_output_behavior(options, output_behavior);
    let converter = converter_for_options(input_behavior, detected.target, options);
    let mut builder = converter.builder_with_options(
        should_keep_mixed_rules(options, input_behavior),
        should_build_rule_sets(options, input_behavior),
        should_keep_domain_set_lines(options),
        should_keep_ip_set_lines(options),
    );
    builder.reserve(
        estimate_rule_count(payload.len()),
        estimate_rule_bytes(payload.len()),
    );
    let count = for_each_rule(
        InputSource::Payload(payload),
        detected.target,
        detected.format,
        |rule| builder.push(rule),
    )?;
    if count == 0 {
        bail!("input does not contain any rules in `rules` or `payload`");
    }
    let mut result = builder.finish()?;
    result.output_behavior = output_behavior;
    if result.is_empty() {
        bail!("no supported rules found for the requested conversion");
    }
    Ok(result)
}

pub fn convert_file(path: impl AsRef<Path>, options: ConvertOptions) -> Result<ConvertResult> {
    convert_files([path], options)
}

pub fn convert_files<P, I>(paths: I, options: ConvertOptions) -> Result<ConvertResult>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = P>,
{
    let inputs = paths
        .into_iter()
        .map(|path| FileInput::path(path.as_ref()))
        .collect::<Vec<_>>();
    convert_file_inputs(inputs, options)
}

pub fn convert_file_inputs<I>(inputs: I, options: ConvertOptions) -> Result<ConvertResult>
where
    I: IntoIterator<Item = FileInput>,
{
    let options = normalize_options(options);
    let (paths, detected) = detect_configured_file_inputs(inputs, options)?;
    if let Some(result) = convert_single_mrs_file_fast_path(&paths, &detected, options)? {
        return Ok(result);
    }
    let input_behavior = merge_input_behavior(detected.iter().copied());
    let output_behavior = resolve_output_behavior(options, input_behavior)?;
    let options = options_with_output_behavior(options, output_behavior);
    let input_target = merge_input_target(detected.iter().copied());
    let converter = converter_for_options(input_behavior, input_target, options);
    let mut builder = converter.builder_with_options(
        should_keep_mixed_rules(options, input_behavior),
        should_build_rule_sets(options, input_behavior),
        should_keep_domain_set_lines(options),
        should_keep_ip_set_lines(options),
    );
    let input_bytes = estimate_file_input_bytes(&paths);
    builder.reserve(
        estimate_rule_count(input_bytes),
        estimate_rule_bytes(input_bytes),
    );
    let mut count = 0usize;
    for (path, detected) in paths.iter().zip(detected.iter().copied()) {
        count += for_each_rule(
            InputSource::FilePath(path),
            detected.target,
            detected.format,
            |rule| builder.push(rule),
        )?;
    }
    if count == 0 {
        bail!("input does not contain any rules in `rules` or `payload`");
    }
    let mut result = builder.finish()?;
    result.output_behavior = output_behavior;
    if result.is_empty() {
        bail!("no supported rules found for the requested conversion");
    }
    Ok(result)
}

pub fn convert_files_to_path_streaming<P, I>(
    paths: I,
    output: impl AsRef<Path>,
    options: ConvertOptions,
) -> Result<Option<(Vec<OutputFile>, Vec<SkippedRule>)>>
where
    P: AsRef<Path>,
    I: IntoIterator<Item = P>,
{
    let inputs = paths
        .into_iter()
        .map(|path| FileInput::path(path.as_ref()))
        .collect::<Vec<_>>();
    convert_file_inputs_to_path_streaming(inputs, output, options)
}

pub fn convert_file_inputs_to_path_streaming<I>(
    inputs: I,
    output: impl AsRef<Path>,
    options: ConvertOptions,
) -> Result<Option<(Vec<OutputFile>, Vec<SkippedRule>)>>
where
    I: IntoIterator<Item = FileInput>,
{
    let options = normalize_options(options);
    let (paths, detected) = detect_configured_file_inputs(inputs, options)?;
    let input_behavior = merge_input_behavior(detected.iter().copied());
    let output_behavior = resolve_output_behavior(options, input_behavior)?;
    let options = options_with_output_behavior(options, output_behavior);

    if !can_stream_text_to_path(options) {
        return Ok(None);
    }

    stream_text_to_path(&paths, &detected, output.as_ref(), options).map(Some)
}

fn convert_single_mrs_file_fast_path(
    paths: &[PathBuf],
    detected: &[DetectedInput],
    options: ConvertOptions,
) -> Result<Option<ConvertResult>> {
    if paths.len() != 1 {
        return Ok(None);
    }
    let Some(detected) = detected.first().copied() else {
        return Ok(None);
    };
    if detected.target != RuleTarget::Mihomo || detected.format != InputFormat::Mrs {
        return Ok(None);
    }

    let file = File::open(&paths[0])
        .with_context(|| format!("failed to read input {}", paths[0].display()))?;
    let rule_set = read_mrs_stream(file)?;
    let input_behavior = match rule_set.behavior() {
        Behavior::Domain => InputBehaviorMode::Domain,
        Behavior::Ipcidr => InputBehaviorMode::Ipcidr,
    };
    let output_behavior = resolve_output_behavior(options, input_behavior)?;
    if !can_reuse_mrs_rule_set(options, output_behavior) {
        return Ok(None);
    }
    if !rule_set_matches_behavior(&rule_set, output_behavior) {
        return Ok(None);
    }

    Ok(Some(ConvertResult {
        outputs: vec![rule_set],
        mixed_rules: RuleTextStore::default(),
        sing_box_rules: None,
        output_behavior,
        no_resolve: false,
        skipped: Vec::new(),
    }))
}

fn estimate_file_input_bytes(paths: &[PathBuf]) -> usize {
    paths
        .iter()
        .filter_map(|path| path.metadata().ok())
        .map(|metadata| metadata.len() as usize)
        .sum()
}

fn estimate_rule_count(input_bytes: usize) -> usize {
    if input_bytes < 1024 * 1024 {
        0
    } else {
        input_bytes / 34
    }
}

fn estimate_rule_bytes(input_bytes: usize) -> usize {
    if input_bytes < 1024 * 1024 {
        0
    } else {
        input_bytes.saturating_mul(2) / 3
    }
}

fn can_stream_text_to_path(options: ConvertOptions) -> bool {
    matches!(
        (options.output_target, options.output_format),
        (
            RuleTarget::General,
            OutputFormat::RuleSet | OutputFormat::DomainSet | OutputFormat::IpSet
        ) | (RuleTarget::Mihomo, OutputFormat::Text | OutputFormat::Yaml)
    ) && options.output_behavior != BehaviorMode::Auto
}

fn stream_text_to_path(
    paths: &[PathBuf],
    detected: &[DetectedInput],
    output: &Path,
    options: ConvertOptions,
) -> Result<(Vec<OutputFile>, Vec<SkippedRule>)> {
    let behavior = behavior_to_mrs_behavior(options.output_behavior);
    let path = resolve_output_path_for_target(
        output,
        behavior,
        false,
        options.output_format,
        options.output_target,
    );
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    }
    let file = File::create(&path)
        .with_context(|| format!("failed to create output {}", path.display()))?;
    let mut writer = BufWriter::with_capacity(64 * 1024, file);
    if options.output_format == OutputFormat::Yaml {
        mihomo::write_payload_yaml_start(&mut writer)?;
    }

    let mut state = StreamTextState::new(options);
    for (path, detected) in paths.iter().zip(detected.iter().copied()) {
        for_each_rule(
            InputSource::FilePath(path),
            detected.target,
            detected.format,
            |rule| state.write_rule(&mut writer, rule),
        )?;
    }

    if state.count == 0 {
        bail!("no supported rules found for the requested conversion");
    }

    Ok((
        vec![OutputFile {
            behavior,
            format: options.output_format,
            count: state.count,
            path,
        }],
        state.skipped,
    ))
}

fn behavior_to_mrs_behavior(behavior: BehaviorMode) -> Behavior {
    match behavior {
        BehaviorMode::Ipcidr => Behavior::Ipcidr,
        BehaviorMode::Auto | BehaviorMode::Domain | BehaviorMode::Classical => Behavior::Domain,
    }
}

struct StreamTextState {
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
    count: usize,
    skipped: Vec<SkippedRule>,
}

impl StreamTextState {
    fn new(options: ConvertOptions) -> Self {
        Self {
            target: options.output_target,
            format: options.output_format,
            behavior: options.output_behavior,
            count: 0,
            skipped: Vec::new(),
        }
    }

    fn write_rule<W: std::io::Write>(&mut self, writer: &mut W, rule: &str) -> Result<()> {
        let Some(out) = self.convert_rule(rule) else {
            return Ok(());
        };

        match (self.target, self.format) {
            (RuleTarget::General, OutputFormat::DomainSet) => {
                generic::text::write_domain_set_rule(writer, &out)?
            }
            (RuleTarget::General, OutputFormat::IpSet) => {
                generic::text::write_plain_rule(writer, &out)?
            }
            (RuleTarget::General, OutputFormat::RuleSet) => {
                generic::text::write_plain_rule(writer, &out)?
            }
            (RuleTarget::Mihomo, OutputFormat::Text) => {
                generic::text::write_plain_rule(writer, &out)?
            }
            (RuleTarget::Mihomo, OutputFormat::Yaml) => {
                mihomo::write_payload_yaml_rule(writer, &out)?
            }
            _ => unreachable!("streaming writer only handles text formats"),
        }
        self.count += 1;
        Ok(())
    }

    fn convert_rule(&mut self, rule: &str) -> Option<String> {
        match self.behavior {
            BehaviorMode::Domain => self.convert_domain(rule),
            BehaviorMode::Ipcidr => self.convert_ip(rule),
            BehaviorMode::Classical => self.convert_classical(rule),
            BehaviorMode::Auto => None,
        }
    }

    fn convert_domain(&mut self, rule: &str) -> Option<String> {
        let domain = if looks_classical(rule) {
            match classical_to_domain(rule) {
                Ok(Some(domain)) => domain,
                Ok(None) => return self.skip(rule, "not a domain rule"),
                Err(err) => return self.skip(rule, err.to_string()),
            }
        } else {
            rule.to_string()
        };

        if self.target == RuleTarget::General && self.format == OutputFormat::RuleSet {
            if let Some(suffix) = domain
                .strip_prefix("+.")
                .or_else(|| domain.strip_prefix('.'))
            {
                Some(format!("DOMAIN-SUFFIX,{}", suffix.trim_start_matches('.')))
            } else {
                Some(format!("DOMAIN,{domain}"))
            }
        } else {
            Some(domain)
        }
    }

    fn convert_ip(&mut self, rule: &str) -> Option<String> {
        let cidr = if looks_classical(rule) {
            match classical_to_ipcidr(rule) {
                Ok(Some(cidr)) => cidr,
                Ok(None) => return self.skip(rule, "not an ipcidr rule"),
                Err(err) => return self.skip(rule, err.to_string()),
            }
        } else {
            if let Err(err) = parse_prefix(rule) {
                return self.skip(rule, err.to_string());
            }
            rule.to_string()
        };

        if self.target == RuleTarget::General && self.format == OutputFormat::RuleSet {
            let kind = if cidr.contains(':') {
                "IP-CIDR6"
            } else {
                "IP-CIDR"
            };
            Some(format!("{kind},{cidr}"))
        } else {
            Some(cidr)
        }
    }

    fn convert_classical(&mut self, rule: &str) -> Option<String> {
        if looks_classical(rule) {
            match classical_to_provider_rule(rule) {
                Ok(Some(rule)) => Some(rule),
                Ok(None) => self.skip(rule, "unsupported rule-provider rule type"),
                Err(err) => self.skip(rule, err.to_string()),
            }
        } else if parse_prefix(rule).is_ok() {
            let kind = if rule.contains(':') {
                "IP-CIDR6"
            } else {
                "IP-CIDR"
            };
            Some(format!("{kind},{rule}"))
        } else {
            Some(format!("DOMAIN,{rule}"))
        }
    }

    fn skip(&mut self, rule: &str, reason: impl Into<String>) -> Option<String> {
        self.skipped.push(SkippedRule::new(rule, reason));
        None
    }
}

fn can_reuse_mrs_rule_set(options: ConvertOptions, output_behavior: BehaviorMode) -> bool {
    if options.output_target == RuleTarget::SingBox {
        return false;
    }
    if options.output_target == RuleTarget::Mihomo
        && matches!(
            options.output_format,
            OutputFormat::Text | OutputFormat::Yaml
        )
        && output_behavior == BehaviorMode::Classical
    {
        return false;
    }
    matches!(
        output_behavior,
        BehaviorMode::Domain | BehaviorMode::Ipcidr | BehaviorMode::Classical
    )
}

fn rule_set_matches_behavior(rule_set: &RuleSetOutput, output_behavior: BehaviorMode) -> bool {
    matches!(
        (rule_set.behavior(), output_behavior),
        (
            Behavior::Domain,
            BehaviorMode::Domain | BehaviorMode::Classical
        ) | (
            Behavior::Ipcidr,
            BehaviorMode::Ipcidr | BehaviorMode::Classical
        )
    )
}

fn detect_configured_file_inputs<I>(
    inputs: I,
    options: ConvertOptions,
) -> Result<(Vec<PathBuf>, Vec<DetectedInput>)>
where
    I: IntoIterator<Item = FileInput>,
{
    let mut paths = Vec::new();
    let mut detected = Vec::new();

    for input in inputs {
        let expanded = expand_file_paths([input.path])?;
        for path in expanded {
            let input_options = ConvertOptions {
                input_target: input.target.or(options.input_target),
                input_format: input.format.or(options.input_format),
                input_behavior: if input.behavior == InputBehaviorMode::Auto {
                    options.input_behavior
                } else {
                    input.behavior
                },
                ..options
            };
            let item_detected = detect_file_input(&path, input_options)?;
            paths.push(path);
            detected.push(item_detected);
        }
    }

    if paths.is_empty() {
        bail!("input path expansion did not match any files");
    }
    Ok((paths, detected))
}

fn detect_file_input(path: &Path, options: ConvertOptions) -> Result<DetectedInput> {
    if let (Some(target), Some(format)) = (options.input_target, options.input_format) {
        let behavior = input_behavior_to_output_mode(options.input_behavior);
        if target == RuleTarget::Mihomo
            && format == InputFormat::Mrs
            && behavior == BehaviorMode::Auto
        {
            return detect_path(path).map(|detected| DetectedInput {
                target,
                format,
                behavior: detected.behavior,
            });
        }
        return Ok(DetectedInput {
            target,
            format,
            behavior,
        });
    }

    detect_path(path).map(|detected| apply_input_options(detected, options))
}

fn apply_input_options(mut detected: DetectedInput, options: ConvertOptions) -> DetectedInput {
    if let Some(target) = options.input_target {
        detected.target = target;
    }
    if let Some(format) = options.input_format {
        detected.format = format;
    }
    if options.input_behavior != InputBehaviorMode::Auto {
        detected.behavior = input_behavior_to_output_mode(options.input_behavior);
    }
    detected
}

fn merge_input_behavior(detected: impl IntoIterator<Item = DetectedInput>) -> InputBehaviorMode {
    let mut behavior = InputBehaviorMode::Auto;
    for item in detected {
        let item_behavior = effective_input_behavior(item);
        if item_behavior == InputBehaviorMode::Auto {
            return InputBehaviorMode::Auto;
        }
        if behavior == InputBehaviorMode::Auto {
            behavior = item_behavior;
        } else if behavior != item_behavior {
            return InputBehaviorMode::Auto;
        }
    }
    behavior
}

fn merge_input_target(detected: impl IntoIterator<Item = DetectedInput>) -> RuleTarget {
    let mut target = None;
    for item in detected {
        match target {
            None => target = Some(item.target),
            Some(current) if current == item.target => {}
            Some(_) => return RuleTarget::General,
        }
    }
    target.unwrap_or(RuleTarget::Mihomo)
}

fn effective_input_behavior(detected: DetectedInput) -> InputBehaviorMode {
    match detected.behavior {
        BehaviorMode::Auto => InputBehaviorMode::Auto,
        BehaviorMode::Domain => InputBehaviorMode::Domain,
        BehaviorMode::Ipcidr => InputBehaviorMode::Ipcidr,
        BehaviorMode::Classical => InputBehaviorMode::Classical,
    }
}

fn input_behavior_to_output_mode(behavior: InputBehaviorMode) -> BehaviorMode {
    match behavior {
        InputBehaviorMode::Auto => BehaviorMode::Auto,
        InputBehaviorMode::Domain => BehaviorMode::Domain,
        InputBehaviorMode::Ipcidr => BehaviorMode::Ipcidr,
        InputBehaviorMode::Classical => BehaviorMode::Classical,
    }
}

fn should_build_rule_sets(options: ConvertOptions, _input_behavior: InputBehaviorMode) -> bool {
    match (options.output_target, options.output_format) {
        (RuleTarget::SingBox, OutputFormat::Json | OutputFormat::Srs) => false,
        (RuleTarget::General, OutputFormat::DomainSet | OutputFormat::IpSet) => true,
        (RuleTarget::General, OutputFormat::RuleSet) => false,
        (RuleTarget::Mihomo, OutputFormat::Text | OutputFormat::Yaml) => {
            options.output_behavior != BehaviorMode::Classical
        }
        _ => true,
    }
}

fn should_keep_domain_set_lines(options: ConvertOptions) -> bool {
    options.output_target == RuleTarget::General && options.output_format == OutputFormat::DomainSet
}

fn should_keep_ip_set_lines(options: ConvertOptions) -> bool {
    options.output_target == RuleTarget::General && options.output_format == OutputFormat::IpSet
}

fn should_keep_mixed_rules(options: ConvertOptions, input_behavior: InputBehaviorMode) -> bool {
    match (options.output_target, options.output_format) {
        (RuleTarget::Mihomo, OutputFormat::Text | OutputFormat::Yaml) => {
            options.output_behavior == BehaviorMode::Classical
        }
        (RuleTarget::General, OutputFormat::RuleSet) => true,
        (RuleTarget::General, OutputFormat::DomainSet | OutputFormat::IpSet) => false,
        (RuleTarget::Egern, OutputFormat::RuleSet) => false,
        _ => {
            options.output_behavior == BehaviorMode::Classical
                && input_behavior == InputBehaviorMode::Classical
        }
    }
}

fn converter_for_options(
    input_behavior: InputBehaviorMode,
    input_target: RuleTarget,
    options: ConvertOptions,
) -> Converter {
    if options.output_target == RuleTarget::SingBox
        && matches!(
            options.output_format,
            OutputFormat::Json | OutputFormat::Srs
        )
    {
        return Converter::for_sing_box_output(
            input_behavior,
            input_target,
            options.output_behavior,
        );
    }

    Converter::with_input_context(input_behavior, input_target, options.output_behavior)
}

pub fn convert_rules(rules: &[String], behavior: BehaviorMode) -> Result<ConvertResult> {
    if rules.is_empty() {
        bail!("input does not contain any rules in `rules` or `payload`");
    }

    let result = Converter::new(behavior).convert(rules)?;
    if result.is_empty() {
        bail!("no supported rules found for the requested conversion");
    }
    Ok(result)
}

pub fn convert_rule_set_output(
    rule_set: RuleSetOutput,
    output_behavior: BehaviorMode,
) -> ConvertResult {
    ConvertResult {
        outputs: vec![rule_set],
        mixed_rules: RuleTextStore::default(),
        sing_box_rules: None,
        output_behavior,
        no_resolve: false,
        skipped: Vec::new(),
    }
}

pub fn write_outputs(result: &ConvertResult, output: impl AsRef<Path>) -> Result<Vec<OutputFile>> {
    write_outputs_as(result, output, RuleTarget::Mihomo, OutputFormat::Mrs)
}

pub fn write_outputs_owned(
    result: ConvertResult,
    output: impl AsRef<Path>,
) -> Result<(Vec<OutputFile>, Vec<SkippedRule>)> {
    write_outputs_as_owned(result, output, RuleTarget::Mihomo, OutputFormat::Mrs)
}

pub fn write_outputs_as(
    result: &ConvertResult,
    output: impl AsRef<Path>,
    target: RuleTarget,
    format: OutputFormat,
) -> Result<Vec<OutputFile>> {
    write_rule_sets(
        &result.outputs,
        &result.mixed_rules,
        result.sing_box_rules.as_ref(),
        OutputTarget::FilePath(output.as_ref()),
        target,
        format,
        result.output_behavior,
        result.no_resolve,
    )
}

pub fn write_outputs_as_owned(
    result: ConvertResult,
    output: impl AsRef<Path>,
    target: RuleTarget,
    format: OutputFormat,
) -> Result<(Vec<OutputFile>, Vec<SkippedRule>)> {
    let skipped = result.skipped;
    let no_resolve = result.no_resolve;
    let output_behavior = result.output_behavior;
    if target == RuleTarget::SingBox
        && matches!(format, OutputFormat::Json | OutputFormat::Srs)
        && let Some(sing_box_rules) = result.sing_box_rules
    {
        let files = write_owned_sing_box_rule_set(
            sing_box_rules,
            OutputTarget::FilePath(output.as_ref()),
            format,
            output_behavior,
        )?;
        return Ok((files, skipped));
    }

    let files = write_rule_sets(
        &result.outputs,
        &result.mixed_rules,
        result.sing_box_rules.as_ref(),
        OutputTarget::FilePath(output.as_ref()),
        target,
        format,
        output_behavior,
        no_resolve,
    )?;
    Ok((files, skipped))
}

pub fn write_outputs_to_memory(
    result: &ConvertResult,
    target: RuleTarget,
    format: OutputFormat,
) -> Result<Vec<MemoryOutput>> {
    write_rule_sets_to_memory(
        &result.outputs,
        &result.mixed_rules,
        result.sing_box_rules.as_ref(),
        target,
        format,
        result.output_behavior,
        result.no_resolve,
    )
}

pub fn write_outputs_to_memory_owned(
    result: ConvertResult,
) -> Result<(Vec<MemoryOutput>, Vec<SkippedRule>)> {
    write_outputs_as_to_memory_owned(result, RuleTarget::Mihomo, OutputFormat::Mrs)
}

pub fn write_outputs_as_to_memory_owned(
    result: ConvertResult,
    target: RuleTarget,
    format: OutputFormat,
) -> Result<(Vec<MemoryOutput>, Vec<SkippedRule>)> {
    let skipped = result.skipped;
    let no_resolve = result.no_resolve;
    let output_behavior = result.output_behavior;
    if target == RuleTarget::SingBox
        && matches!(format, OutputFormat::Json | OutputFormat::Srs)
        && let Some(sing_box_rules) = result.sing_box_rules
    {
        let outputs =
            write_owned_sing_box_rule_set_to_memory(sing_box_rules, format, output_behavior)?;
        return Ok((outputs, skipped));
    }

    let outputs = write_rule_sets_to_memory(
        &result.outputs,
        &result.mixed_rules,
        result.sing_box_rules.as_ref(),
        target,
        format,
        output_behavior,
        no_resolve,
    )?;
    Ok((outputs, skipped))
}
