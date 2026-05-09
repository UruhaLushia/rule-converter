use rule_converter::{
    BehaviorMode, ConvertOptions, OutputFormat, RuleTarget, convert_payload,
    write_outputs_as_to_memory_owned,
};

use super::types::{InputCase, OutputCase};

fn options(
    input: &InputCase,
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
) -> ConvertOptions {
    ConvertOptions {
        input_target: Some(input.target),
        input_format: Some(input.format),
        input_behavior: input.behavior,
        output_target: target,
        output_format: format,
        output_behavior: behavior,
    }
}

pub(super) fn render(input: &InputCase, output: OutputCase) -> anyhow::Result<Vec<u8>> {
    let result = convert_payload(
        &input.payload,
        options(input, output.target, output.format, output.behavior),
    )?;
    let (outputs, _) = write_outputs_as_to_memory_owned(result, output.target, output.format)?;
    anyhow::ensure!(
        !outputs.is_empty(),
        "{} did not produce output",
        case_name(input, output)
    );
    Ok(outputs
        .into_iter()
        .flat_map(|output| output.bytes)
        .collect())
}

pub(super) fn case_name(input: &InputCase, output: OutputCase) -> String {
    format!("{}-to-{}", input.from, output.to)
}
