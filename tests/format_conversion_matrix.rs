#[path = "format_conversion_matrix/cases.rs"]
mod cases;
#[path = "format_conversion_matrix/outputs.rs"]
mod outputs;
#[path = "format_conversion_matrix/render.rs"]
mod render;
#[path = "format_conversion_matrix/types.rs"]
mod types;

use cases::derived_input_cases;
use outputs::output_cases;
use render::{case_name, render};

#[test]
fn format_conversion_matrix() {
    let inputs = derived_input_cases();
    let outputs = output_cases();
    let mut checked = 0usize;

    for input in &inputs {
        for output in &outputs {
            if !(output.accepts)(input.kind) {
                continue;
            }

            let bytes = render(input, *output)
                .unwrap_or_else(|error| panic!("{} failed: {error:?}", case_name(input, *output)));
            assert!(
                !bytes.is_empty(),
                "{} produced empty bytes",
                case_name(input, *output)
            );
            checked += 1;
        }
    }

    assert!(checked > 0);
}
