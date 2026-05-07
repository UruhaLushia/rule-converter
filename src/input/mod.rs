mod detect;
mod format;
pub(crate) mod parser;
mod source;

pub use detect::{DetectedInput, detect_path, detect_payload};
pub use format::InputFormat;
pub use parser::{parse_input, parse_input_as};
pub use source::{InputSource, expand_file_paths, for_each_rule, load_rules, load_rules_as};
