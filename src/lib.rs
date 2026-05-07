mod api;
pub mod codec;
#[cfg(feature = "config")]
mod config;
mod input;
mod output;
mod rules;
mod target;

pub use api::{
    ConvertOptions, ConvertResult, SkippedRule, convert_file, convert_files, convert_payload,
    convert_rules, write_outputs, write_outputs_as, write_outputs_as_owned,
    write_outputs_as_to_memory_owned, write_outputs_owned, write_outputs_to_memory,
    write_outputs_to_memory_owned,
};
#[cfg(feature = "config")]
pub use config::{ConfigJob, load_config};
pub use input::{InputFormat, InputSource, load_rules, load_rules_as, parse_input};
pub use output::{
    Behavior, MemoryOutput, OutputFile, OutputFormat, OutputTarget, RuleSetOutput,
    resolve_output_path, write_owned_sing_box_rule_set, write_owned_sing_box_rule_set_to_memory,
    write_rule_sets, write_rule_sets_to_memory,
};
pub use rules::{BehaviorMode, InputBehaviorMode};
pub use target::RuleTarget;

pub type Result<T> = anyhow::Result<T>;
