mod format;
mod target;

pub use crate::codec::mihomo::mrs::{Behavior, RuleSetOutput};
pub use format::OutputFormat;
pub use target::{
    MemoryOutput, OutputFile, OutputTarget, resolve_output_path, resolve_output_path_for_target,
    write_owned_sing_box_rule_set, write_owned_sing_box_rule_set_to_memory, write_rule_sets,
    write_rule_sets_to_memory,
};
