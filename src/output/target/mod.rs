mod memory;
mod path;
mod writer;

pub use memory::{
    MemoryOutput, write_owned_sing_box_rule_set_to_memory, write_rule_sets_to_memory,
};
pub use path::{resolve_output_path, resolve_output_path_for_target};
pub use writer::{OutputFile, OutputTarget, write_owned_sing_box_rule_set, write_rule_sets};
