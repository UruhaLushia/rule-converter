mod convert;
mod fields;
mod kind;
mod rule;

pub use convert::{
    classical_has_no_resolve, classical_to_domain, classical_to_ipcidr, classical_to_mixed_rule,
    classical_to_provider_rule, looks_classical,
};
pub use kind::ClassicalKind;
pub use rule::ClassicalRule;

use fields::{option_start, split_top_level_commas};
use kind::parse_kind;
