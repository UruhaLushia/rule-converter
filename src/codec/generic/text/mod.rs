mod adguard;
pub mod plain;

pub use adguard::{
    for_each_adguard_rule, looks_like_adguard_line, parse_adguard, write_adguard_domain_rule,
};
pub use plain::{
    for_each_domain_set_rule, for_each_plain_rule, parse_domain_set, parse_plain,
    write_domain_set_rule, write_plain_rule, write_plain_rules, write_typed_rule,
};
