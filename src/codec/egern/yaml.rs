mod chars;
mod extractor;
mod parse;
mod write;

pub use parse::{for_each_ruleset_rule, parse_ruleset};
pub use write::{
    write_ruleset_yaml, write_ruleset_yaml_with_options, write_rulesets_yaml_with_options,
};

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn parses_supported_egern_ruleset_fields() {
        let yaml = r#"
no_resolve: true
domain_set:
  - www.google.com
domain_keyword_set:
  - ignored
domain_suffix_set: [google.com, .youtube.com]
ip_cidr_set:
  - 192.168.0.0/16
ip_cidr6_set:
  - "2001:db8::/32"
"#;
        let mut rules = Vec::new();
        let count = for_each_ruleset_rule(Cursor::new(yaml), |rule| {
            rules.push(rule.to_string());
            Ok(())
        })
        .unwrap();

        assert_eq!(count, 5);
        assert_eq!(
            rules,
            vec![
                "www.google.com",
                "+.google.com",
                "+.youtube.com",
                "IP-CIDR,192.168.0.0/16,no-resolve",
                "IP-CIDR6,2001:db8::/32,no-resolve"
            ]
        );
    }
}
