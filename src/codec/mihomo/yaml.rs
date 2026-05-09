mod chars;
mod parse;
mod write;

pub use parse::{for_each_simple_yaml_rule, for_each_yaml_rule, parse_yaml};
pub use write::{
    write_payload_yaml, write_payload_yaml_domain_rule, write_payload_yaml_rule,
    write_payload_yaml_start, write_payload_yaml_typed_rule,
};

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn streams_payload_rules_from_formatted_yaml() {
        let yaml = r#"
port: 7890
payload:
  - DOMAIN,example.com
  - "DOMAIN-SUFFIX,example.net"
  # ignored
other:
  - not-a-rule
rules:
  - IP-CIDR,192.168.1.0/24
"#;
        let mut rules = Vec::new();
        let count = for_each_yaml_rule(Cursor::new(yaml), |rule| {
            rules.push(rule.to_string());
            Ok(())
        })
        .unwrap();

        assert_eq!(count, 3);
        assert_eq!(
            rules,
            vec![
                "DOMAIN,example.com",
                "DOMAIN-SUFFIX,example.net",
                "IP-CIDR,192.168.1.0/24"
            ]
        );
    }

    #[test]
    fn streams_flow_style_payload_rules() {
        let yaml = r#"payload: ["DOMAIN,example.com", "IP-CIDR,10.0.0.0/8"]"#;
        let mut rules = Vec::new();
        let count = for_each_yaml_rule(Cursor::new(yaml), |rule| {
            rules.push(rule.to_string());
            Ok(())
        })
        .unwrap();

        assert_eq!(count, 2);
        assert_eq!(rules, vec!["DOMAIN,example.com", "IP-CIDR,10.0.0.0/8"]);
    }

    #[test]
    fn streams_root_sequence_rules() {
        let yaml = r#"
- DOMAIN,example.com
- "DOMAIN-SUFFIX,example.net"
"#;
        let mut rules = Vec::new();
        let count = for_each_yaml_rule(Cursor::new(yaml), |rule| {
            rules.push(rule.to_string());
            Ok(())
        })
        .unwrap();

        assert_eq!(count, 2);
        assert_eq!(
            rules,
            vec!["DOMAIN,example.com", "DOMAIN-SUFFIX,example.net"]
        );
    }

    #[test]
    fn simple_yaml_fast_path_streams_plain_payload_rules() {
        let yaml = r#"payload:
  - DOMAIN,example.com
  - DOMAIN-SUFFIX,example.net
"#;
        let mut rules = Vec::new();
        let count = for_each_simple_yaml_rule(Cursor::new(yaml), |rule| {
            rules.push(rule.to_string());
            Ok(())
        })
        .unwrap();

        assert_eq!(count, Some(2));
        assert_eq!(
            rules,
            vec!["DOMAIN,example.com", "DOMAIN-SUFFIX,example.net"]
        );
    }

    #[test]
    fn simple_yaml_fast_path_declines_quoted_rules() {
        let yaml = r#"payload:
  - "DOMAIN,example.com"
"#;
        let count = for_each_simple_yaml_rule(Cursor::new(yaml), |_| Ok(())).unwrap();

        assert_eq!(count, None);
    }
}
