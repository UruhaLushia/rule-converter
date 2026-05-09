mod builder;
mod io;
mod louds;
mod normalize;
mod set;

pub use builder::DomainSetBuilder;
pub use normalize::normalize_domain_rule;
pub use set::DomainSet;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_expands_to_exact_and_complex_wildcard() {
        let mut domains = Vec::new();
        normalize_domain_rule("+.example.com", |rule| {
            domains.push(rule.to_string());
            Ok(())
        })
        .unwrap();
        assert_eq!(domains, vec!["example.com", "+.example.com"]);
    }

    #[test]
    fn rules_distinguish_subdomain_only_and_complex_wildcard() {
        let mut builder = DomainSetBuilder::default();
        builder.insert(".example.com").unwrap();
        builder.insert("+.example.net").unwrap();

        let set = builder.finish().unwrap();

        assert_eq!(set.rules(), vec![".example.com", "+.example.net"]);
    }

    #[test]
    fn domain_set_suffix_lines_include_exact_domain() {
        let mut builder = DomainSetBuilder::default();
        builder.insert_domain_set(".example.com").unwrap();

        let set = builder.finish().unwrap();

        assert_eq!(set.rules(), vec!["+.example.com"]);
    }
}
