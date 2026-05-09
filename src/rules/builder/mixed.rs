use super::ConversionBuilder;

impl ConversionBuilder {
    pub(crate) fn push_mixed_rule(&mut self, rule: impl AsRef<str>) {
        if self.keep_mixed_rules {
            self.mixed_rules.push(rule);
        }
    }

    pub(crate) fn push_plain_mixed_domain_rule(&mut self, rule: &str) {
        if self.domain_set_mixed_rules {
            if let Some(suffix) = rule.strip_prefix("+.").or_else(|| rule.strip_prefix('.')) {
                self.push_mixed_rule(format!(".{}", suffix.trim_start_matches('.')));
            } else {
                self.push_mixed_rule(rule);
            }
            return;
        }
        if let Some(suffix) = rule.strip_prefix("+.").or_else(|| rule.strip_prefix('.')) {
            self.push_mixed_rule(format!("DOMAIN-SUFFIX,{}", suffix.trim_start_matches('.')));
        } else {
            self.push_mixed_rule(format!("DOMAIN,{rule}"));
        }
    }

    pub(crate) fn push_plain_mixed_ip_rule(&mut self, rule: &str) {
        if self.ip_set_mixed_rules {
            self.push_mixed_rule(rule);
            return;
        }
        let kind = if rule.contains(':') {
            "IP-CIDR6"
        } else {
            "IP-CIDR"
        };
        self.push_mixed_rule(format!("{kind},{rule}"));
    }
}
