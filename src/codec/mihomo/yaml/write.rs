use std::io::Write;

use crate::codec::mihomo::mrs::Behavior;

pub fn write_payload_yaml<W, I, S>(mut writer: W, rules: I) -> std::io::Result<()>
where
    W: Write,
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    writeln!(writer, "payload:")?;
    for rule in rules {
        writeln!(writer, "  - {:?}", rule.as_ref())?;
    }
    Ok(())
}

pub fn write_payload_yaml_start<W: Write>(writer: &mut W) -> std::io::Result<()> {
    writeln!(writer, "payload:")
}

pub fn write_payload_yaml_rule<W: Write>(writer: &mut W, rule: &str) -> std::io::Result<()> {
    writeln!(writer, "  - {rule:?}")
}

pub fn write_payload_yaml_typed_rule<W: Write>(
    writer: &mut W,
    behavior: Behavior,
    rule: &str,
) -> std::io::Result<()> {
    let rule = match behavior {
        Behavior::Domain => {
            if let Some(suffix) = rule.strip_prefix("+.") {
                format!("DOMAIN-SUFFIX,{suffix}")
            } else {
                format!("DOMAIN,{rule}")
            }
        }
        Behavior::Ipcidr => {
            let kind = if rule.contains(':') {
                "IP-CIDR6"
            } else {
                "IP-CIDR"
            };
            format!("{kind},{rule}")
        }
    };
    writeln!(writer, "  - {rule:?}")
}

pub fn write_payload_yaml_domain_rule<W: Write>(writer: &mut W, rule: &str) -> std::io::Result<()> {
    writeln!(writer, "  - {rule:?}")
}
