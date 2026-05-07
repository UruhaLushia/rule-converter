pub fn write_domain_rule<W: std::io::Write>(writer: &mut W, rule: &str) -> std::io::Result<()> {
    writeln!(writer, "{rule}")
}
