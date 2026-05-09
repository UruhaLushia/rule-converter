use anyhow::Result;

pub(super) fn report_result(
    files: Vec<rule_converter::OutputFile>,
    skipped: Vec<rule_converter::SkippedRule>,
) -> Result<()> {
    for file in files {
        eprintln!(
            "wrote {} rules to {} ({})",
            file.count,
            file.path.display(),
            file.behavior.as_str()
        );
    }

    if !skipped.is_empty() {
        eprintln!("skipped {} unsupported rules", skipped.len());
        for item in skipped.iter().take(10) {
            eprintln!("  - {}: {}", item.reason, item.rule);
        }
        if skipped.len() > 10 {
            eprintln!("  ... {} more", skipped.len() - 10);
        }
    }

    Ok(())
}
