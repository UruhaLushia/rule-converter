fn is_provider_option(value: &str) -> bool {
    value.eq_ignore_ascii_case("no-resolve")
        || value.eq_ignore_ascii_case("src")
        || value.eq_ignore_ascii_case("extended-matching")
}

pub(super) fn option_start(fields: &[&str]) -> usize {
    if is_provider_option(fields.get(2).copied().unwrap_or_default()) {
        2
    } else {
        3
    }
}

pub(super) fn split_top_level_commas(rule: &str) -> Vec<&str> {
    let mut fields = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;

    for (index, ch) in rule.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                fields.push(&rule[start..index]);
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    fields.push(&rule[start..]);
    fields
}
