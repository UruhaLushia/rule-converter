use std::fs::{self, File};
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use super::types::{ConvertOptions, SkippedRule};
use crate::RuleTarget;
use crate::codec::mihomo::mrs::{Behavior, parse_prefix};
use crate::codec::{generic, mihomo};
use crate::input::{DetectedInput, InputSource, for_each_rule};
use crate::output::{OutputFile, OutputFormat, resolve_output_path_for_target};
use crate::rules::{
    BehaviorMode, classical_to_domain, classical_to_ipcidr, classical_to_provider_rule,
    looks_classical,
};

pub(super) fn can_stream_text_to_path(options: ConvertOptions) -> bool {
    matches!(
        (options.output_target, options.output_format),
        (
            RuleTarget::General,
            OutputFormat::RuleSet
                | OutputFormat::DomainSet
                | OutputFormat::Adguard
                | OutputFormat::IpSet
        ) | (RuleTarget::Mihomo, OutputFormat::Text | OutputFormat::Yaml)
    ) && options.output_behavior != BehaviorMode::Auto
}

pub(super) fn stream_text_to_path(
    paths: &[PathBuf],
    detected: &[DetectedInput],
    output: &Path,
    options: ConvertOptions,
) -> Result<(Vec<OutputFile>, Vec<SkippedRule>)> {
    let behavior = behavior_to_mrs_behavior(options.output_behavior);
    let path = resolve_output_path_for_target(
        output,
        behavior,
        false,
        options.output_format,
        options.output_target,
    );
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory {}", parent.display()))?;
    }
    let file = File::create(&path)
        .with_context(|| format!("failed to create output {}", path.display()))?;
    let mut writer = BufWriter::with_capacity(64 * 1024, file);
    if options.output_format == OutputFormat::Yaml {
        mihomo::write_payload_yaml_start(&mut writer)?;
    }

    let mut state = StreamTextState::new(options);
    for (path, detected) in paths.iter().zip(detected.iter().copied()) {
        for_each_rule(
            InputSource::FilePath(path),
            detected.target,
            detected.format,
            |rule| state.write_rule(&mut writer, rule),
        )?;
    }

    if state.count == 0 {
        bail!("no supported rules found for the requested conversion");
    }

    Ok((
        vec![OutputFile {
            behavior,
            format: options.output_format,
            count: state.count,
            path,
        }],
        state.skipped,
    ))
}

fn behavior_to_mrs_behavior(behavior: BehaviorMode) -> Behavior {
    match behavior {
        BehaviorMode::Ipcidr => Behavior::Ipcidr,
        BehaviorMode::Auto | BehaviorMode::Domain | BehaviorMode::Classical => Behavior::Domain,
    }
}

struct StreamTextState {
    target: RuleTarget,
    format: OutputFormat,
    behavior: BehaviorMode,
    count: usize,
    skipped: Vec<SkippedRule>,
}

impl StreamTextState {
    fn new(options: ConvertOptions) -> Self {
        Self {
            target: options.output_target,
            format: options.output_format,
            behavior: options.output_behavior,
            count: 0,
            skipped: Vec::new(),
        }
    }

    fn write_rule<W: std::io::Write>(&mut self, writer: &mut W, rule: &str) -> Result<()> {
        let Some(out) = self.convert_rule(rule) else {
            return Ok(());
        };

        match (self.target, self.format) {
            (RuleTarget::General, OutputFormat::DomainSet) => {
                generic::text::write_domain_set_rule(writer, &out)?
            }
            (RuleTarget::General, OutputFormat::Adguard) => {
                generic::text::write_adguard_domain_rule(writer, &out)?
            }
            (RuleTarget::General, OutputFormat::IpSet) => {
                generic::text::write_plain_rule(writer, &out)?
            }
            (RuleTarget::General, OutputFormat::RuleSet) => {
                generic::text::write_plain_rule(writer, &out)?
            }
            (RuleTarget::Mihomo, OutputFormat::Text) => {
                generic::text::write_plain_rule(writer, &out)?
            }
            (RuleTarget::Mihomo, OutputFormat::Yaml) => {
                mihomo::write_payload_yaml_rule(writer, &out)?
            }
            _ => unreachable!("streaming writer only handles text formats"),
        }
        self.count += 1;
        Ok(())
    }

    fn convert_rule(&mut self, rule: &str) -> Option<String> {
        match self.behavior {
            BehaviorMode::Domain => self.convert_domain(rule),
            BehaviorMode::Ipcidr => self.convert_ip(rule),
            BehaviorMode::Classical => self.convert_classical(rule),
            BehaviorMode::Auto => None,
        }
    }

    fn convert_domain(&mut self, rule: &str) -> Option<String> {
        let domain = if looks_classical(rule) {
            match classical_to_domain(rule) {
                Ok(Some(domain)) => domain,
                Ok(None) => return self.skip(rule, "not a domain rule"),
                Err(err) => return self.skip(rule, err.to_string()),
            }
        } else {
            rule.to_string()
        };

        if self.target == RuleTarget::General && self.format == OutputFormat::RuleSet {
            if let Some(suffix) = domain
                .strip_prefix("+.")
                .or_else(|| domain.strip_prefix('.'))
            {
                Some(format!("DOMAIN-SUFFIX,{}", suffix.trim_start_matches('.')))
            } else {
                Some(format!("DOMAIN,{domain}"))
            }
        } else {
            Some(domain)
        }
    }

    fn convert_ip(&mut self, rule: &str) -> Option<String> {
        let cidr = if looks_classical(rule) {
            match classical_to_ipcidr(rule) {
                Ok(Some(cidr)) => cidr,
                Ok(None) => return self.skip(rule, "not an ipcidr rule"),
                Err(err) => return self.skip(rule, err.to_string()),
            }
        } else {
            if let Err(err) = parse_prefix(rule) {
                return self.skip(rule, err.to_string());
            }
            rule.to_string()
        };

        if self.target == RuleTarget::General && self.format == OutputFormat::RuleSet {
            let kind = if cidr.contains(':') {
                "IP-CIDR6"
            } else {
                "IP-CIDR"
            };
            Some(format!("{kind},{cidr}"))
        } else {
            Some(cidr)
        }
    }

    fn convert_classical(&mut self, rule: &str) -> Option<String> {
        if looks_classical(rule) {
            match classical_to_provider_rule(rule) {
                Ok(Some(rule)) => Some(rule),
                Ok(None) => self.skip(rule, "unsupported rule-provider rule type"),
                Err(err) => self.skip(rule, err.to_string()),
            }
        } else if parse_prefix(rule).is_ok() {
            let kind = if rule.contains(':') {
                "IP-CIDR6"
            } else {
                "IP-CIDR"
            };
            Some(format!("{kind},{rule}"))
        } else {
            Some(format!("DOMAIN,{rule}"))
        }
    }

    fn skip(&mut self, rule: &str, reason: impl Into<String>) -> Option<String> {
        self.skipped.push(SkippedRule::new(rule, reason));
        None
    }
}
