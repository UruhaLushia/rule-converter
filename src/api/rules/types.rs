use std::path::PathBuf;

use crate::RuleTarget;
use crate::codec::sing_box::RuleStore;
use crate::input::InputFormat;
use crate::output::{OutputFormat, RuleSetOutput};
use crate::rules::{BehaviorMode, InputBehaviorMode, RuleTextStore};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConvertOptions {
    pub input_target: Option<RuleTarget>,
    pub input_format: Option<InputFormat>,
    pub input_behavior: InputBehaviorMode,
    pub output_target: RuleTarget,
    pub output_format: OutputFormat,
    pub output_behavior: BehaviorMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileInput {
    pub path: PathBuf,
    pub target: Option<RuleTarget>,
    pub format: Option<InputFormat>,
    pub behavior: InputBehaviorMode,
}

impl FileInput {
    pub fn path(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            target: None,
            format: None,
            behavior: InputBehaviorMode::Auto,
        }
    }
}

impl Default for ConvertOptions {
    fn default() -> Self {
        Self {
            input_target: None,
            input_format: None,
            input_behavior: InputBehaviorMode::Auto,
            output_target: RuleTarget::Mihomo,
            output_format: OutputFormat::Mrs,
            output_behavior: BehaviorMode::Auto,
        }
    }
}

pub struct ConvertResult {
    pub outputs: Vec<RuleSetOutput>,
    pub mixed_rules: RuleTextStore,
    pub sing_box_rules: Option<RuleStore>,
    pub output_behavior: BehaviorMode,
    pub no_resolve: bool,
    pub skipped: Vec<SkippedRule>,
}

impl ConvertResult {
    pub fn is_empty(&self) -> bool {
        self.outputs.is_empty()
            && self.mixed_rules.is_empty()
            && self.sing_box_rules.as_ref().is_none_or(RuleStore::is_empty)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkippedRule {
    pub rule: String,
    pub reason: String,
}

impl SkippedRule {
    pub fn new(rule: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            rule: rule.into(),
            reason: reason.into(),
        }
    }
}
