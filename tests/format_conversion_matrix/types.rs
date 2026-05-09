use rule_converter::{BehaviorMode, InputBehaviorMode, InputFormat, OutputFormat, RuleTarget};

#[derive(Clone)]
pub(super) struct InputCase {
    pub(super) from: &'static str,
    pub(super) target: RuleTarget,
    pub(super) format: InputFormat,
    pub(super) behavior: InputBehaviorMode,
    pub(super) kind: RuleKind,
    pub(super) payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RuleKind {
    Domain,
    Ip,
    Classical,
}

#[derive(Clone, Copy)]
pub(super) struct OutputCase {
    pub(super) name: &'static str,
    pub(super) to: &'static str,
    pub(super) target: RuleTarget,
    pub(super) format: OutputFormat,
    pub(super) behavior: BehaviorMode,
    pub(super) accepts: fn(RuleKind) -> bool,
}
