use crate::RuleTarget;

use super::{BehaviorMode, InputBehaviorMode};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConversionMode {
    AutoGeneric,
    AutoMihomo,
    DomainSet,
    DomainMihomo,
    Ipcidr,
    ClassicalOutput,
    ClassicalAuto,
    SingBoxAuto(DomainSyntax),
    SingBoxDomain(DomainSyntax),
    SingBoxIpcidr,
}

impl ConversionMode {
    pub(crate) fn from_output_behavior(output_behavior: BehaviorMode) -> Self {
        match output_behavior {
            BehaviorMode::Auto => Self::AutoGeneric,
            BehaviorMode::Domain => Self::DomainSet,
            BehaviorMode::Ipcidr => Self::Ipcidr,
            BehaviorMode::Classical => Self::ClassicalOutput,
        }
    }

    pub(crate) fn from_input_output(
        input_behavior: InputBehaviorMode,
        input_target: RuleTarget,
        output_behavior: BehaviorMode,
    ) -> Self {
        let domain = if matches!(input_target, RuleTarget::Mihomo | RuleTarget::SingBox) {
            Self::DomainMihomo
        } else {
            Self::DomainSet
        };
        let auto = if matches!(input_target, RuleTarget::Mihomo | RuleTarget::SingBox) {
            Self::AutoMihomo
        } else {
            Self::AutoGeneric
        };

        match output_behavior {
            BehaviorMode::Domain => domain,
            BehaviorMode::Ipcidr => Self::Ipcidr,
            BehaviorMode::Classical => Self::ClassicalOutput,
            BehaviorMode::Auto => match input_behavior {
                InputBehaviorMode::Auto => auto,
                InputBehaviorMode::Domain => domain,
                InputBehaviorMode::Ipcidr => Self::Ipcidr,
                InputBehaviorMode::Classical => Self::ClassicalAuto,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DomainSyntax {
    Generic,
    Mihomo,
}
