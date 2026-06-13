// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Neutral, backend-portable flow program IR.

use std::collections::BTreeSet;

use core::fmt;
use core::net::Ipv4Addr;
use core::str::FromStr;

use crate::cookie::FlowKind;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FlowProgram {
    pub stages: Vec<Stage>,
}

impl FlowProgram {
    #[must_use]
    pub fn new() -> Self {
        Self { stages: Vec::new() }
    }

    #[must_use]
    pub fn stage(mut self, stage: Stage) -> Self {
        self.stages.push(stage);
        self
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stages.iter().all(|stage| stage.rules.is_empty())
    }

    #[must_use]
    pub fn handles(&self) -> Vec<FlowHandle> {
        self.stages
            .iter()
            .flat_map(|stage| stage.rules.iter().map(|rule| rule.handle))
            .collect()
    }

    /// Validate the program against the neutral backend contract.
    ///
    /// This is intentionally protocol-agnostic: it catches IR shapes that no
    /// backend should be asked to interpret, while leaving protocol-specific
    /// constraints to concrete backend modules.
    pub fn validate_portable(&self) -> Result<(), FlowProgramError> {
        let stages = self
            .stages
            .iter()
            .map(|stage| stage.kind)
            .collect::<BTreeSet<_>>();
        for stage in &self.stages {
            for rule in &stage.rules {
                if rule.actions.is_empty() {
                    return Err(FlowProgramError::EmptyActions {
                        stage: stage.kind,
                        handle: rule.handle,
                    });
                }
                for action in &rule.actions {
                    if let Action::Goto(target) = action
                        && !stages.contains(target)
                    {
                        return Err(FlowProgramError::MissingGotoTarget {
                            from: stage.kind,
                            target: *target,
                            handle: rule.handle,
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowProgramError {
    EmptyActions {
        stage: StageKind,
        handle: FlowHandle,
    },
    MissingGotoTarget {
        from: StageKind,
        target: StageKind,
        handle: FlowHandle,
    },
}

impl fmt::Display for FlowProgramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyActions { stage, handle } => {
                write!(f, "flow rule {handle:?} in stage {stage} has no actions")
            }
            Self::MissingGotoTarget {
                from,
                target,
                handle,
            } => write!(
                f,
                "flow rule {handle:?} in stage {from} jumps to missing stage {target}"
            ),
        }
    }
}

impl std::error::Error for FlowProgramError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage {
    pub kind: StageKind,
    pub rules: Vec<Rule>,
}

impl Stage {
    #[must_use]
    pub fn new(kind: StageKind) -> Self {
        Self {
            kind,
            rules: Vec::new(),
        }
    }

    #[must_use]
    pub fn rule(mut self, rule: Rule) -> Self {
        self.rules.push(rule);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StageKind {
    Classify,
    Admission,
    Firewall,
    Forward,
    Return,
}

impl fmt::Display for StageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Classify => f.write_str("classify"),
            Self::Admission => f.write_str("admission"),
            Self::Firewall => f.write_str("firewall"),
            Self::Forward => f.write_str("forward"),
            Self::Return => f.write_str("return"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowHandle {
    pub kind: FlowKind,
    pub flow_id: u32,
}

impl FlowHandle {
    #[must_use]
    pub fn new(kind: FlowKind, flow_id: u32) -> Self {
        Self { kind, flow_id }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub handle: FlowHandle,
    pub priority: u16,
    pub matches: Vec<Match>,
    pub actions: Vec<Action>,
}

impl Rule {
    #[must_use]
    pub fn new(handle: FlowHandle, priority: u16) -> Self {
        Self {
            handle,
            priority,
            matches: Vec::new(),
            actions: Vec::new(),
        }
    }

    #[must_use]
    pub fn match_(mut self, m: Match) -> Self {
        self.matches.push(m);
        self
    }

    #[must_use]
    pub fn action(mut self, action: Action) -> Self {
        self.actions.push(action);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Match {
    InPort(Port),
    EtherType(EtherType),
    ArpTpa(Ipv4Addr),
    ArpOp(u16),
    Ipv4Src(Ipv4Addr),
    Ipv4Dst(Ipv4Addr),
    TcpDst(u16),
    CtState(CtState),
    CtZone(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Arp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtState {
    NewTracked,
    EstablishedTracked,
}

impl CtState {
    #[must_use]
    pub fn to_ovs(self) -> String {
        match self {
            Self::NewTracked => "+new+trk".to_string(),
            Self::EstablishedTracked => "+est+trk".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Drop,
    Forward(Port),
    Hairpin,
    Goto(StageKind),
    Ct(CtIntent),
    SetEthernetSource(MacAddress),
    SetEthernetDestination(MacAddress),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtIntent {
    pub commit: bool,
    pub zone: u16,
    pub goto: Option<StageKind>,
    pub nat: Option<CtNat>,
}

impl CtIntent {
    #[must_use]
    pub fn track(zone: u16, goto: StageKind) -> Self {
        Self {
            commit: false,
            zone,
            goto: Some(goto),
            nat: None,
        }
    }

    #[must_use]
    pub fn track_nat(zone: u16, goto: StageKind) -> Self {
        Self {
            commit: false,
            zone,
            goto: Some(goto),
            nat: Some(CtNat::Existing),
        }
    }

    #[must_use]
    pub fn commit_snat(zone: u16, snat_to: Ipv4Addr) -> Self {
        Self {
            commit: true,
            zone,
            goto: None,
            nat: Some(CtNat::Source(snat_to)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtNat {
    Existing,
    Source(Ipv4Addr),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Port {
    pub name: String,
}

impl Port {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddress(String);

impl MacAddress {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for MacAddress {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = value.trim().split(':').collect();
        if parts.len() != 6 {
            return Err(format!("invalid MAC address {value:?}: expected 6 octets"));
        }
        let mut normalized = Vec::with_capacity(6);
        for part in parts {
            if part.len() != 2 || !part.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!(
                    "invalid MAC address {value:?}: octets must be two hex digits"
                ));
            }
            normalized.push(part.to_ascii_lowercase());
        }
        Ok(Self(normalized.join(":")))
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_validation_accepts_complete_program() {
        let program = FlowProgram::new()
            .stage(
                Stage::new(StageKind::Classify).rule(
                    Rule::new(FlowHandle::new(FlowKind::Endpoint, 7), 240)
                        .match_(Match::InPort(Port::new("pf0vf0")))
                        .action(Action::Goto(StageKind::Admission)),
                ),
            )
            .stage(
                Stage::new(StageKind::Admission).rule(
                    Rule::new(FlowHandle::new(FlowKind::Endpoint, 7), 100)
                        .match_(Match::EtherType(EtherType::Ipv4))
                        .action(Action::Forward(Port::new("osuplink"))),
                ),
            );

        program.validate_portable().unwrap();
    }

    #[test]
    fn portable_validation_rejects_empty_actions() {
        let program = FlowProgram::new().stage(
            Stage::new(StageKind::Admission)
                .rule(Rule::new(FlowHandle::new(FlowKind::Endpoint, 7), 100)),
        );
        assert!(matches!(
            program.validate_portable().unwrap_err(),
            FlowProgramError::EmptyActions { .. }
        ));
    }

    #[test]
    fn portable_validation_rejects_missing_goto_target() {
        let program = FlowProgram::new().stage(
            Stage::new(StageKind::Classify).rule(
                Rule::new(FlowHandle::new(FlowKind::Endpoint, 7), 240)
                    .action(Action::Goto(StageKind::Admission)),
            ),
        );
        assert!(matches!(
            program.validate_portable().unwrap_err(),
            FlowProgramError::MissingGotoTarget { .. }
        ));
    }
}
