// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenFlow`/OVS backend for [`crate::FlowProgram`].
//!
//! `OpenFlow`-only escape hatches such as raw NXM moves, table numbers, and
//! `resubmit` live here. Callers above the backend boundary should build the
//! neutral IR from [`crate::program`].

pub mod render;
pub mod spec;

use crate::program as neutral;

pub use crate::cookie::{
    FlowKind, OPENSHELL_OWNER_PREFIX, cookie, exact_mask, flow_id_from_str, kind_mask,
};
pub use render::render;
pub use spec::{Action, CtAction, FlowSpec, MacAddress, Match};

/// Maps neutral stage names onto concrete `OpenFlow` table ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TableMap {
    pub classify: u8,
    pub admission: u8,
    pub firewall: u8,
    pub forward: u8,
    pub return_: u8,
}

impl Default for TableMap {
    fn default() -> Self {
        Self {
            classify: 0,
            admission: 100,
            firewall: 105,
            forward: 110,
            return_: 115,
        }
    }
}

impl TableMap {
    #[must_use]
    pub fn table(self, stage: neutral::StageKind) -> u8 {
        match stage {
            neutral::StageKind::Classify => self.classify,
            neutral::StageKind::Admission => self.admission,
            neutral::StageKind::Firewall => self.firewall,
            neutral::StageKind::Forward => self.forward,
            neutral::StageKind::Return => self.return_,
        }
    }
}

/// Render a neutral flow program to `ovs-ofctl add-flow` argument strings.
#[must_use]
pub fn render_program(program: &neutral::FlowProgram, tables: TableMap) -> Vec<String> {
    let mut rendered = Vec::new();
    for stage in &program.stages {
        for rule in &stage.rules {
            let mut spec = FlowSpec::new(
                rule.handle.kind,
                rule.handle.flow_id,
                tables.table(stage.kind),
                rule.priority,
            );
            for m in &rule.matches {
                spec = apply_match(spec, m);
            }
            for a in &rule.actions {
                spec = apply_action(spec, a, tables);
            }
            rendered.push(render(&spec));
        }
    }
    rendered
}

fn apply_match(mut spec: FlowSpec, m: &neutral::Match) -> FlowSpec {
    match m {
        neutral::Match::InPort(port) => spec = spec.match_(Match::InPort(port.name.clone())),
        neutral::Match::EtherType(neutral::EtherType::Ipv4) => spec = spec.match_(Match::Ip),
        neutral::Match::EtherType(neutral::EtherType::Arp) => spec = spec.match_(Match::Arp),
        neutral::Match::ArpTpa(ip) => spec = spec.match_(Match::ArpTpa(*ip)),
        neutral::Match::ArpOp(op) => spec = spec.match_(Match::ArpOp(*op)),
        neutral::Match::Ipv4Src(ip) => spec = spec.match_(Match::NwSrc(*ip)),
        neutral::Match::Ipv4Dst(ip) => spec = spec.match_(Match::NwDst(*ip)),
        neutral::Match::TcpDst(port) => {
            spec = spec.match_(Match::Tcp).match_(Match::TpDst(*port));
        }
        neutral::Match::CtState(state) => spec = spec.match_(Match::CtState(state.to_ovs())),
        neutral::Match::CtZone(zone) => spec = spec.match_(Match::CtZone(*zone)),
    }
    spec
}

fn apply_action(mut spec: FlowSpec, a: &neutral::Action, tables: TableMap) -> FlowSpec {
    match a {
        neutral::Action::Drop => spec = spec.action(Action::Drop),
        neutral::Action::Forward(port) => spec = spec.action(Action::Output(port.name.clone())),
        neutral::Action::Hairpin => spec = spec.action(Action::InPort),
        neutral::Action::Goto(stage) => spec = spec.action(Action::Resubmit(tables.table(*stage))),
        neutral::Action::Ct(intent) => spec = spec.action(Action::Ct(ct_action(intent, tables))),
        neutral::Action::SetEthernetSource(mac) => {
            spec = spec.action(Action::SetEthSrc(
                mac.to_string().parse().expect("valid mac"),
            ));
        }
        neutral::Action::SetEthernetDestination(mac) => {
            spec = spec.action(Action::SetEthDst(
                mac.to_string().parse().expect("valid mac"),
            ));
        }
    }
    spec
}

fn ct_action(intent: &neutral::CtIntent, tables: TableMap) -> CtAction {
    CtAction {
        commit: intent.commit,
        table: intent.goto.map(|stage| tables.table(stage)),
        zone: Some(intent.zone),
        nat: matches!(intent.nat, Some(neutral::CtNat::Existing)),
        snat_to: match intent.nat {
            Some(neutral::CtNat::Source(ip)) => Some(ip),
            _ => None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FlowHandle, FlowKind, FlowProgram, Port, Rule, Stage, StageKind};

    #[test]
    fn renders_neutral_program_to_openflow_tables() {
        let program = FlowProgram::new().stage(
            Stage::new(StageKind::Classify).rule(
                Rule::new(FlowHandle::new(FlowKind::Endpoint, 7), 240)
                    .match_(neutral::Match::InPort(Port::new("pf0vf0")))
                    .action(neutral::Action::Goto(StageKind::Admission)),
            ),
        );

        let rendered = render_program(&program, TableMap::default());
        assert_eq!(rendered.len(), 1);
        assert!(rendered[0].contains("table=0"));
        assert!(rendered[0].contains("in_port=pf0vf0"));
        assert!(rendered[0].ends_with("actions=resubmit(,100)"));
    }
}
