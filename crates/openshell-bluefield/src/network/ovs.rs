// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OVS` command planning helpers.
//!
//! This module intentionally does not execute `ovs-ofctl`. It returns the
//! exact argument vector a privileged caller can execute, log, test, or hand to
//! an `OVS` control component.

use crate::network::policy::StampedFlow;

const OPENFLOW_VERSION: &str = "OpenFlow13";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OvsOfctlCommand {
    args: Vec<String>,
}

impl OvsOfctlCommand {
    fn new(args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    pub fn into_args(self) -> Vec<String> {
        self.args
    }
}

pub fn add_flow_command(bridge: impl Into<String>, flow: &StampedFlow) -> OvsOfctlCommand {
    OvsOfctlCommand::new([
        "-O".to_string(),
        OPENFLOW_VERSION.to_string(),
        "add-flow".to_string(),
        bridge.into(),
        flow.as_ovs_arg().to_string(),
    ])
}

pub fn delete_exact_cookie_command(bridge: impl Into<String>, cookie: u64) -> OvsOfctlCommand {
    OvsOfctlCommand::new([
        "-O".to_string(),
        OPENFLOW_VERSION.to_string(),
        "del-flows".to_string(),
        bridge.into(),
        format!("cookie=0x{cookie:016x}/-1"),
    ])
}

#[cfg(test)]
mod tests {
    use crate::network::{
        Action, FlowKind, FlowOwnerPolicy, FlowSpec, Match, OPENSHELL_TABLE_ADMISSION,
        flow_id_from_str,
    };

    use super::*;

    #[test]
    fn add_flow_command_wraps_stamped_flow() {
        let policy = FlowOwnerPolicy::default();
        let flow = policy
            .stamp(
                &FlowSpec::new(
                    FlowKind::Endpoint,
                    flow_id_from_str("sandbox-1"),
                    OPENSHELL_TABLE_ADMISSION,
                    100,
                )
                .add_match(Match::InPort("pf0vf1".to_string()))
                .add_action(Action::Drop),
            )
            .unwrap();

        let command = add_flow_command("br-openshell", &flow);

        assert_eq!(command.args()[0], "-O");
        assert_eq!(command.args()[1], "OpenFlow13");
        assert_eq!(command.args()[2], "add-flow");
        assert_eq!(command.args()[3], "br-openshell");
        assert!(command.args()[4].contains("cookie=0x0f050001"));
    }

    #[test]
    fn delete_exact_cookie_command_scopes_by_full_cookie() {
        let command = delete_exact_cookie_command("br-openshell", 0x0f05_0001_dead_beef);

        assert_eq!(
            command.into_args(),
            vec![
                "-O",
                "OpenFlow13",
                "del-flows",
                "br-openshell",
                "cookie=0x0f050001deadbeef/-1",
            ]
        );
    }
}
