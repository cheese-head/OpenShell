// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OVS/OpenFlow programming boundary for sandbox-owned flows.

use thiserror::Error;

use crate::command::{CommandError, CommandRunner, CommandSpec, SystemCommandRunner};
use crate::network::{OvsOfctlCommand, StampedFlow, add_flow_command, delete_exact_cookie_command};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxFlowPlan {
    pub sandbox_id: String,
    pub bridge: String,
    pub flows: Vec<StampedFlow>,
}

#[derive(Debug, Error)]
pub enum FlowProgrammerError {
    #[error("sandbox id is required")]
    MissingSandboxId,
    #[error("OVS bridge is required")]
    MissingBridge,
}

#[derive(Debug, Error)]
pub enum OvsExecutionError {
    #[error("{0}")]
    Command(#[from] CommandError),
}

pub trait FlowProgrammer: std::fmt::Debug + Send + Sync + 'static {
    fn install_commands(
        &self,
        plan: &SandboxFlowPlan,
    ) -> Result<Vec<OvsOfctlCommand>, FlowProgrammerError>;

    fn delete_cookie_command(
        &self,
        bridge: &str,
        cookie: u64,
    ) -> Result<OvsOfctlCommand, FlowProgrammerError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OvsFlowProgrammer;

impl FlowProgrammer for OvsFlowProgrammer {
    fn install_commands(
        &self,
        plan: &SandboxFlowPlan,
    ) -> Result<Vec<OvsOfctlCommand>, FlowProgrammerError> {
        validate_plan(plan)?;
        Ok(plan
            .flows
            .iter()
            .map(|flow| add_flow_command(plan.bridge.clone(), flow))
            .collect())
    }

    fn delete_cookie_command(
        &self,
        bridge: &str,
        cookie: u64,
    ) -> Result<OvsOfctlCommand, FlowProgrammerError> {
        validate_bridge(bridge)?;
        Ok(delete_exact_cookie_command(bridge, cookie))
    }
}

#[derive(Debug, Clone)]
pub struct OvsOfctlExecutor<R = SystemCommandRunner> {
    program: String,
    runner: R,
}

impl OvsOfctlExecutor<SystemCommandRunner> {
    pub fn system() -> Self {
        Self::new(SystemCommandRunner)
    }
}

impl<R> OvsOfctlExecutor<R>
where
    R: CommandRunner,
{
    pub fn new(runner: R) -> Self {
        Self {
            program: "ovs-ofctl".to_string(),
            runner,
        }
    }

    #[must_use]
    pub fn with_program(mut self, program: impl Into<String>) -> Self {
        self.program = program.into();
        self
    }

    pub fn execute(&self, command: &OvsOfctlCommand) -> Result<(), OvsExecutionError> {
        self.runner
            .run(&CommandSpec::new(
                self.program.clone(),
                command.args().iter().cloned(),
            ))
            .map(|_| ())
            .map_err(OvsExecutionError::from)
    }

    pub fn execute_all<'a>(
        &self,
        commands: impl IntoIterator<Item = &'a OvsOfctlCommand>,
    ) -> Result<(), OvsExecutionError> {
        for command in commands {
            self.execute(command)?;
        }
        Ok(())
    }
}

fn validate_plan(plan: &SandboxFlowPlan) -> Result<(), FlowProgrammerError> {
    if plan.sandbox_id.trim().is_empty() {
        return Err(FlowProgrammerError::MissingSandboxId);
    }
    validate_bridge(&plan.bridge)
}

fn validate_bridge(bridge: &str) -> Result<(), FlowProgrammerError> {
    if bridge.trim().is_empty() {
        return Err(FlowProgrammerError::MissingBridge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use crate::command::{CommandResult, CommandSpec};
    use crate::network::{
        Action, FlowKind, FlowOwnerPolicy, FlowSpec, Match, OPENSHELL_TABLE_ADMISSION,
        flow_id_from_str,
    };

    use super::*;

    #[derive(Debug, Clone, Default)]
    struct RecordingRunner {
        commands: Arc<Mutex<Vec<CommandSpec>>>,
    }

    impl CommandRunner for RecordingRunner {
        fn run(&self, spec: &CommandSpec) -> Result<CommandResult, CommandError> {
            self.commands.lock().unwrap().push(spec.clone());
            Ok(CommandResult {
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn ovs_executor_runs_planned_commands() {
        let policy = FlowOwnerPolicy::default();
        let flow = policy
            .stamp(
                &FlowSpec::new(
                    FlowKind::Endpoint,
                    flow_id_from_str("sandbox-1"),
                    OPENSHELL_TABLE_ADMISSION,
                    100,
                )
                .add_match(Match::InPort("pf0vf0".to_string()))
                .add_action(Action::Drop),
            )
            .unwrap();
        let command = add_flow_command("br-openshell", &flow);
        let runner = RecordingRunner::default();
        let seen = runner.commands.clone();
        let executor = OvsOfctlExecutor::new(runner).with_program("test-ovs-ofctl");

        executor.execute(&command).unwrap();

        let commands = seen.lock().unwrap();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].program, "test-ovs-ofctl");
        assert_eq!(commands[0].args[2], "add-flow");
        assert_eq!(commands[0].args[3], "br-openshell");
    }
}
