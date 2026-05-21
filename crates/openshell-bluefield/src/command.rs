// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Command execution boundary for privileged host operations.

use std::process::{Command, Output};

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
}

impl CommandSpec {
    pub fn new(
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("failed to execute {program}: {source}")]
    Spawn {
        program: String,
        source: std::io::Error,
    },
    #[error("{program} exited with status {status}: {stderr}")]
    Failed {
        program: String,
        status: String,
        stderr: String,
    },
    #[error("{stream} from {program} was not valid UTF-8: {source}")]
    Utf8 {
        program: String,
        stream: &'static str,
        source: std::string::FromUtf8Error,
    },
}

pub trait CommandRunner: std::fmt::Debug + Send + Sync + 'static {
    fn run(&self, spec: &CommandSpec) -> Result<CommandResult, CommandError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, spec: &CommandSpec) -> Result<CommandResult, CommandError> {
        let output = Command::new(&spec.program)
            .args(&spec.args)
            .output()
            .map_err(|source| CommandError::Spawn {
                program: spec.program.clone(),
                source,
            })?;
        command_result(&spec.program, output)
    }
}

fn command_result(program: &str, output: Output) -> Result<CommandResult, CommandError> {
    let stdout = String::from_utf8(output.stdout).map_err(|source| CommandError::Utf8 {
        program: program.to_string(),
        stream: "stdout",
        source,
    })?;
    let stderr = String::from_utf8(output.stderr).map_err(|source| CommandError::Utf8 {
        program: program.to_string(),
        stream: "stderr",
        source,
    })?;
    if !output.status.success() {
        return Err(CommandError::Failed {
            program: program.to_string(),
            status: output.status.to_string(),
            stderr,
        });
    }
    Ok(CommandResult { stdout, stderr })
}
