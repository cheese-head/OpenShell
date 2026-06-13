// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Execution of rendered OVS flows via `ovs-ofctl`.
//!
//! The [`ovs`](super) module builds flow *argument strings*; this module
//! turns them into side effects on a real switch. It is abstracted behind
//! [`OvsRunner`] so the controller can be exercised in tests (and on hosts
//! without OVS) against a recording double, while production wires the real
//! [`OvsOfctlRunner`].
//!
//! Flows are applied as an atomic bundle (`--bundle`) so a partial failure
//! never leaves a sandbox half-admitted, and deletions are cookie-scoped so
//! cleanup only ever removes OpenShell-owned flows.

use core::fmt;
use std::process::Stdio;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// Error surface for OVS command execution.
#[derive(Debug, Clone)]
pub enum OvsError {
    /// The `ovs-ofctl` binary could not be spawned (missing / not on PATH).
    Spawn(String),
    /// `ovs-ofctl` ran but exited non-zero.
    CommandFailed {
        command: String,
        code: Option<i32>,
        stderr: String,
    },
    /// Failed to write the flow bundle to the child's stdin.
    Io(String),
}

impl fmt::Display for OvsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(m) => write!(f, "failed to spawn ovs-ofctl: {m}"),
            Self::CommandFailed {
                command,
                code,
                stderr,
            } => write!(
                f,
                "ovs-ofctl {command} failed (code {code:?}): {}",
                stderr.trim()
            ),
            Self::Io(m) => write!(f, "ovs-ofctl io error: {m}"),
        }
    }
}

impl std::error::Error for OvsError {}

pub type OvsResult<T> = Result<T, OvsError>;

/// Applies and removes rendered OVS flows for a bridge.
#[tonic::async_trait]
pub trait OvsRunner: fmt::Debug + Send + Sync {
    /// Atomically add a batch of rendered `add-flow` argument strings to
    /// `bridge`. A no-op when `flows` is empty.
    async fn add_flows(&self, bridge: &str, flows: &[String]) -> OvsResult<()>;

    /// Delete every flow on `bridge` whose cookie matches `cookie & mask`.
    /// Use [`super::super::openflow::exact_mask`] for per-flow deletion or
    /// [`super::super::openflow::kind_mask`] to clear a whole family.
    async fn del_flows_by_cookie(&self, bridge: &str, cookie: u64, mask: u64) -> OvsResult<()>;
}

/// Production runner that shells out to `ovs-ofctl`.
#[derive(Debug, Clone)]
pub struct OvsOfctlRunner {
    ofctl: String,
}

impl OvsOfctlRunner {
    #[must_use]
    pub fn new(ofctl: impl Into<String>) -> Self {
        Self {
            ofctl: ofctl.into(),
        }
    }
}

impl Default for OvsOfctlRunner {
    fn default() -> Self {
        Self::new("ovs-ofctl")
    }
}

impl OvsOfctlRunner {
    async fn run(&self, args: &[&str], stdin: Option<&str>) -> OvsResult<()> {
        let mut cmd = Command::new(&self.ofctl);
        cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
        if stdin.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| OvsError::Spawn(format!("{} {}: {e}", self.ofctl, args.join(" "))))?;

        if let Some(payload) = stdin {
            let mut sink = child
                .stdin
                .take()
                .ok_or_else(|| OvsError::Io("child stdin unavailable".to_string()))?;
            sink.write_all(payload.as_bytes())
                .await
                .map_err(|e| OvsError::Io(e.to_string()))?;
            // Drop closes stdin so ovs-ofctl sees EOF and proceeds.
            drop(sink);
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| OvsError::Io(e.to_string()))?;

        if output.status.success() {
            Ok(())
        } else {
            Err(OvsError::CommandFailed {
                command: args.join(" "),
                code: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            })
        }
    }
}

#[tonic::async_trait]
impl OvsRunner for OvsOfctlRunner {
    async fn add_flows(&self, bridge: &str, flows: &[String]) -> OvsResult<()> {
        if flows.is_empty() {
            return Ok(());
        }
        // `add-flows <bridge> -` reads newline-separated flows from stdin;
        // `--bundle` makes the batch atomic (all-or-nothing).
        let payload = {
            let mut s = flows.join("\n");
            s.push('\n');
            s
        };
        self.run(&["--bundle", "add-flows", bridge, "-"], Some(&payload))
            .await
    }

    async fn del_flows_by_cookie(&self, bridge: &str, cookie: u64, mask: u64) -> OvsResult<()> {
        let spec = format!("cookie=0x{cookie:016x}/0x{mask:016x}");
        self.run(&["del-flows", bridge, &spec], None).await
    }
}

/// Runner that logs intended actions without touching a switch. Useful on
/// hosts/containers where OVS is absent (e.g. CI) and as a safe default for
/// dry-run topologies.
#[derive(Debug, Clone, Default)]
pub struct NoopRunner;

#[tonic::async_trait]
impl OvsRunner for NoopRunner {
    async fn add_flows(&self, bridge: &str, flows: &[String]) -> OvsResult<()> {
        tracing::info!(bridge, count = flows.len(), "ovs noop runner: add_flows");
        Ok(())
    }

    async fn del_flows_by_cookie(&self, bridge: &str, cookie: u64, mask: u64) -> OvsResult<()> {
        tracing::info!(
            bridge,
            cookie = format!("0x{cookie:016x}"),
            mask = format!("0x{mask:016x}"),
            "ovs noop runner: del_flows_by_cookie"
        );
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Records every call so controller behavior can be asserted without OVS.
    /// `pub` is capped to crate visibility by the `pub(crate)` module.
    #[derive(Debug, Default)]
    pub struct RecordingRunner {
        pub added: Mutex<Vec<(String, Vec<String>)>>,
        pub deleted: Mutex<Vec<(String, u64, u64)>>,
    }

    #[tonic::async_trait]
    impl OvsRunner for RecordingRunner {
        async fn add_flows(&self, bridge: &str, flows: &[String]) -> OvsResult<()> {
            self.added
                .lock()
                .unwrap()
                .push((bridge.to_string(), flows.to_vec()));
            Ok(())
        }

        async fn del_flows_by_cookie(&self, bridge: &str, cookie: u64, mask: u64) -> OvsResult<()> {
            self.deleted
                .lock()
                .unwrap()
                .push((bridge.to_string(), cookie, mask));
            Ok(())
        }
    }

    #[tokio::test]
    async fn noop_runner_is_inert() {
        let r = NoopRunner;
        r.add_flows("br-openshell", &["x".to_string()])
            .await
            .unwrap();
        r.del_flows_by_cookie("br-openshell", 0x1, u64::MAX)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn recording_runner_captures_calls() {
        let r = RecordingRunner::default();
        r.add_flows("br0", &["a".to_string(), "b".to_string()])
            .await
            .unwrap();
        r.del_flows_by_cookie("br0", 0xff, u64::MAX).await.unwrap();
        assert_eq!(r.added.lock().unwrap().len(), 1);
        assert_eq!(r.added.lock().unwrap()[0].1.len(), 2);
        assert_eq!(r.deleted.lock().unwrap()[0].1, 0xff);
    }

    #[tokio::test]
    async fn ofctl_runner_add_flows_empty_is_noop() {
        // No binary is invoked when there are no flows, so this never spawns.
        let r = OvsOfctlRunner::new("/nonexistent/ovs-ofctl");
        r.add_flows("br0", &[]).await.unwrap();
    }

    #[tokio::test]
    async fn ofctl_runner_reports_spawn_failure() {
        let r = OvsOfctlRunner::new("/nonexistent/ovs-ofctl");
        let err = r
            .add_flows("br0", &["cookie=0x1,actions=drop".to_string()])
            .await
            .unwrap_err();
        assert!(matches!(err, OvsError::Spawn(_)));
    }
}
