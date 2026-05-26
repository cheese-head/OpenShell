// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use openshell_core::proto::compute::v1::DriverSandbox as Sandbox;

use crate::runtime::{AllocatedPciDevice, VmBackend};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchAbortReason {
    LauncherSpawnFailed,
    BeforeLaunchHookFailed,
}

#[derive(Debug, Clone)]
pub struct VmLifecycleError {
    message: String,
    resource_exhausted: bool,
}

impl VmLifecycleError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            resource_exhausted: false,
        }
    }

    pub fn resource_exhausted(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            resource_exhausted: true,
        }
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub fn is_resource_exhausted(&self) -> bool {
        self.resource_exhausted
    }
}

impl std::fmt::Display for VmLifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for VmLifecycleError {}

pub type VmLifecycleResult<T> = Result<T, VmLifecycleError>;

#[derive(Debug, Clone)]
pub struct VmPersistedSandbox {
    pub sandbox: Sandbox,
    pub state_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct VmLaunchPlan {
    pub backend: VmBackend,
    pub vcpus: u8,
    pub mem_mib: u32,
    pub gpu_bdf: Option<String>,
    pub tap_device: Option<String>,
    pub guest_ip: Option<String>,
    pub host_ip: Option<String>,
    pub vsock_cid: Option<u32>,
    pub guest_mac: Option<String>,
    pub gateway_port: Option<u16>,
    pub devices: Vec<AllocatedPciDevice>,
    pub env: Vec<String>,
}

#[tonic::async_trait]
pub trait VmLifecycleExtension: std::fmt::Debug + Send + Sync {
    fn name(&self) -> &str;

    fn required_backend(&self) -> Option<VmBackend> {
        None
    }

    async fn reconcile_before_restore(&self, _extension_state_dir: &Path) -> VmLifecycleResult<()> {
        Ok(())
    }

    async fn reconcile_after_restore(
        &self,
        _extension_state_dir: &Path,
        _sandboxes: &[VmPersistedSandbox],
    ) -> VmLifecycleResult<()> {
        Ok(())
    }

    async fn before_vm_launch(
        &self,
        _sandbox: &Sandbox,
        _state_dir: &Path,
        _plan: &mut VmLaunchPlan,
    ) -> VmLifecycleResult<()> {
        Ok(())
    }

    async fn after_vm_launch_failed(
        &self,
        _sandbox: &Sandbox,
        _state_dir: &Path,
        _reason: LaunchAbortReason,
    ) -> VmLifecycleResult<()> {
        Ok(())
    }

    async fn after_sandbox_deleted(
        &self,
        _sandbox: &Sandbox,
        _state_dir: &Path,
    ) -> VmLifecycleResult<()> {
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct VmLifecycleExtensions {
    extensions: Vec<Arc<dyn VmLifecycleExtension>>,
}

impl std::fmt::Debug for VmLifecycleExtensions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmLifecycleExtensions")
            .field(
                "names",
                &self
                    .extensions
                    .iter()
                    .map(|ext| ext.name())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl VmLifecycleExtensions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(extensions: Vec<Arc<dyn VmLifecycleExtension>>) -> Self {
        Self { extensions }
    }

    pub fn push(&mut self, extension: Arc<dyn VmLifecycleExtension>) {
        self.extensions.push(extension);
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.extensions.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.extensions.len()
    }

    #[must_use]
    pub fn requires_qemu(&self) -> bool {
        self.extensions
            .iter()
            .any(|ext| ext.required_backend() == Some(VmBackend::Qemu))
    }

    pub fn state_dirs(&self, root: &Path) -> VmLifecycleResult<Vec<(String, PathBuf)>> {
        let mut names = HashSet::new();
        let mut dirs = Vec::with_capacity(self.extensions.len());
        for ext in &self.extensions {
            let name = ext.name();
            if !names.insert(name.to_string()) {
                return Err(VmLifecycleError::new(format!(
                    "duplicate VM lifecycle extension name: {name}"
                )));
            }
            dirs.push((name.to_string(), extension_state_dir(root, name)?));
        }
        Ok(dirs)
    }

    pub async fn reconcile_before_restore(&self, root: &Path) -> VmLifecycleResult<()> {
        let state_dirs = self.state_dirs(root)?;
        for (ext, (_, state_dir)) in self.extensions.iter().zip(state_dirs.iter()) {
            if let Err(err) = ext.reconcile_before_restore(state_dir).await {
                return Err(VmLifecycleError::new(format!(
                    "{} reconcile_before_restore failed: {}",
                    ext.name(),
                    err.message()
                )));
            }
        }
        Ok(())
    }

    pub async fn reconcile_after_restore(
        &self,
        root: &Path,
        sandboxes: &[VmPersistedSandbox],
    ) -> VmLifecycleResult<()> {
        let state_dirs = self.state_dirs(root)?;
        for (ext, (_, state_dir)) in self.extensions.iter().zip(state_dirs.iter()) {
            if let Err(err) = ext.reconcile_after_restore(state_dir, sandboxes).await {
                return Err(VmLifecycleError::new(format!(
                    "{} reconcile_after_restore failed: {}",
                    ext.name(),
                    err.message()
                )));
            }
        }
        Ok(())
    }

    pub async fn before_vm_launch(
        &self,
        sandbox: &Sandbox,
        state_dir: &Path,
        plan: &mut VmLaunchPlan,
    ) -> VmLifecycleResult<()> {
        for ext in &self.extensions {
            ext.before_vm_launch(sandbox, state_dir, plan).await?;
        }
        Ok(())
    }

    pub async fn after_vm_launch_failed(
        &self,
        sandbox: &Sandbox,
        state_dir: &Path,
        reason: LaunchAbortReason,
    ) {
        for ext in &self.extensions {
            if let Err(err) = ext
                .after_vm_launch_failed(sandbox, state_dir, reason.clone())
                .await
            {
                tracing::warn!(
                    extension = ext.name(),
                    sandbox_id = %sandbox.id,
                    error = %err,
                    "vm driver: lifecycle extension after_vm_launch_failed hook failed"
                );
            }
        }
    }

    pub async fn after_sandbox_deleted(&self, sandbox: &Sandbox, state_dir: &Path) {
        for ext in &self.extensions {
            if let Err(err) = ext.after_sandbox_deleted(sandbox, state_dir).await {
                tracing::warn!(
                    extension = ext.name(),
                    sandbox_id = %sandbox.id,
                    error = %err,
                    "vm driver: lifecycle extension after_sandbox_deleted hook failed"
                );
            }
        }
    }
}

fn extension_state_dir(root: &Path, name: &str) -> VmLifecycleResult<PathBuf> {
    let valid = !name.is_empty()
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
    if !valid {
        return Err(VmLifecycleError::new(format!(
            "invalid VM lifecycle extension name: {name:?}"
        )));
    }
    Ok(root.join(name))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Mutex;

    use super::*;

    #[derive(Debug)]
    struct RecordingExtension {
        name: String,
        backend: Option<VmBackend>,
        before_should_fail: bool,
        reconcile_before_should_fail: bool,
        reconcile_after_should_fail: bool,
        calls: Mutex<Vec<String>>,
    }

    impl RecordingExtension {
        fn new(name: &str, backend: Option<VmBackend>) -> Arc<Self> {
            Arc::new(Self {
                name: name.to_string(),
                backend,
                before_should_fail: false,
                reconcile_before_should_fail: false,
                reconcile_after_should_fail: false,
                calls: Mutex::new(Vec::new()),
            })
        }

        fn failing(name: &str, backend: Option<VmBackend>) -> Arc<Self> {
            Arc::new(Self {
                name: name.to_string(),
                backend,
                before_should_fail: true,
                reconcile_before_should_fail: false,
                reconcile_after_should_fail: false,
                calls: Mutex::new(Vec::new()),
            })
        }

        fn failing_reconcile_before(name: &str) -> Arc<Self> {
            Arc::new(Self {
                name: name.to_string(),
                backend: None,
                before_should_fail: false,
                reconcile_before_should_fail: true,
                reconcile_after_should_fail: false,
                calls: Mutex::new(Vec::new()),
            })
        }

        fn failing_reconcile_after(name: &str) -> Arc<Self> {
            Arc::new(Self {
                name: name.to_string(),
                backend: None,
                before_should_fail: false,
                reconcile_before_should_fail: false,
                reconcile_after_should_fail: true,
                calls: Mutex::new(Vec::new()),
            })
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[tonic::async_trait]
    impl VmLifecycleExtension for RecordingExtension {
        fn name(&self) -> &str {
            &self.name
        }

        fn required_backend(&self) -> Option<VmBackend> {
            self.backend.clone()
        }

        async fn reconcile_before_restore(
            &self,
            extension_state_dir: &Path,
        ) -> VmLifecycleResult<()> {
            self.calls.lock().unwrap().push(format!(
                "{}:reconcile_before_restore:{}",
                self.name,
                extension_state_dir.file_name().unwrap().to_string_lossy()
            ));
            if self.reconcile_before_should_fail {
                return Err(VmLifecycleError::new(format!(
                    "{}: scripted reconcile_before_restore failure",
                    self.name
                )));
            }
            Ok(())
        }

        async fn reconcile_after_restore(
            &self,
            extension_state_dir: &Path,
            sandboxes: &[VmPersistedSandbox],
        ) -> VmLifecycleResult<()> {
            self.calls.lock().unwrap().push(format!(
                "{}:reconcile_after_restore:{}:{}",
                self.name,
                extension_state_dir.file_name().unwrap().to_string_lossy(),
                sandboxes.len()
            ));
            if self.reconcile_after_should_fail {
                return Err(VmLifecycleError::new(format!(
                    "{}: scripted reconcile_after_restore failure",
                    self.name
                )));
            }
            Ok(())
        }

        async fn before_vm_launch(
            &self,
            _sandbox: &Sandbox,
            _state_dir: &Path,
            plan: &mut VmLaunchPlan,
        ) -> VmLifecycleResult<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{}:before_vm_launch", self.name));
            if self.before_should_fail {
                return Err(VmLifecycleError::new(format!(
                    "{}: scripted before_vm_launch failure",
                    self.name
                )));
            }
            plan.env.push(format!("RECORDING_{}=1", self.name));
            Ok(())
        }

        async fn after_vm_launch_failed(
            &self,
            _sandbox: &Sandbox,
            _state_dir: &Path,
            reason: LaunchAbortReason,
        ) -> VmLifecycleResult<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{}:after_vm_launch_failed:{:?}", self.name, reason));
            Ok(())
        }

        async fn after_sandbox_deleted(
            &self,
            _sandbox: &Sandbox,
            _state_dir: &Path,
        ) -> VmLifecycleResult<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{}:after_sandbox_deleted", self.name));
            Ok(())
        }
    }

    fn sample_plan(backend: VmBackend) -> VmLaunchPlan {
        VmLaunchPlan {
            backend,
            vcpus: 2,
            mem_mib: 2048,
            gpu_bdf: None,
            tap_device: None,
            guest_ip: None,
            host_ip: None,
            vsock_cid: None,
            guest_mac: None,
            gateway_port: None,
            devices: Vec::new(),
            env: Vec::new(),
        }
    }

    fn sample_sandbox() -> Sandbox {
        Sandbox {
            id: "sandbox-123".to_string(),
            name: "sandbox-123".to_string(),
            ..Default::default()
        }
    }

    fn sample_persisted_sandbox() -> VmPersistedSandbox {
        VmPersistedSandbox {
            sandbox: sample_sandbox(),
            state_dir: PathBuf::from("/tmp/state/sandbox-123"),
        }
    }

    fn as_extension<T>(extension: &Arc<T>) -> Arc<dyn VmLifecycleExtension>
    where
        T: VmLifecycleExtension + 'static,
    {
        extension.clone()
    }

    #[test]
    fn empty_registry_does_not_require_qemu() {
        let registry = VmLifecycleExtensions::new();
        assert!(registry.is_empty());
        assert!(!registry.requires_qemu());
    }

    #[test]
    fn registry_requires_qemu_when_any_extension_declares_it() {
        let mut registry = VmLifecycleExtensions::new();
        registry.push(RecordingExtension::new("noop", None));
        registry.push(RecordingExtension::new("vfio", Some(VmBackend::Qemu)));
        assert!(registry.requires_qemu());
    }

    #[test]
    fn registry_does_not_require_qemu_when_no_extension_declares_it() {
        let mut registry = VmLifecycleExtensions::new();
        registry.push(RecordingExtension::new("noop1", None));
        registry.push(RecordingExtension::new("noop2", Some(VmBackend::Libkrun)));
        assert!(!registry.requires_qemu());
    }

    #[test]
    fn state_dirs_reject_duplicate_or_unsafe_extension_names() {
        let duplicate = VmLifecycleExtensions::with(vec![
            RecordingExtension::new("dup", None),
            RecordingExtension::new("dup", None),
        ]);
        assert!(duplicate.state_dirs(Path::new("/tmp/ext")).is_err());

        let unsafe_name =
            VmLifecycleExtensions::with(vec![RecordingExtension::new("../escape", None)]);
        assert!(unsafe_name.state_dirs(Path::new("/tmp/ext")).is_err());
    }

    #[tokio::test]
    async fn reconcile_before_restore_runs_each_extension_in_order() {
        let ext_a = RecordingExtension::new("a", None);
        let ext_b = RecordingExtension::new("b", None);
        let registry =
            VmLifecycleExtensions::with(vec![as_extension(&ext_a), as_extension(&ext_b)]);

        registry
            .reconcile_before_restore(Path::new("/tmp/extensions"))
            .await
            .expect("reconcile_before_restore succeeds");

        assert_eq!(ext_a.calls(), vec!["a:reconcile_before_restore:a"]);
        assert_eq!(ext_b.calls(), vec!["b:reconcile_before_restore:b"]);
    }

    #[tokio::test]
    async fn reconcile_after_restore_runs_each_extension_in_order() {
        let ext_a = RecordingExtension::new("a", None);
        let ext_b = RecordingExtension::new("b", None);
        let registry =
            VmLifecycleExtensions::with(vec![as_extension(&ext_a), as_extension(&ext_b)]);
        let persisted = vec![sample_persisted_sandbox()];

        registry
            .reconcile_after_restore(Path::new("/tmp/extensions"), &persisted)
            .await
            .expect("reconcile_after_restore succeeds");

        assert_eq!(ext_a.calls(), vec!["a:reconcile_after_restore:a:1"]);
        assert_eq!(ext_b.calls(), vec!["b:reconcile_after_restore:b:1"]);
    }

    #[tokio::test]
    async fn reconcile_restore_failures_short_circuit() {
        let ext_a = RecordingExtension::new("a", None);
        let ext_fail = RecordingExtension::failing_reconcile_before("boom");
        let ext_c = RecordingExtension::new("c", None);
        let registry = VmLifecycleExtensions::with(vec![
            as_extension(&ext_a),
            as_extension(&ext_fail),
            as_extension(&ext_c),
        ]);

        let err = registry
            .reconcile_before_restore(Path::new("/tmp/extensions"))
            .await
            .expect_err("scripted failure should propagate");

        assert!(err.message().contains("reconcile_before_restore failed"));
        assert_eq!(ext_a.calls(), vec!["a:reconcile_before_restore:a"]);
        assert_eq!(ext_fail.calls(), vec!["boom:reconcile_before_restore:boom"]);
        assert!(ext_c.calls().is_empty());
    }

    #[tokio::test]
    async fn reconcile_after_restore_failures_short_circuit() {
        let ext_a = RecordingExtension::new("a", None);
        let ext_fail = RecordingExtension::failing_reconcile_after("boom");
        let ext_c = RecordingExtension::new("c", None);
        let registry = VmLifecycleExtensions::with(vec![
            as_extension(&ext_a),
            as_extension(&ext_fail),
            as_extension(&ext_c),
        ]);
        let persisted = vec![sample_persisted_sandbox()];

        let err = registry
            .reconcile_after_restore(Path::new("/tmp/extensions"), &persisted)
            .await
            .expect_err("scripted failure should propagate");

        assert!(err.message().contains("reconcile_after_restore failed"));
        assert_eq!(ext_a.calls(), vec!["a:reconcile_after_restore:a:1"]);
        assert_eq!(
            ext_fail.calls(),
            vec!["boom:reconcile_after_restore:boom:1"]
        );
        assert!(ext_c.calls().is_empty());
    }

    #[tokio::test]
    async fn before_vm_launch_runs_each_extension_in_order_and_collects_env() {
        let ext_a = RecordingExtension::new("a", None);
        let ext_b = RecordingExtension::new("b", Some(VmBackend::Qemu));
        let registry =
            VmLifecycleExtensions::with(vec![as_extension(&ext_a), as_extension(&ext_b)]);
        let mut plan = sample_plan(VmBackend::Qemu);
        let sandbox = sample_sandbox();

        registry
            .before_vm_launch(&sandbox, &PathBuf::from("/tmp/state"), &mut plan)
            .await
            .expect("before_vm_launch succeeds");

        assert_eq!(plan.env, vec!["RECORDING_a=1", "RECORDING_b=1"]);
        assert_eq!(ext_a.calls(), vec!["a:before_vm_launch"]);
        assert_eq!(ext_b.calls(), vec!["b:before_vm_launch"]);
    }

    #[tokio::test]
    async fn before_vm_launch_short_circuits_on_first_failure() {
        let ext_a = RecordingExtension::new("a", None);
        let ext_fail = RecordingExtension::failing("boom", None);
        let ext_c = RecordingExtension::new("c", None);
        let registry = VmLifecycleExtensions::with(vec![
            as_extension(&ext_a),
            as_extension(&ext_fail),
            as_extension(&ext_c),
        ]);
        let mut plan = sample_plan(VmBackend::Libkrun);
        let sandbox = sample_sandbox();

        let err = registry
            .before_vm_launch(&sandbox, &PathBuf::from("/tmp/state"), &mut plan)
            .await
            .expect_err("scripted failure should propagate");
        assert!(err.message().contains("scripted before_vm_launch failure"));

        assert_eq!(ext_a.calls(), vec!["a:before_vm_launch"]);
        assert_eq!(ext_fail.calls(), vec!["boom:before_vm_launch"]);
        assert!(
            ext_c.calls().is_empty(),
            "extensions after the failure must not be invoked"
        );
    }

    #[tokio::test]
    async fn after_vm_launch_failed_runs_every_extension() {
        let ext_a = RecordingExtension::new("a", None);
        let ext_b = RecordingExtension::new("b", None);
        let registry =
            VmLifecycleExtensions::with(vec![as_extension(&ext_a), as_extension(&ext_b)]);
        let sandbox = sample_sandbox();

        registry
            .after_vm_launch_failed(
                &sandbox,
                &PathBuf::from("/tmp/state"),
                LaunchAbortReason::LauncherSpawnFailed,
            )
            .await;

        assert_eq!(
            ext_a.calls(),
            vec!["a:after_vm_launch_failed:LauncherSpawnFailed"]
        );
        assert_eq!(
            ext_b.calls(),
            vec!["b:after_vm_launch_failed:LauncherSpawnFailed"]
        );
    }

    #[tokio::test]
    async fn after_sandbox_deleted_runs_every_extension() {
        let ext_a = RecordingExtension::new("a", None);
        let ext_b = RecordingExtension::new("b", None);
        let registry =
            VmLifecycleExtensions::with(vec![as_extension(&ext_a), as_extension(&ext_b)]);
        let sandbox = sample_sandbox();

        registry
            .after_sandbox_deleted(&sandbox, &PathBuf::from("/tmp/state"))
            .await;

        assert_eq!(ext_a.calls(), vec!["a:after_sandbox_deleted"]);
        assert_eq!(ext_b.calls(), vec!["b:after_sandbox_deleted"]);
    }

    #[test]
    fn resource_exhausted_flag_round_trips() {
        let err = VmLifecycleError::resource_exhausted("pool empty");
        assert!(err.is_resource_exhausted());
        assert_eq!(err.message(), "pool empty");

        let plain = VmLifecycleError::new("internal");
        assert!(!plain.is_resource_exhausted());
    }
}
