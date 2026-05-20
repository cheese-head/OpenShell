// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::attachments::{
    VmDeviceAttachment, VmNetworkAttachment, VmRootfsConfig, VmStorageAttachment,
};
use crate::runtime::VmBackend;
use openshell_core::proto::compute::v1::DriverSandbox as Sandbox;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::fmt::{Display, Formatter};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::warn;

pub const EXTENSION_STATE_DIR: &str = "extensions";

pub type ExtensionStateMap = BTreeMap<String, PersistedExtensionState>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedExtensionState {
    #[serde(default)]
    pub data: Value,
}

impl PersistedExtensionState {
    pub fn new(data: Value) -> Self {
        Self { data }
    }
}

impl Default for PersistedExtensionState {
    fn default() -> Self {
        Self { data: Value::Null }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmLifecycleHookResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persisted_state: Option<PersistedExtensionState>,
}

impl VmLifecycleHookResult {
    pub fn with_state(state: PersistedExtensionState) -> Self {
        Self {
            persisted_state: Some(state),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ReconcileOutcome {
    #[default]
    Continue,
    SkipRestore {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchAbortReason {
    ExtensionHookFailed { hook: String, message: String },
    LauncherSpawnFailed { message: String },
    ProvisioningCancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLifecycleError {
    message: String,
}

impl VmLifecycleError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Display for VmLifecycleError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for VmLifecycleError {}

impl From<String> for VmLifecycleError {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for VmLifecycleError {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

pub type VmLifecycleResult<T> = Result<T, VmLifecycleError>;

#[derive(Debug, Clone)]
pub struct VmLifecycleContext<'a> {
    pub sandbox: &'a Sandbox,
    pub state_dir: &'a Path,
    pub image_ref: Option<&'a str>,
    pub persisted_states: &'a ExtensionStateMap,
}

impl<'a> VmLifecycleContext<'a> {
    pub fn new(
        sandbox: &'a Sandbox,
        state_dir: &'a Path,
        image_ref: Option<&'a str>,
        persisted_states: &'a ExtensionStateMap,
    ) -> Self {
        Self {
            sandbox,
            state_dir,
            image_ref,
            persisted_states,
        }
    }

    pub fn persisted_state(&self, extension_name: &str) -> Option<&PersistedExtensionState> {
        self.persisted_states.get(extension_name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLaunchPlan {
    pub rootfs: VmRootfsConfig,
    pub exec_path: String,
    pub workdir: String,
    pub console_output: PathBuf,
    pub vcpus: u8,
    pub mem_mib: u32,
    pub krun_log_level: u32,
    pub env: Vec<String>,
    pub backend: VmBackend,
    pub network: Vec<VmNetworkAttachment>,
    pub devices: Vec<VmDeviceAttachment>,
    pub extra_launcher_args: Vec<String>,
}

impl VmLaunchPlan {
    pub fn validate(&self) -> Result<(), String> {
        validate_rootfs_config(&self.rootfs)?;
        validate_env_entries(&self.env)?;
        validate_extra_launcher_args(&self.extra_launcher_args)?;
        if self.backend == VmBackend::Qemu {
            validate_qemu_launch_plan(self)?;
        } else if !self.network.is_empty() || !self.devices.is_empty() {
            return Err("VM network/device attachments require QEMU backend".to_string());
        }
        Ok(())
    }
}

#[tonic::async_trait]
pub trait VmLifecycleExtension: std::fmt::Debug + Send + Sync {
    fn name(&self) -> &str;

    async fn before_vm_launch(
        &self,
        _context: &VmLifecycleContext<'_>,
        _plan: &mut VmLaunchPlan,
    ) -> VmLifecycleResult<VmLifecycleHookResult> {
        Ok(VmLifecycleHookResult::default())
    }

    async fn after_vm_launch_succeeded(
        &self,
        _context: &VmLifecycleContext<'_>,
        _plan: &VmLaunchPlan,
    ) -> VmLifecycleResult<VmLifecycleHookResult> {
        Ok(VmLifecycleHookResult::default())
    }

    async fn after_vm_launch_failed(
        &self,
        _context: &VmLifecycleContext<'_>,
        _plan: &VmLaunchPlan,
        _reason: &LaunchAbortReason,
    ) -> VmLifecycleResult<VmLifecycleHookResult> {
        Ok(VmLifecycleHookResult::default())
    }

    async fn after_sandbox_deleted(
        &self,
        _context: &VmLifecycleContext<'_>,
    ) -> VmLifecycleResult<VmLifecycleHookResult> {
        Ok(VmLifecycleHookResult::default())
    }

    async fn reconcile_before_restore(
        &self,
        _context: &VmLifecycleContext<'_>,
    ) -> VmLifecycleResult<ReconcileOutcome> {
        Ok(ReconcileOutcome::Continue)
    }

    async fn reconcile_after_restore(
        &self,
        _context: &VmLifecycleContext<'_>,
    ) -> VmLifecycleResult<VmLifecycleHookResult> {
        Ok(VmLifecycleHookResult::default())
    }
}

#[derive(Debug, Clone, Default)]
pub struct VmLifecycleExtensions {
    extensions: Vec<Arc<dyn VmLifecycleExtension>>,
}

impl VmLifecycleExtensions {
    pub fn new(extensions: Vec<Arc<dyn VmLifecycleExtension>>) -> VmLifecycleResult<Self> {
        validate_lifecycle_extensions(&extensions)?;
        Ok(Self { extensions })
    }

    pub fn is_empty(&self) -> bool {
        self.extensions.is_empty()
    }

    pub fn validate(&self) -> VmLifecycleResult<()> {
        validate_lifecycle_extensions(&self.extensions)
    }

    pub async fn before_vm_launch(
        &self,
        sandbox: &Sandbox,
        state_dir: &Path,
        image_ref: &str,
        plan: &mut VmLaunchPlan,
    ) -> VmLifecycleResult<()> {
        if self.extensions.is_empty() {
            return Ok(());
        }

        let mut states = self.read_persisted_states(state_dir).await?;
        for extension in &self.extensions {
            let context = VmLifecycleContext::new(sandbox, state_dir, Some(image_ref), &states);
            let result = extension
                .before_vm_launch(&context, plan)
                .await
                .map_err(|err| hook_error(extension.name(), "before_vm_launch", &err))?;
            persist_lifecycle_hook_result(state_dir, extension.name(), result, &mut states).await?;
        }
        Ok(())
    }

    pub async fn after_vm_launch_succeeded(
        &self,
        sandbox: &Sandbox,
        state_dir: &Path,
        image_ref: &str,
        plan: &VmLaunchPlan,
    ) -> VmLifecycleResult<()> {
        if self.extensions.is_empty() {
            return Ok(());
        }

        let mut states = self.read_persisted_states(state_dir).await?;
        for extension in &self.extensions {
            let context = VmLifecycleContext::new(sandbox, state_dir, Some(image_ref), &states);
            let result = extension
                .after_vm_launch_succeeded(&context, plan)
                .await
                .map_err(|err| hook_error(extension.name(), "after_vm_launch_succeeded", &err))?;
            persist_lifecycle_hook_result(state_dir, extension.name(), result, &mut states).await?;
        }
        Ok(())
    }

    pub async fn after_vm_launch_failed(
        &self,
        sandbox: &Sandbox,
        state_dir: &Path,
        image_ref: &str,
        plan: &VmLaunchPlan,
        reason: &LaunchAbortReason,
    ) {
        if self.extensions.is_empty() {
            return;
        }

        let mut states = match self.read_persisted_states(state_dir).await {
            Ok(states) => states,
            Err(err) => {
                warn!(
                    sandbox_id = %sandbox.id,
                    error = %err.message(),
                    "vm driver: failed to load lifecycle extension state for launch failure hooks"
                );
                ExtensionStateMap::new()
            }
        };
        for extension in &self.extensions {
            let context = VmLifecycleContext::new(sandbox, state_dir, Some(image_ref), &states);
            let result = extension
                .after_vm_launch_failed(&context, plan, reason)
                .await
                .map_err(|err| hook_error(extension.name(), "after_vm_launch_failed", &err));
            match result {
                Ok(result) => {
                    if let Err(err) = persist_lifecycle_hook_result(
                        state_dir,
                        extension.name(),
                        result,
                        &mut states,
                    )
                    .await
                    {
                        warn!(
                            sandbox_id = %sandbox.id,
                            extension = extension.name(),
                            error = %err.message(),
                            "vm driver: lifecycle extension launch failure hook state persistence failed"
                        );
                    }
                }
                Err(err) => {
                    warn!(
                        sandbox_id = %sandbox.id,
                        extension = extension.name(),
                        error = %err.message(),
                        "vm driver: lifecycle extension launch failure hook failed"
                    );
                }
            }
        }
    }

    pub async fn after_sandbox_deleted(
        &self,
        sandbox: &Sandbox,
        state_dir: &Path,
    ) -> VmLifecycleResult<()> {
        if self.extensions.is_empty() {
            return Ok(());
        }

        let mut states = self.read_persisted_states(state_dir).await?;
        for extension in &self.extensions {
            let context = VmLifecycleContext::new(sandbox, state_dir, None, &states);
            let result = extension
                .after_sandbox_deleted(&context)
                .await
                .map_err(|err| hook_error(extension.name(), "after_sandbox_deleted", &err))?;
            persist_lifecycle_hook_result(state_dir, extension.name(), result, &mut states).await?;
        }
        Ok(())
    }

    pub async fn reconcile_before_restore(
        &self,
        sandbox: &Sandbox,
        state_dir: &Path,
    ) -> VmLifecycleResult<ReconcileOutcome> {
        if self.extensions.is_empty() {
            return Ok(ReconcileOutcome::Continue);
        }

        let states = self.read_persisted_states(state_dir).await?;
        for extension in &self.extensions {
            let context = VmLifecycleContext::new(sandbox, state_dir, None, &states);
            match extension
                .reconcile_before_restore(&context)
                .await
                .map_err(|err| hook_error(extension.name(), "reconcile_before_restore", &err))?
            {
                ReconcileOutcome::Continue => {}
                outcome @ ReconcileOutcome::SkipRestore { .. } => return Ok(outcome),
            }
        }
        Ok(ReconcileOutcome::Continue)
    }

    pub async fn reconcile_after_restore(
        &self,
        sandbox: &Sandbox,
        state_dir: &Path,
    ) -> VmLifecycleResult<()> {
        if self.extensions.is_empty() {
            return Ok(());
        }

        let mut states = self.read_persisted_states(state_dir).await?;
        for extension in &self.extensions {
            let context = VmLifecycleContext::new(sandbox, state_dir, None, &states);
            let result = extension
                .reconcile_after_restore(&context)
                .await
                .map_err(|err| hook_error(extension.name(), "reconcile_after_restore", &err))?;
            persist_lifecycle_hook_result(state_dir, extension.name(), result, &mut states).await?;
        }
        Ok(())
    }

    async fn read_persisted_states(
        &self,
        state_dir: &Path,
    ) -> VmLifecycleResult<ExtensionStateMap> {
        let mut states = ExtensionStateMap::new();
        for extension in &self.extensions {
            let path = extension_state_path(state_dir, extension.name()).map_err(|err| {
                VmLifecycleError::new(format!(
                    "invalid VM lifecycle extension state path for '{}': {err}",
                    extension.name()
                ))
            })?;
            let bytes = match tokio::fs::read(&path).await {
                Ok(bytes) => bytes,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(VmLifecycleError::new(format!(
                        "read VM lifecycle extension state {} failed: {err}",
                        path.display()
                    )));
                }
            };
            let state =
                serde_json::from_slice::<PersistedExtensionState>(&bytes).map_err(|err| {
                    VmLifecycleError::new(format!(
                        "decode VM lifecycle extension state {} failed: {err}",
                        path.display()
                    ))
                })?;
            states.insert(extension.name().to_string(), state);
        }
        Ok(states)
    }
}

#[derive(Debug, Default)]
pub struct NoopVmLifecycleExtension;

#[tonic::async_trait]
impl VmLifecycleExtension for NoopVmLifecycleExtension {
    #[allow(clippy::unnecessary_literal_bound)]
    fn name(&self) -> &str {
        "noop"
    }
}

pub fn validate_extension_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("extension name is required".to_string());
    }
    if name.len() > 128 {
        return Err("extension name exceeds maximum length (128 bytes)".to_string());
    }
    if matches!(name, "." | "..") {
        return Err("extension name must match [A-Za-z0-9._-]{1,128}".to_string());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err("extension name must match [A-Za-z0-9._-]{1,128}".to_string());
    }
    Ok(())
}

pub fn extension_state_path(state_dir: &Path, extension_name: &str) -> Result<PathBuf, String> {
    validate_extension_name(extension_name)?;
    Ok(state_dir
        .join(EXTENSION_STATE_DIR)
        .join(format!("{extension_name}.json")))
}

fn validate_lifecycle_extensions(
    extensions: &[Arc<dyn VmLifecycleExtension>],
) -> VmLifecycleResult<()> {
    let mut names = HashSet::new();
    for extension in extensions {
        validate_extension_name(extension.name()).map_err(VmLifecycleError::new)?;
        if !names.insert(extension.name().to_string()) {
            return Err(VmLifecycleError::new(format!(
                "duplicate VM lifecycle extension '{}'",
                extension.name()
            )));
        }
    }
    Ok(())
}

fn hook_error(extension_name: &str, hook: &str, err: &VmLifecycleError) -> VmLifecycleError {
    VmLifecycleError::new(format!(
        "vm lifecycle extension '{extension_name}' {hook} failed: {err}"
    ))
}

async fn persist_lifecycle_hook_result(
    state_dir: &Path,
    extension_name: &str,
    result: VmLifecycleHookResult,
    states: &mut ExtensionStateMap,
) -> VmLifecycleResult<()> {
    let Some(state) = result.persisted_state else {
        return Ok(());
    };
    write_persisted_extension_state(state_dir, extension_name, &state).await?;
    states.insert(extension_name.to_string(), state);
    Ok(())
}

async fn write_persisted_extension_state(
    state_dir: &Path,
    extension_name: &str,
    state: &PersistedExtensionState,
) -> VmLifecycleResult<()> {
    let path = extension_state_path(state_dir, extension_name).map_err(|err| {
        VmLifecycleError::new(format!(
            "invalid VM lifecycle extension state path for '{extension_name}': {err}"
        ))
    })?;
    let Some(parent) = path.parent() else {
        return Err(VmLifecycleError::new(format!(
            "VM lifecycle extension state path has no parent: {}",
            path.display()
        )));
    };
    create_private_dir_all(parent).await.map_err(|err| {
        VmLifecycleError::new(format!(
            "create VM lifecycle extension state dir {} failed: {err}",
            parent.display()
        ))
    })?;
    let bytes = serde_json::to_vec_pretty(state).map_err(|err| {
        VmLifecycleError::new(format!(
            "encode VM lifecycle extension state for '{extension_name}' failed: {err}"
        ))
    })?;
    write_private_file(&path, bytes).await.map_err(|err| {
        VmLifecycleError::new(format!(
            "write VM lifecycle extension state {} failed: {err}",
            path.display()
        ))
    })
}

async fn create_private_dir_all(path: &Path) -> Result<(), std::io::Error> {
    tokio::fs::create_dir_all(path).await?;
    restrict_owner_only_dir(path).await
}

#[cfg(unix)]
async fn restrict_owner_only_dir(path: &Path) -> Result<(), std::io::Error> {
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await
}

#[cfg(not(unix))]
async fn restrict_owner_only_dir(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

async fn write_private_file(path: &Path, bytes: Vec<u8>) -> Result<(), std::io::Error> {
    tokio::fs::write(path, bytes).await?;
    restrict_owner_read_write(path).await
}

#[cfg(unix)]
async fn restrict_owner_read_write(path: &Path) -> Result<(), std::io::Error> {
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await
}

#[cfg(not(unix))]
async fn restrict_owner_read_write(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

fn validate_env_entries(env: &[String]) -> Result<(), String> {
    for entry in env {
        if entry.is_empty() {
            return Err("VM launch environment contains an empty entry".to_string());
        }
        if entry.contains('\0') {
            return Err("VM launch environment contains a NUL byte".to_string());
        }
        let Some((key, _value)) = entry.split_once('=') else {
            return Err(format!(
                "VM launch environment entry '{entry}' is missing '='"
            ));
        };
        if key.is_empty() {
            return Err("VM launch environment contains an empty key".to_string());
        }
        if key.bytes().any(|b| b == b'=' || b == 0) {
            return Err(format!("VM launch environment key '{key}' is invalid"));
        }
    }
    Ok(())
}

fn validate_extra_launcher_args(args: &[String]) -> Result<(), String> {
    for arg in args {
        if arg.is_empty() {
            return Err("VM launch extra argument cannot be empty".to_string());
        }
        if arg.contains('\0') {
            return Err("VM launch extra argument contains a NUL byte".to_string());
        }
        if reserved_launcher_arg(arg) {
            return Err(format!(
                "VM launch extra argument '{arg}' overrides a driver-owned argument"
            ));
        }
    }
    Ok(())
}

fn validate_qemu_launch_plan(plan: &VmLaunchPlan) -> Result<(), String> {
    if plan.network.is_empty() {
        return Err("QEMU launch plan requires at least one network attachment".to_string());
    }
    for network in &plan.network {
        validate_network_attachment(network)?;
    }
    for device in &plan.devices {
        validate_device_attachment(device)?;
    }
    Ok(())
}

fn validate_rootfs_config(rootfs: &VmRootfsConfig) -> Result<(), String> {
    validate_storage_attachment("root", &rootfs.root)?;
    validate_storage_attachment("overlay", &rootfs.overlay)?;
    if let Some(image) = &rootfs.image {
        validate_storage_attachment("image", image)?;
    }
    Ok(())
}

fn validate_storage_attachment(name: &str, storage: &VmStorageAttachment) -> Result<(), String> {
    match storage {
        VmStorageAttachment::HostFile { path, .. }
        | VmStorageAttachment::HostBlockDevice { path, .. } => {
            if path.as_os_str().is_empty() {
                return Err(format!("VM launch {name} storage path is empty"));
            }
        }
        VmStorageAttachment::DpuProvisioned { id, device, .. } => {
            if id.trim().is_empty() {
                return Err(format!("VM launch {name} DPU storage id is empty"));
            }
            if device.as_os_str().is_empty() {
                return Err(format!("VM launch {name} DPU storage device path is empty"));
            }
        }
    }
    Ok(())
}

fn validate_network_attachment(network: &VmNetworkAttachment) -> Result<(), String> {
    match network {
        VmNetworkAttachment::Tap {
            ifname,
            guest_ip,
            host_ip,
            mac,
            ..
        } => {
            if ifname.trim().is_empty() {
                return Err("QEMU TAP network attachment requires ifname".to_string());
            }
            if guest_ip.trim().is_empty() {
                return Err("QEMU TAP network attachment requires guest_ip".to_string());
            }
            if host_ip.trim().is_empty() {
                return Err("QEMU TAP network attachment requires host_ip".to_string());
            }
            if mac.trim().is_empty() {
                return Err("QEMU TAP network attachment requires mac".to_string());
            }
        }
        VmNetworkAttachment::VfioPci { bdf, .. } => {
            if bdf.trim().is_empty() {
                return Err("QEMU VFIO network attachment requires bdf".to_string());
            }
        }
        VmNetworkAttachment::Vdpa { device, .. } => {
            if device.as_os_str().is_empty() {
                return Err("QEMU vDPA network attachment requires device".to_string());
            }
        }
    }
    Ok(())
}

fn validate_device_attachment(device: &VmDeviceAttachment) -> Result<(), String> {
    match device {
        VmDeviceAttachment::VfioPci { bdf, .. } => {
            if bdf.trim().is_empty() {
                return Err("QEMU VFIO device attachment requires bdf".to_string());
            }
        }
        VmDeviceAttachment::Vsock { cid } => {
            if *cid == 0 {
                return Err("QEMU vhost-vsock attachment requires a non-zero cid".to_string());
            }
        }
    }
    Ok(())
}

fn reserved_launcher_arg(arg: &str) -> bool {
    const RESERVED: &[&str] = &[
        "--internal-run-vm",
        "--vm-root-disk",
        "--vm-rootfs",
        "--vm-rootfs-config",
        "--vm-overlay-disk",
        "--vm-image-disk",
        "--vm-exec",
        "--vm-workdir",
        "--vm-env",
        "--vm-console-output",
        "--vm-vcpus",
        "--vm-mem-mib",
        "--vm-krun-log-level",
        "--vm-backend",
        "--vm-gpu-bdf",
        "--vm-tap-device",
        "--vm-guest-ip",
        "--vm-host-ip",
        "--vm-vsock-cid",
        "--vm-guest-mac",
        "--vm-gateway-port",
        "--vm-network-attachment",
        "--vm-device-attachment",
    ];

    RESERVED
        .iter()
        .any(|reserved| arg == *reserved || arg.starts_with(&format!("{reserved}=")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_state_path_rejects_unsafe_names() {
        for name in ["", ".", "..", "../escape", "nested/name", "bad name"] {
            let err = extension_state_path(Path::new("/tmp/sandbox"), name)
                .expect_err("unsafe extension name should be rejected");
            assert!(err.contains("extension name"));
        }
    }

    #[test]
    fn launch_plan_validation_rejects_reserved_extra_args() {
        let plan = VmLaunchPlan {
            rootfs: VmRootfsConfig::host_files(
                PathBuf::from("/root.ext4"),
                PathBuf::from("/overlay.ext4"),
                None,
            ),
            exec_path: "/init".to_string(),
            workdir: "/".to_string(),
            console_output: PathBuf::from("/console.log"),
            vcpus: 2,
            mem_mib: 2048,
            krun_log_level: 1,
            env: vec!["A=B".to_string()],
            backend: VmBackend::Libkrun,
            network: Vec::new(),
            devices: Vec::new(),
            extra_launcher_args: vec!["--vm-root-disk=/other".to_string()],
        };

        let err = plan
            .validate()
            .expect_err("reserved extension args should be rejected");
        assert!(err.contains("driver-owned"));
    }

    #[test]
    fn launch_plan_validation_rejects_incomplete_qemu_plan() {
        let plan = VmLaunchPlan {
            rootfs: VmRootfsConfig::host_files(
                PathBuf::from("/root.ext4"),
                PathBuf::from("/overlay.ext4"),
                None,
            ),
            exec_path: "/init".to_string(),
            workdir: "/".to_string(),
            console_output: PathBuf::from("/console.log"),
            vcpus: 2,
            mem_mib: 2048,
            krun_log_level: 1,
            env: vec!["A=B".to_string()],
            backend: VmBackend::Qemu,
            network: Vec::new(),
            devices: Vec::new(),
            extra_launcher_args: Vec::new(),
        };

        let err = plan
            .validate()
            .expect_err("incomplete QEMU plans should be rejected");
        assert!(err.contains("network attachment"));
    }

    #[test]
    fn launch_plan_validation_accepts_qemu_vfio_network_attachment() {
        let plan = VmLaunchPlan {
            rootfs: VmRootfsConfig::host_files(
                PathBuf::from("/root.ext4"),
                PathBuf::from("/overlay.ext4"),
                None,
            ),
            exec_path: "/init".to_string(),
            workdir: "/".to_string(),
            console_output: PathBuf::from("/console.log"),
            vcpus: 2,
            mem_mib: 2048,
            krun_log_level: 1,
            env: vec!["A=B".to_string()],
            backend: VmBackend::Qemu,
            network: vec![VmNetworkAttachment::VfioPci {
                bdf: "0000:03:00.2".to_string(),
                mac: None,
            }],
            devices: Vec::new(),
            extra_launcher_args: Vec::new(),
        };

        plan.validate()
            .expect("QEMU should accept a VFIO network attachment without TAP");
    }
}
