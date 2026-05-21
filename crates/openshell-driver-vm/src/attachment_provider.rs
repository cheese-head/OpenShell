// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::attachments::{DeviceAttachment, NetworkAttachment, RootfsConfig, StorageAttachment};
use crate::extension::{
    LaunchAbortReason, PersistedExtensionState, ReconcileOutcome, VmLaunchPlan, VmLifecycleContext,
    VmLifecycleError, VmLifecycleExtension, VmLifecycleHookResult, VmLifecycleResult,
    validate_extension_name,
};
use crate::runtime::VmBackend;
use openshell_core::proto::attachment::v1 as attachment_proto;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

pub const VM_ATTACHMENT_LIFECYCLE_EXTENSION_NAME: &str = "vm-attachments";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttachmentProviderHealth {
    pub healthy: bool,
    pub message: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentPlan {
    #[serde(default)]
    pub replace_network: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network: Vec<NetworkAttachment>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<DeviceAttachment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs: Option<RootfsConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentRequest {
    pub sandbox_id: String,
    pub sandbox_name: String,
    pub image_ref: Option<String>,
    pub state_dir: PathBuf,
    pub backend: VmBackend,
    pub rootfs: RootfsConfig,
    pub network: Vec<NetworkAttachment>,
    pub devices: Vec<DeviceAttachment>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentLease {
    pub attachment_id: String,
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub plan: AttachmentPlan,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[tonic::async_trait]
pub trait AttachmentProvider: std::fmt::Debug + Send + Sync {
    async fn health(&self) -> VmLifecycleResult<AttachmentProviderHealth>;

    async fn attach(&self, request: AttachmentRequest) -> VmLifecycleResult<AttachmentLease>;

    async fn detach(&self, lease: AttachmentLease) -> VmLifecycleResult<()>;

    async fn list(&self) -> VmLifecycleResult<Vec<AttachmentLease>>;

    async fn reconcile(&self, lease: AttachmentLease) -> VmLifecycleResult<ReconcileOutcome>;
}

#[derive(Debug, Clone)]
pub struct GrpcAttachmentProvider {
    client: attachment_proto::attachment_provider_client::AttachmentProviderClient<Channel>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrpcAttachmentProviderConfig {
    pub endpoint: String,
    pub tls: Option<AttachmentProviderClientTlsConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentProviderClientTlsConfig {
    pub ca_cert: PathBuf,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
    pub domain_name: Option<String>,
}

impl GrpcAttachmentProvider {
    pub fn connect_lazy(endpoint: impl Into<String>) -> VmLifecycleResult<Self> {
        Self::connect_lazy_with_config(GrpcAttachmentProviderConfig {
            endpoint: endpoint.into(),
            tls: None,
        })
    }

    pub fn connect_lazy_with_config(
        config: GrpcAttachmentProviderConfig,
    ) -> VmLifecycleResult<Self> {
        let endpoint = Endpoint::from_shared(config.endpoint.clone()).map_err(|err| {
            VmLifecycleError::new(format!("invalid attachment provider endpoint: {err}"))
        })?;
        let endpoint = if let Some(tls) = config.tls {
            endpoint
                .tls_config(client_tls_config(tls)?)
                .map_err(|err| {
                    VmLifecycleError::new(format!(
                        "configure attachment provider TLS for '{}': {err}",
                        config.endpoint
                    ))
                })?
        } else {
            endpoint
        };
        Ok(Self::from_channel(endpoint.connect_lazy()))
    }

    pub fn from_channel(channel: Channel) -> Self {
        Self {
            client: attachment_proto::attachment_provider_client::AttachmentProviderClient::new(
                channel,
            ),
        }
    }
}

#[tonic::async_trait]
impl AttachmentProvider for GrpcAttachmentProvider {
    async fn health(&self) -> VmLifecycleResult<AttachmentProviderHealth> {
        let mut client = self.client.clone();
        let response = client
            .health(attachment_proto::HealthRequest {})
            .await
            .map_err(|err| grpc_error("health", err))?
            .into_inner();
        Ok(AttachmentProviderHealth {
            healthy: response.healthy,
            message: response.message,
            capabilities: response.capabilities,
        })
    }

    async fn attach(&self, request: AttachmentRequest) -> VmLifecycleResult<AttachmentLease> {
        let mut client = self.client.clone();
        let response = client
            .attach(attachment_proto::AttachRequest::from(request))
            .await
            .map_err(|err| grpc_error("attach", err))?
            .into_inner();
        response
            .lease
            .ok_or_else(|| {
                VmLifecycleError::new("attachment provider attach response missing lease")
            })?
            .try_into()
    }

    async fn detach(&self, lease: AttachmentLease) -> VmLifecycleResult<()> {
        let mut client = self.client.clone();
        client
            .detach(attachment_proto::DetachRequest {
                lease: Some(attachment_proto::AttachmentLease::from(lease)),
            })
            .await
            .map_err(|err| grpc_error("detach", err))?;
        Ok(())
    }

    async fn list(&self) -> VmLifecycleResult<Vec<AttachmentLease>> {
        let mut client = self.client.clone();
        let response = client
            .list(attachment_proto::ListRequest {})
            .await
            .map_err(|err| grpc_error("list", err))?
            .into_inner();
        response.leases.into_iter().map(TryInto::try_into).collect()
    }

    async fn reconcile(&self, lease: AttachmentLease) -> VmLifecycleResult<ReconcileOutcome> {
        let mut client = self.client.clone();
        let response = client
            .reconcile(attachment_proto::ReconcileRequest {
                lease: Some(attachment_proto::AttachmentLease::from(lease)),
            })
            .await
            .map_err(|err| grpc_error("reconcile", err))?
            .into_inner();
        reconcile_outcome_from_proto(response.outcome, response.reason)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticAttachmentProviderConfig {
    #[serde(default = "default_static_attachment_id_prefix")]
    pub attachment_id_prefix: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    #[serde(default, flatten)]
    pub plan: AttachmentPlan,
}

impl Default for StaticAttachmentProviderConfig {
    fn default() -> Self {
        Self {
            attachment_id_prefix: default_static_attachment_id_prefix(),
            metadata: BTreeMap::new(),
            plan: AttachmentPlan::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StaticAttachmentProvider {
    config: StaticAttachmentProviderConfig,
}

impl StaticAttachmentProvider {
    pub fn new(config: StaticAttachmentProviderConfig) -> Self {
        Self { config }
    }
}

#[tonic::async_trait]
impl AttachmentProvider for StaticAttachmentProvider {
    async fn health(&self) -> VmLifecycleResult<AttachmentProviderHealth> {
        Ok(AttachmentProviderHealth {
            healthy: true,
            message: "static attachment provider configured".to_string(),
            capabilities: vec!["static-plan".to_string()],
        })
    }

    async fn attach(&self, request: AttachmentRequest) -> VmLifecycleResult<AttachmentLease> {
        let attachment_id = if self.config.attachment_id_prefix.is_empty() {
            request.sandbox_id
        } else {
            format!(
                "{}-{}",
                self.config.attachment_id_prefix, request.sandbox_id
            )
        };

        Ok(AttachmentLease {
            attachment_id,
            generation: 1,
            plan: self.config.plan.clone(),
            metadata: self.config.metadata.clone(),
        })
    }

    async fn detach(&self, _lease: AttachmentLease) -> VmLifecycleResult<()> {
        Ok(())
    }

    async fn list(&self) -> VmLifecycleResult<Vec<AttachmentLease>> {
        Ok(Vec::new())
    }

    async fn reconcile(&self, _lease: AttachmentLease) -> VmLifecycleResult<ReconcileOutcome> {
        Ok(ReconcileOutcome::Continue)
    }
}

#[derive(Debug, Clone)]
pub struct VmAttachmentLifecycleExtension {
    name: String,
    provider: Arc<dyn AttachmentProvider>,
}

impl VmAttachmentLifecycleExtension {
    pub fn new(provider: Arc<dyn AttachmentProvider>) -> Self {
        Self {
            name: VM_ATTACHMENT_LIFECYCLE_EXTENSION_NAME.to_string(),
            provider,
        }
    }

    pub fn with_name(
        name: impl Into<String>,
        provider: Arc<dyn AttachmentProvider>,
    ) -> VmLifecycleResult<Self> {
        let name = name.into();
        validate_extension_name(&name).map_err(VmLifecycleError::new)?;
        Ok(Self { name, provider })
    }

    fn persisted_lease(
        &self,
        context: &VmLifecycleContext<'_>,
    ) -> VmLifecycleResult<Option<AttachmentLease>> {
        let Some(state) = context.persisted_state(self.name()) else {
            return Ok(None);
        };
        let lifecycle_state: VmAttachmentLifecycleState =
            serde_json::from_value(state.data.clone()).map_err(|err| {
                VmLifecycleError::new(format!(
                    "decode VM attachment lifecycle state for '{}' failed: {err}",
                    self.name
                ))
            })?;
        Ok(Some(lifecycle_state.lease))
    }

    fn hook_result_with_lease(
        &self,
        lease: AttachmentLease,
    ) -> VmLifecycleResult<VmLifecycleHookResult> {
        validate_lease(&lease)?;
        let state = VmAttachmentLifecycleState { lease };
        let data = serde_json::to_value(state).map_err(|err| {
            VmLifecycleError::new(format!(
                "encode VM attachment lifecycle state for '{}' failed: {err}",
                self.name
            ))
        })?;
        Ok(VmLifecycleHookResult::with_state(
            PersistedExtensionState::new(data),
        ))
    }

    async fn detach_persisted_lease(
        &self,
        context: &VmLifecycleContext<'_>,
    ) -> VmLifecycleResult<VmLifecycleHookResult> {
        let Some(lease) = self.persisted_lease(context)? else {
            return Ok(VmLifecycleHookResult::default());
        };
        self.provider.detach(lease).await?;
        Ok(VmLifecycleHookResult::clear_state())
    }
}

#[tonic::async_trait]
impl VmLifecycleExtension for VmAttachmentLifecycleExtension {
    fn name(&self) -> &str {
        &self.name
    }

    async fn before_vm_launch(
        &self,
        context: &VmLifecycleContext<'_>,
        plan: &mut VmLaunchPlan,
    ) -> VmLifecycleResult<VmLifecycleHookResult> {
        if plan.backend != VmBackend::Qemu {
            return Err(VmLifecycleError::new(
                "VM attachment lifecycle requires the QEMU backend",
            ));
        }

        if let Some(lease) = self.persisted_lease(context)? {
            apply_lease_to_plan(&lease, plan)?;
            return Ok(VmLifecycleHookResult::default());
        }

        let request = AttachmentRequest {
            sandbox_id: context.sandbox.id.clone(),
            sandbox_name: context.sandbox.name.clone(),
            image_ref: context.image_ref.map(ToString::to_string),
            state_dir: context.state_dir.to_path_buf(),
            backend: plan.backend.clone(),
            rootfs: plan.rootfs.clone(),
            network: plan.network.clone(),
            devices: plan.devices.clone(),
        };
        let lease = self.provider.attach(request).await?;
        apply_lease_to_plan(&lease, plan)?;
        self.hook_result_with_lease(lease)
    }

    async fn after_vm_launch_failed(
        &self,
        context: &VmLifecycleContext<'_>,
        _plan: &VmLaunchPlan,
        _reason: &LaunchAbortReason,
    ) -> VmLifecycleResult<VmLifecycleHookResult> {
        self.detach_persisted_lease(context).await
    }

    async fn after_sandbox_deleted(
        &self,
        context: &VmLifecycleContext<'_>,
    ) -> VmLifecycleResult<VmLifecycleHookResult> {
        self.detach_persisted_lease(context).await
    }

    async fn reconcile_before_restore(
        &self,
        context: &VmLifecycleContext<'_>,
    ) -> VmLifecycleResult<ReconcileOutcome> {
        let Some(lease) = self.persisted_lease(context)? else {
            return Ok(ReconcileOutcome::Continue);
        };
        self.provider.reconcile(lease).await
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VmAttachmentLifecycleState {
    lease: AttachmentLease,
}

fn apply_lease_to_plan(lease: &AttachmentLease, plan: &mut VmLaunchPlan) -> VmLifecycleResult<()> {
    validate_lease(lease)?;
    if lease.plan.replace_network {
        plan.network.clear();
    }
    plan.network.extend(lease.plan.network.clone());
    plan.devices.extend(lease.plan.devices.clone());
    if let Some(rootfs) = &lease.plan.rootfs {
        plan.rootfs = rootfs.clone();
    }
    plan.env.extend(lease.plan.env.clone());
    Ok(())
}

fn validate_lease(lease: &AttachmentLease) -> VmLifecycleResult<()> {
    if lease.attachment_id.trim().is_empty() {
        return Err(VmLifecycleError::new("attachment lease id cannot be empty"));
    }
    Ok(())
}

fn grpc_error(operation: &str, status: tonic::Status) -> VmLifecycleError {
    VmLifecycleError::new(format!(
        "attachment provider {operation} RPC failed: {status}"
    ))
}

fn client_tls_config(
    config: AttachmentProviderClientTlsConfig,
) -> VmLifecycleResult<ClientTlsConfig> {
    let ca_cert = std::fs::read(&config.ca_cert).map_err(|err| {
        VmLifecycleError::new(format!(
            "read attachment provider CA cert {} failed: {err}",
            config.ca_cert.display()
        ))
    })?;
    let client_cert = std::fs::read(&config.client_cert).map_err(|err| {
        VmLifecycleError::new(format!(
            "read attachment provider client cert {} failed: {err}",
            config.client_cert.display()
        ))
    })?;
    let client_key = std::fs::read(&config.client_key).map_err(|err| {
        VmLifecycleError::new(format!(
            "read attachment provider client key {} failed: {err}",
            config.client_key.display()
        ))
    })?;
    let mut tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca_cert))
        .identity(Identity::from_pem(client_cert, client_key));
    if let Some(domain_name) = config.domain_name {
        tls = tls.domain_name(domain_name);
    }
    Ok(tls)
}

fn default_static_attachment_id_prefix() -> String {
    "vm-attachment".to_string()
}

fn consumer_from_backend(backend: &VmBackend) -> String {
    match backend {
        VmBackend::Libkrun => "libkrun",
        VmBackend::Qemu => "qemu",
    }
    .to_string()
}

fn backend_from_consumer(consumer: &str) -> VmLifecycleResult<VmBackend> {
    match consumer {
        "libkrun" | "" => Ok(VmBackend::Libkrun),
        "qemu" => Ok(VmBackend::Qemu),
        other => Err(VmLifecycleError::new(format!(
            "unsupported attachment consumer '{other}'"
        ))),
    }
}

fn path_to_proto(path: PathBuf) -> String {
    path.to_string_lossy().into_owned()
}

fn path_from_proto(path: String) -> PathBuf {
    PathBuf::from(path)
}

fn reconcile_outcome_from_proto(
    outcome: i32,
    reason: String,
) -> VmLifecycleResult<ReconcileOutcome> {
    match attachment_proto::ReconcileOutcome::try_from(outcome) {
        Ok(
            attachment_proto::ReconcileOutcome::Unspecified
            | attachment_proto::ReconcileOutcome::Continue,
        ) => Ok(ReconcileOutcome::Continue),
        Ok(attachment_proto::ReconcileOutcome::SkipRestore) => {
            Ok(ReconcileOutcome::SkipRestore { reason })
        }
        Err(_) => Err(VmLifecycleError::new(format!(
            "unknown VM attachment reconcile outcome {outcome}"
        ))),
    }
}

#[cfg(test)]
fn reconcile_outcome_to_proto(outcome: ReconcileOutcome) -> (i32, String) {
    match outcome {
        ReconcileOutcome::Continue => (
            attachment_proto::ReconcileOutcome::Continue.into(),
            String::new(),
        ),
        ReconcileOutcome::SkipRestore { reason } => (
            attachment_proto::ReconcileOutcome::SkipRestore.into(),
            reason,
        ),
    }
}

impl From<AttachmentRequest> for attachment_proto::AttachRequest {
    fn from(value: AttachmentRequest) -> Self {
        Self {
            sandbox_id: value.sandbox_id,
            sandbox_name: value.sandbox_name,
            image_ref: value.image_ref,
            consumer: consumer_from_backend(&value.backend),
            rootfs: Some(attachment_proto::RootfsConfig::from(value.rootfs)),
            network: value.network.into_iter().map(Into::into).collect(),
            devices: value.devices.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<attachment_proto::AttachRequest> for AttachmentRequest {
    type Error = VmLifecycleError;

    fn try_from(value: attachment_proto::AttachRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            sandbox_id: value.sandbox_id,
            sandbox_name: value.sandbox_name,
            image_ref: value.image_ref,
            state_dir: PathBuf::new(),
            backend: backend_from_consumer(&value.consumer)?,
            rootfs: value
                .rootfs
                .ok_or_else(|| VmLifecycleError::new("attachment attach request missing rootfs"))?
                .try_into()?,
            network: value
                .network
                .into_iter()
                .map(TryInto::try_into)
                .collect::<VmLifecycleResult<_>>()?,
            devices: value
                .devices
                .into_iter()
                .map(TryInto::try_into)
                .collect::<VmLifecycleResult<_>>()?,
        })
    }
}

impl From<AttachmentLease> for attachment_proto::AttachmentLease {
    fn from(value: AttachmentLease) -> Self {
        Self {
            attachment_id: value.attachment_id,
            generation: value.generation,
            plan: Some(attachment_proto::AttachmentPlan::from(value.plan)),
            metadata: value.metadata.into_iter().collect(),
        }
    }
}

impl TryFrom<attachment_proto::AttachmentLease> for AttachmentLease {
    type Error = VmLifecycleError;

    fn try_from(value: attachment_proto::AttachmentLease) -> Result<Self, Self::Error> {
        let lease = Self {
            attachment_id: value.attachment_id,
            generation: value.generation,
            plan: value
                .plan
                .map(TryInto::try_into)
                .transpose()?
                .unwrap_or_default(),
            metadata: value.metadata.into_iter().collect(),
        };
        validate_lease(&lease)?;
        Ok(lease)
    }
}

impl From<AttachmentPlan> for attachment_proto::AttachmentPlan {
    fn from(value: AttachmentPlan) -> Self {
        Self {
            replace_network: value.replace_network,
            network: value.network.into_iter().map(Into::into).collect(),
            devices: value.devices.into_iter().map(Into::into).collect(),
            rootfs: value.rootfs.map(Into::into),
            env: value.env,
        }
    }
}

impl TryFrom<attachment_proto::AttachmentPlan> for AttachmentPlan {
    type Error = VmLifecycleError;

    fn try_from(value: attachment_proto::AttachmentPlan) -> Result<Self, Self::Error> {
        Ok(Self {
            replace_network: value.replace_network,
            network: value
                .network
                .into_iter()
                .map(TryInto::try_into)
                .collect::<VmLifecycleResult<_>>()?,
            devices: value
                .devices
                .into_iter()
                .map(TryInto::try_into)
                .collect::<VmLifecycleResult<_>>()?,
            rootfs: value.rootfs.map(TryInto::try_into).transpose()?,
            env: value.env,
        })
    }
}

impl From<RootfsConfig> for attachment_proto::RootfsConfig {
    fn from(value: RootfsConfig) -> Self {
        Self {
            root: Some(attachment_proto::StorageAttachment::from(value.root)),
            overlay: Some(attachment_proto::StorageAttachment::from(value.overlay)),
            image: value.image.map(Into::into),
        }
    }
}

impl TryFrom<attachment_proto::RootfsConfig> for RootfsConfig {
    type Error = VmLifecycleError;

    fn try_from(value: attachment_proto::RootfsConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            root: value
                .root
                .ok_or_else(|| VmLifecycleError::new("attachment rootfs config missing root"))?
                .try_into()?,
            overlay: value
                .overlay
                .ok_or_else(|| VmLifecycleError::new("attachment rootfs config missing overlay"))?
                .try_into()?,
            image: value.image.map(TryInto::try_into).transpose()?,
        })
    }
}

impl From<StorageAttachment> for attachment_proto::StorageAttachment {
    fn from(value: StorageAttachment) -> Self {
        use attachment_proto::storage_attachment::Kind;

        let kind = match value {
            StorageAttachment::HostFile { path, read_only } => {
                Kind::HostFile(attachment_proto::HostFileStorageAttachment {
                    path: path_to_proto(path),
                    read_only,
                })
            }
            StorageAttachment::HostBlockDevice { path, read_only } => {
                Kind::HostBlockDevice(attachment_proto::HostBlockDeviceStorageAttachment {
                    path: path_to_proto(path),
                    read_only,
                })
            }
            StorageAttachment::ProviderProvisioned {
                id,
                device,
                read_only,
            } => {
                Kind::ProviderProvisioned(attachment_proto::ProviderProvisionedStorageAttachment {
                    id,
                    device: path_to_proto(device),
                    read_only,
                })
            }
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<attachment_proto::StorageAttachment> for StorageAttachment {
    type Error = VmLifecycleError;

    fn try_from(value: attachment_proto::StorageAttachment) -> Result<Self, Self::Error> {
        use attachment_proto::storage_attachment::Kind;

        match value.kind {
            Some(Kind::HostFile(attachment)) => Ok(Self::HostFile {
                path: path_from_proto(attachment.path),
                read_only: attachment.read_only,
            }),
            Some(Kind::HostBlockDevice(attachment)) => Ok(Self::HostBlockDevice {
                path: path_from_proto(attachment.path),
                read_only: attachment.read_only,
            }),
            Some(Kind::ProviderProvisioned(attachment)) => Ok(Self::ProviderProvisioned {
                id: attachment.id,
                device: path_from_proto(attachment.device),
                read_only: attachment.read_only,
            }),
            None => Err(VmLifecycleError::new(
                "provider storage attachment missing kind",
            )),
        }
    }
}

impl From<NetworkAttachment> for attachment_proto::NetworkAttachment {
    fn from(value: NetworkAttachment) -> Self {
        use attachment_proto::network_attachment::Kind;

        let kind = match value {
            NetworkAttachment::Tap {
                ifname,
                guest_ip,
                host_ip,
                mac,
                gateway_port,
            } => Kind::Tap(attachment_proto::TapNetworkAttachment {
                ifname,
                guest_ip,
                host_ip,
                mac,
                gateway_port: gateway_port.map(u32::from),
            }),
            NetworkAttachment::VfioPci { bdf, mac } => {
                Kind::VfioPci(attachment_proto::VfioPciNetworkAttachment { bdf, mac })
            }
            NetworkAttachment::Vdpa { device, mac } => {
                Kind::Vdpa(attachment_proto::VdpaNetworkAttachment {
                    device: path_to_proto(device),
                    mac,
                })
            }
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<attachment_proto::NetworkAttachment> for NetworkAttachment {
    type Error = VmLifecycleError;

    fn try_from(value: attachment_proto::NetworkAttachment) -> Result<Self, Self::Error> {
        use attachment_proto::network_attachment::Kind;

        match value.kind {
            Some(Kind::Tap(attachment)) => {
                let gateway_port = attachment
                    .gateway_port
                    .map(|gateway_port| {
                        u16::try_from(gateway_port).map_err(|_| {
                            VmLifecycleError::new(format!(
                                "attachment TAP gateway port {gateway_port} exceeds u16"
                            ))
                        })
                    })
                    .transpose()?;
                Ok(Self::Tap {
                    ifname: attachment.ifname,
                    guest_ip: attachment.guest_ip,
                    host_ip: attachment.host_ip,
                    mac: attachment.mac,
                    gateway_port,
                })
            }
            Some(Kind::VfioPci(attachment)) => Ok(Self::VfioPci {
                bdf: attachment.bdf,
                mac: attachment.mac,
            }),
            Some(Kind::Vdpa(attachment)) => Ok(Self::Vdpa {
                device: path_from_proto(attachment.device),
                mac: attachment.mac,
            }),
            None => Err(VmLifecycleError::new(
                "attachment network attachment missing kind",
            )),
        }
    }
}

impl From<DeviceAttachment> for attachment_proto::DeviceAttachment {
    fn from(value: DeviceAttachment) -> Self {
        use attachment_proto::device_attachment::Kind;

        let kind = match value {
            DeviceAttachment::VfioPci { bdf, id } => {
                Kind::VfioPci(attachment_proto::VfioPciDeviceAttachment { bdf, id })
            }
            DeviceAttachment::Vsock { cid } => {
                Kind::Vsock(attachment_proto::VsockDeviceAttachment { cid })
            }
        };
        Self { kind: Some(kind) }
    }
}

impl TryFrom<attachment_proto::DeviceAttachment> for DeviceAttachment {
    type Error = VmLifecycleError;

    fn try_from(value: attachment_proto::DeviceAttachment) -> Result<Self, Self::Error> {
        use attachment_proto::device_attachment::Kind;

        match value.kind {
            Some(Kind::VfioPci(attachment)) => Ok(Self::VfioPci {
                bdf: attachment.bdf,
                id: attachment.id,
            }),
            Some(Kind::Vsock(attachment)) => Ok(Self::Vsock {
                cid: attachment.cid,
            }),
            None => Err(VmLifecycleError::new(
                "attachment device attachment missing kind",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attachments::StorageAttachment;
    use crate::extension::{VmLifecycleExtensions, extension_state_path};
    use openshell_core::proto::compute::v1::DriverSandbox as Sandbox;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::{Request, Response, Status};

    #[tokio::test]
    async fn vm_attachment_lifecycle_replaces_launch_plan_and_clears_state_on_failure() {
        let state_dir = unique_temp_dir();
        std::fs::create_dir_all(&state_dir).unwrap();
        let detached = Arc::new(Mutex::new(Vec::new()));
        let provider = Arc::new(RecordingAttachmentProvider {
            plan: vm_attachment_plan(),
            detached: detached.clone(),
        });
        let extensions = VmLifecycleExtensions::new(vec![Arc::new(
            VmAttachmentLifecycleExtension::new(provider),
        )])
        .unwrap();
        let sandbox = Sandbox {
            id: "sandbox-1".to_string(),
            name: "sandbox-1".to_string(),
            ..Default::default()
        };
        let mut plan = minimal_qemu_plan();

        extensions
            .before_vm_launch(&sandbox, &state_dir, "image", &mut plan)
            .await
            .unwrap();

        assert_eq!(
            plan.network,
            vec![NetworkAttachment::Vdpa {
                device: PathBuf::from("/dev/vhost-vdpa-0"),
                mac: Some("02:00:00:00:00:02".to_string()),
            }]
        );
        assert!(matches!(
            plan.rootfs.root,
            StorageAttachment::ProviderProvisioned { .. }
        ));
        assert!(
            plan.env
                .contains(&"OPENSHELL_VM_ATTACHMENT_PROVIDER=bluefield".to_string())
        );
        let state_path =
            extension_state_path(&state_dir, VM_ATTACHMENT_LIFECYCLE_EXTENSION_NAME).unwrap();
        assert!(state_path.is_file());

        extensions
            .after_vm_launch_failed(
                &sandbox,
                &state_dir,
                "image",
                &plan,
                &LaunchAbortReason::ProvisioningCancelled,
            )
            .await;

        assert_eq!(detached.lock().unwrap().as_slice(), &["lease-sandbox-1"]);
        assert!(!state_path.exists());
        let _ = std::fs::remove_dir_all(state_dir);
    }

    #[test]
    fn static_vm_attachment_provider_config_parses_attachment_template() {
        let config: StaticAttachmentProviderConfig = serde_json::from_str(
            r#"{
                "attachment_id_prefix": "bf",
                "replace_network": true,
                "network": [
                    { "kind": "vfio_pci", "bdf": "0000:04:00.1", "mac": "02:00:00:00:00:09" }
                ],
                "devices": [
                    { "kind": "vsock", "cid": 42 }
                ],
                "metadata": {
                    "provider": "static"
                }
            }"#,
        )
        .unwrap();

        assert_eq!(config.attachment_id_prefix, "bf");
        assert!(config.plan.replace_network);
        assert_eq!(config.plan.network.len(), 1);
        assert_eq!(
            config.plan.devices,
            vec![DeviceAttachment::Vsock { cid: 42 }]
        );
        assert_eq!(
            config.metadata.get("provider").map(String::as_str),
            Some("static")
        );
    }

    #[tokio::test]
    async fn grpc_vm_attachment_provider_services_many_sandboxes() {
        let server = FakeAttachmentProviderServer::default();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let incoming = TcpListenerStream::new(listener);
        let service =
            attachment_proto::attachment_provider_server::AttachmentProviderServer::new(server);
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(incoming)
                .await
                .unwrap();
        });
        let provider = GrpcAttachmentProvider::connect_lazy(format!("http://{address}")).unwrap();

        let first = provider
            .attach(attachment_request("sandbox-a"))
            .await
            .unwrap();
        let second = provider
            .attach(attachment_request("sandbox-b"))
            .await
            .unwrap();

        assert_eq!(first.attachment_id, "lease-sandbox-a");
        assert_eq!(second.attachment_id, "lease-sandbox-b");
        assert_eq!(provider.list().await.unwrap().len(), 2);

        provider.detach(first).await.unwrap();

        let leases = provider.list().await.unwrap();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].attachment_id, "lease-sandbox-b");
    }

    #[derive(Debug)]
    struct RecordingAttachmentProvider {
        plan: AttachmentPlan,
        detached: Arc<Mutex<Vec<String>>>,
    }

    #[tonic::async_trait]
    impl AttachmentProvider for RecordingAttachmentProvider {
        async fn health(&self) -> VmLifecycleResult<AttachmentProviderHealth> {
            Ok(AttachmentProviderHealth {
                healthy: true,
                message: "recording".to_string(),
                capabilities: Vec::new(),
            })
        }

        async fn attach(&self, request: AttachmentRequest) -> VmLifecycleResult<AttachmentLease> {
            Ok(AttachmentLease {
                attachment_id: format!("lease-{}", request.sandbox_id),
                generation: 1,
                plan: self.plan.clone(),
                metadata: BTreeMap::new(),
            })
        }

        async fn detach(&self, lease: AttachmentLease) -> VmLifecycleResult<()> {
            self.detached.lock().unwrap().push(lease.attachment_id);
            Ok(())
        }

        async fn list(&self) -> VmLifecycleResult<Vec<AttachmentLease>> {
            Ok(Vec::new())
        }

        async fn reconcile(&self, _lease: AttachmentLease) -> VmLifecycleResult<ReconcileOutcome> {
            Ok(ReconcileOutcome::Continue)
        }
    }

    #[derive(Debug, Default)]
    struct FakeAttachmentProviderServer {
        leases: tokio::sync::Mutex<HashMap<String, attachment_proto::AttachmentLease>>,
    }

    #[tonic::async_trait]
    impl attachment_proto::attachment_provider_server::AttachmentProvider
        for FakeAttachmentProviderServer
    {
        async fn health(
            &self,
            _request: Request<attachment_proto::HealthRequest>,
        ) -> Result<Response<attachment_proto::HealthResponse>, Status> {
            Ok(Response::new(attachment_proto::HealthResponse {
                healthy: true,
                message: "fake".to_string(),
                capabilities: vec!["multi-sandbox".to_string()],
            }))
        }

        async fn attach(
            &self,
            request: Request<attachment_proto::AttachRequest>,
        ) -> Result<Response<attachment_proto::AttachResponse>, Status> {
            let request = AttachmentRequest::try_from(request.into_inner())
                .map_err(|err| Status::invalid_argument(err.message().to_string()))?;
            let lease = AttachmentLease {
                attachment_id: format!("lease-{}", request.sandbox_id),
                generation: 1,
                plan: vm_attachment_plan(),
                metadata: BTreeMap::from([("server".to_string(), "fake".to_string())]),
            };
            let lease = attachment_proto::AttachmentLease::from(lease);
            self.leases
                .lock()
                .await
                .insert(lease.attachment_id.clone(), lease.clone());
            Ok(Response::new(attachment_proto::AttachResponse {
                lease: Some(lease),
            }))
        }

        async fn detach(
            &self,
            request: Request<attachment_proto::DetachRequest>,
        ) -> Result<Response<attachment_proto::DetachResponse>, Status> {
            let lease = request
                .into_inner()
                .lease
                .ok_or_else(|| Status::invalid_argument("missing lease"))?;
            self.leases.lock().await.remove(&lease.attachment_id);
            Ok(Response::new(attachment_proto::DetachResponse {}))
        }

        async fn list(
            &self,
            _request: Request<attachment_proto::ListRequest>,
        ) -> Result<Response<attachment_proto::ListResponse>, Status> {
            let leases = self.leases.lock().await.values().cloned().collect();
            Ok(Response::new(attachment_proto::ListResponse { leases }))
        }

        async fn reconcile(
            &self,
            request: Request<attachment_proto::ReconcileRequest>,
        ) -> Result<Response<attachment_proto::ReconcileResponse>, Status> {
            let lease = request
                .into_inner()
                .lease
                .ok_or_else(|| Status::invalid_argument("missing lease"))?;
            if self.leases.lock().await.contains_key(&lease.attachment_id) {
                let (outcome, reason) = reconcile_outcome_to_proto(ReconcileOutcome::Continue);
                Ok(Response::new(attachment_proto::ReconcileResponse {
                    outcome,
                    reason,
                }))
            } else {
                let (outcome, reason) = reconcile_outcome_to_proto(ReconcileOutcome::SkipRestore {
                    reason: "lease not found".to_string(),
                });
                Ok(Response::new(attachment_proto::ReconcileResponse {
                    outcome,
                    reason,
                }))
            }
        }
    }

    fn attachment_request(sandbox_id: &str) -> AttachmentRequest {
        AttachmentRequest {
            sandbox_id: sandbox_id.to_string(),
            sandbox_name: sandbox_id.to_string(),
            image_ref: Some("image".to_string()),
            state_dir: unique_temp_dir(),
            backend: VmBackend::Qemu,
            rootfs: minimal_qemu_plan().rootfs,
            network: minimal_qemu_plan().network,
            devices: Vec::new(),
        }
    }

    fn vm_attachment_plan() -> AttachmentPlan {
        AttachmentPlan {
            replace_network: true,
            network: vec![NetworkAttachment::Vdpa {
                device: PathBuf::from("/dev/vhost-vdpa-0"),
                mac: Some("02:00:00:00:00:02".to_string()),
            }],
            devices: vec![DeviceAttachment::VfioPci {
                bdf: "0000:03:00.0".to_string(),
                id: Some("bluefield-net".to_string()),
            }],
            rootfs: Some(RootfsConfig {
                root: StorageAttachment::ProviderProvisioned {
                    id: "rootfs-1".to_string(),
                    device: PathBuf::from("/dev/disk/by-id/nvme-rootfs-1"),
                    read_only: true,
                },
                overlay: StorageAttachment::host_file(PathBuf::from("/tmp/overlay.ext4"), false),
                image: None,
            }),
            env: vec!["OPENSHELL_VM_ATTACHMENT_PROVIDER=bluefield".to_string()],
        }
    }

    fn minimal_qemu_plan() -> VmLaunchPlan {
        VmLaunchPlan {
            rootfs: RootfsConfig::host_files(
                PathBuf::from("/tmp/root.ext4"),
                PathBuf::from("/tmp/overlay.ext4"),
                None,
            ),
            exec_path: "/init".to_string(),
            workdir: "/".to_string(),
            console_output: PathBuf::from("/tmp/console.log"),
            vcpus: 2,
            mem_mib: 2048,
            krun_log_level: 1,
            env: Vec::new(),
            backend: VmBackend::Qemu,
            network: vec![NetworkAttachment::Tap {
                ifname: "vmtap0".to_string(),
                guest_ip: "10.0.0.2".to_string(),
                host_ip: "10.0.0.1".to_string(),
                mac: "02:00:00:00:00:01".to_string(),
                gateway_port: None,
            }],
            devices: Vec::new(),
            extra_launcher_args: Vec::new(),
        }
    }

    fn unique_temp_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let suffix = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "openshell-vm-attachment-provider-test-{}-{nanos}-{suffix}",
            std::process::id()
        ))
    }
}
