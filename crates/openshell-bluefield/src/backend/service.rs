// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `BlueField` backend implementation for the attachment-provider service.

use openshell_core::proto::attachment::v1 as proto;

use crate::backend::actuator::{AttachmentActuator, NoopAttachmentActuator};
use crate::backend::config::BlueFieldAttachmentBackendConfig;
use crate::backend::inventory::{
    BlueFieldVfSlot, METADATA_VF_HOST_BDF, METADATA_VF_REPRESENTOR, METADATA_VF_SLOT_ID,
};
use crate::backend::lease::{InMemoryLeaseStore, LeaseStore};
use crate::provider::{AttachmentProviderBackend, AttachmentProviderResult};

#[derive(Debug, Clone)]
pub struct BlueFieldAttachmentBackend<S = InMemoryLeaseStore, A = NoopAttachmentActuator> {
    config: BlueFieldAttachmentBackendConfig,
    leases: S,
    actuator: A,
}

impl BlueFieldAttachmentBackend<InMemoryLeaseStore, NoopAttachmentActuator> {
    pub fn new(config: BlueFieldAttachmentBackendConfig) -> AttachmentProviderResult<Self> {
        Self::with_lease_store(config, InMemoryLeaseStore::new())
    }
}

impl<S> BlueFieldAttachmentBackend<S, NoopAttachmentActuator>
where
    S: LeaseStore,
{
    pub fn with_lease_store(
        config: BlueFieldAttachmentBackendConfig,
        leases: S,
    ) -> AttachmentProviderResult<Self> {
        Self::with_lease_store_and_actuator(config, leases, NoopAttachmentActuator)
    }
}

impl<S, A> BlueFieldAttachmentBackend<S, A>
where
    S: LeaseStore,
    A: AttachmentActuator,
{
    pub fn with_lease_store_and_actuator(
        config: BlueFieldAttachmentBackendConfig,
        leases: S,
        actuator: A,
    ) -> AttachmentProviderResult<Self> {
        config.validate()?;
        Ok(Self {
            config,
            leases,
            actuator,
        })
    }

    pub fn config(&self) -> &BlueFieldAttachmentBackendConfig {
        &self.config
    }

    pub fn lease_store(&self) -> &S {
        &self.leases
    }

    pub fn actuator(&self) -> &A {
        &self.actuator
    }
}

#[tonic::async_trait]
impl<S, A> AttachmentProviderBackend for BlueFieldAttachmentBackend<S, A>
where
    S: LeaseStore,
    A: AttachmentActuator,
{
    async fn health(&self) -> AttachmentProviderResult<proto::HealthResponse> {
        Ok(proto::HealthResponse {
            healthy: true,
            message: format!(
                "BlueField attachment backend ready on {}",
                self.config.host_id
            ),
            capabilities: self.config.capabilities.clone(),
        })
    }

    async fn attach(
        &self,
        request: proto::AttachRequest,
    ) -> AttachmentProviderResult<proto::AttachmentLease> {
        let active_leases = self.leases.list().await?;
        if let Some(existing) = existing_lease_for_sandbox(&active_leases, &request.sandbox_id) {
            self.actuator.reconcile_lease(existing)?;
            return Ok(existing.clone());
        }

        let vf_slot = self
            .config
            .inventory
            .allocate_vf_slot(&active_leases)?
            .cloned();
        let lease = proto::AttachmentLease {
            attachment_id: self.attachment_id_for(&request.sandbox_id),
            generation: 1,
            plan: Some(self.config.inventory.plan_for(&request, vf_slot.as_ref())),
            metadata: lease_metadata(&self.config, &request, vf_slot.as_ref()),
        };
        self.actuator.prepare_attach(&lease)?;
        if let Err(err) = self.leases.put(lease.clone()).await {
            let _ = self.actuator.cleanup_detach(&lease);
            return Err(err);
        }
        Ok(lease)
    }

    async fn detach(&self, lease: proto::AttachmentLease) -> AttachmentProviderResult<()> {
        self.actuator.cleanup_detach(&lease)?;
        self.leases.remove(&lease.attachment_id).await?;
        Ok(())
    }

    async fn list(&self) -> AttachmentProviderResult<Vec<proto::AttachmentLease>> {
        self.leases.list().await
    }

    async fn reconcile(
        &self,
        lease: proto::AttachmentLease,
    ) -> AttachmentProviderResult<proto::ReconcileResponse> {
        let stored = self
            .leases
            .list()
            .await?
            .into_iter()
            .find(|stored| stored.attachment_id == lease.attachment_id);
        if let Some(stored) = stored {
            self.actuator.reconcile_lease(&stored)?;
            Ok(proto::ReconcileResponse {
                outcome: proto::ReconcileOutcome::Continue as i32,
                reason: String::new(),
            })
        } else {
            Ok(proto::ReconcileResponse {
                outcome: proto::ReconcileOutcome::SkipRestore as i32,
                reason: format!("attachment lease '{}' is not present", lease.attachment_id),
            })
        }
    }
}

impl<S, A> BlueFieldAttachmentBackend<S, A>
where
    S: LeaseStore,
    A: AttachmentActuator,
{
    fn attachment_id_for(&self, sandbox_id: &str) -> String {
        format!("{}-{sandbox_id}", self.config.attachment_id_prefix)
    }
}

fn existing_lease_for_sandbox<'a>(
    leases: &'a [proto::AttachmentLease],
    sandbox_id: &str,
) -> Option<&'a proto::AttachmentLease> {
    leases.iter().find(|lease| {
        lease
            .metadata
            .get("sandbox_id")
            .is_some_and(|id| id == sandbox_id)
    })
}

fn lease_metadata(
    config: &BlueFieldAttachmentBackendConfig,
    request: &proto::AttachRequest,
    vf_slot: Option<&BlueFieldVfSlot>,
) -> std::collections::HashMap<String, String> {
    let mut metadata = [
        ("provider".to_string(), "openshell-bluefield".to_string()),
        ("host_id".to_string(), config.host_id.clone()),
        ("sandbox_id".to_string(), request.sandbox_id.clone()),
        ("sandbox_name".to_string(), request.sandbox_name.clone()),
    ]
    .into_iter()
    .collect::<std::collections::HashMap<_, _>>();

    if let Some(vf_slot) = vf_slot {
        metadata.insert(METADATA_VF_SLOT_ID.to_string(), vf_slot.id.clone());
        metadata.insert(METADATA_VF_HOST_BDF.to_string(), vf_slot.host_bdf.clone());
        if let Some(representor) = &vf_slot.representor {
            metadata.insert(METADATA_VF_REPRESENTOR.to_string(), representor.clone());
        }
    }

    metadata
}

#[cfg(test)]
mod tests {
    use tonic::Code;

    use crate::backend::inventory::{BlueFieldInventory, BlueFieldVfSlot};
    use crate::provider::{
        AttachmentProviderBackend, CAPABILITY_NETWORK_VDPA, CAPABILITY_NETWORK_VFIO_PCI,
    };

    use super::*;

    #[test]
    fn backend_default_capabilities_focus_on_vfio_not_vdpa() {
        let capabilities = BlueFieldAttachmentBackendConfig::new("bf-a").capabilities;

        assert!(capabilities.contains(&CAPABILITY_NETWORK_VFIO_PCI.to_string()));
        assert!(!capabilities.contains(&CAPABILITY_NETWORK_VDPA.to_string()));
    }

    #[tokio::test]
    async fn backend_attaches_idempotently_and_lists_leases() {
        let backend =
            BlueFieldAttachmentBackend::new(BlueFieldAttachmentBackendConfig::new("bf-a")).unwrap();

        let first = backend.attach(attach_request("sandbox-1")).await.unwrap();
        let second = backend.attach(attach_request("sandbox-1")).await.unwrap();

        assert_eq!(first.attachment_id, "bluefield-sandbox-1");
        assert_eq!(first, second);
        assert_eq!(backend.list().await.unwrap(), vec![first]);
    }

    #[tokio::test]
    async fn backend_uses_static_inventory_plan() {
        let inventory = BlueFieldInventory::empty()
            .replace_network(true)
            .with_env(["BF_ATTACHMENT=enabled".to_string()]);
        let backend = BlueFieldAttachmentBackend::new(
            BlueFieldAttachmentBackendConfig::new("bf-a").with_inventory(inventory),
        )
        .unwrap();

        let lease = backend.attach(attach_request("sandbox-1")).await.unwrap();
        let plan = lease.plan.unwrap();

        assert!(plan.replace_network);
        assert_eq!(plan.env, ["BF_ATTACHMENT=enabled"]);
    }

    #[tokio::test]
    async fn backend_allocates_vfio_network_attachment_from_vf_pool() {
        let inventory = BlueFieldInventory::empty().with_vf_slot(
            BlueFieldVfSlot::new("vf0", "0000:03:00.2")
                .with_mac("02:00:00:00:00:10")
                .with_representor("pf0vf0"),
        );
        let backend = BlueFieldAttachmentBackend::new(
            BlueFieldAttachmentBackendConfig::new("bf-a").with_inventory(inventory),
        )
        .unwrap();

        let lease = backend.attach(attach_request("sandbox-1")).await.unwrap();
        let same = backend.attach(attach_request("sandbox-1")).await.unwrap();

        assert_eq!(lease, same);
        assert_eq!(
            lease.metadata.get(METADATA_VF_SLOT_ID).map(String::as_str),
            Some("vf0")
        );
        assert_eq!(
            lease.metadata.get(METADATA_VF_HOST_BDF).map(String::as_str),
            Some("0000:03:00.2")
        );
        assert_eq!(
            lease
                .metadata
                .get(METADATA_VF_REPRESENTOR)
                .map(String::as_str),
            Some("pf0vf0")
        );

        let plan = lease.plan.unwrap();
        assert!(plan.replace_network);
        assert_eq!(plan.network.len(), 1);
        let Some(proto::network_attachment::Kind::VfioPci(vfio)) = plan.network[0].kind.as_ref()
        else {
            panic!("expected vfio-pci network attachment");
        };
        assert_eq!(vfio.bdf, "0000:03:00.2");
        assert_eq!(vfio.mac.as_deref(), Some("02:00:00:00:00:10"));
    }

    #[tokio::test]
    async fn backend_allocates_distinct_vfs_and_releases_on_detach() {
        let inventory = BlueFieldInventory::empty().with_vf_pool([
            BlueFieldVfSlot::new("vf0", "0000:03:00.2"),
            BlueFieldVfSlot::new("vf1", "0000:03:00.3"),
        ]);
        let backend = BlueFieldAttachmentBackend::new(
            BlueFieldAttachmentBackendConfig::new("bf-a").with_inventory(inventory),
        )
        .unwrap();

        let first = backend.attach(attach_request("sandbox-1")).await.unwrap();
        let second = backend.attach(attach_request("sandbox-2")).await.unwrap();

        assert_eq!(
            first.metadata.get(METADATA_VF_SLOT_ID).map(String::as_str),
            Some("vf0")
        );
        assert_eq!(
            second.metadata.get(METADATA_VF_SLOT_ID).map(String::as_str),
            Some("vf1")
        );

        let exhausted = backend
            .attach(attach_request("sandbox-3"))
            .await
            .unwrap_err();
        assert_eq!(exhausted.code(), Code::FailedPrecondition);

        backend.detach(first).await.unwrap();

        let third = backend.attach(attach_request("sandbox-3")).await.unwrap();
        assert_eq!(
            third.metadata.get(METADATA_VF_SLOT_ID).map(String::as_str),
            Some("vf0")
        );
    }

    #[tokio::test]
    async fn backend_detach_is_idempotent_and_reconcile_skips_missing_lease() {
        let backend =
            BlueFieldAttachmentBackend::new(BlueFieldAttachmentBackendConfig::new("bf-a")).unwrap();
        let lease = backend.attach(attach_request("sandbox-1")).await.unwrap();

        backend.detach(lease.clone()).await.unwrap();
        backend.detach(lease.clone()).await.unwrap();

        let reconcile = backend.reconcile(lease).await.unwrap();
        assert_eq!(
            reconcile.outcome,
            proto::ReconcileOutcome::SkipRestore as i32
        );
    }

    fn attach_request(sandbox_id: &str) -> proto::AttachRequest {
        proto::AttachRequest {
            sandbox_id: sandbox_id.to_string(),
            sandbox_name: format!("{sandbox_id}-name"),
            image_ref: Some("example.test/rootfs:latest".to_string()),
            consumer: "qemu".to_string(),
            rootfs: Some(proto::RootfsConfig::default()),
            network: Vec::new(),
            devices: Vec::new(),
        }
    }
}
