// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Static `BlueField` attachment inventory.
//!
//! This is the first backend-facing representation. It deliberately models the
//! plan the provider can hand back today; later hardware allocators can replace
//! this with dynamic VF/rootfs allocation while preserving the backend service
//! boundary.

use std::collections::HashSet;

use openshell_core::proto::attachment::v1 as proto;

use crate::provider::{AttachmentProviderError, AttachmentProviderResult};

pub const METADATA_VF_HOST_BDF: &str = "vf_host_bdf";
pub const METADATA_VF_REPRESENTOR: &str = "vf_representor";
pub const METADATA_VF_SLOT_ID: &str = "vf_slot_id";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlueFieldVfSlot {
    pub id: String,
    pub host_bdf: String,
    pub mac: Option<String>,
    pub representor: Option<String>,
}

impl BlueFieldVfSlot {
    pub fn new(id: impl Into<String>, host_bdf: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            host_bdf: host_bdf.into(),
            mac: None,
            representor: None,
        }
    }

    #[must_use]
    pub fn with_mac(mut self, mac: impl Into<String>) -> Self {
        self.mac = Some(mac.into());
        self
    }

    #[must_use]
    pub fn with_representor(mut self, representor: impl Into<String>) -> Self {
        self.representor = Some(representor.into());
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct BlueFieldInventory {
    pub replace_network: bool,
    pub network: Vec<proto::NetworkAttachment>,
    pub devices: Vec<proto::DeviceAttachment>,
    pub rootfs: Option<proto::RootfsConfig>,
    pub env: Vec<String>,
    pub vf_pool: Vec<BlueFieldVfSlot>,
}

impl BlueFieldInventory {
    pub fn empty() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn replace_network(mut self, replace_network: bool) -> Self {
        self.replace_network = replace_network;
        self
    }

    #[must_use]
    pub fn with_network(
        mut self,
        network: impl IntoIterator<Item = proto::NetworkAttachment>,
    ) -> Self {
        self.network = network.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_devices(
        mut self,
        devices: impl IntoIterator<Item = proto::DeviceAttachment>,
    ) -> Self {
        self.devices = devices.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_rootfs(mut self, rootfs: proto::RootfsConfig) -> Self {
        self.rootfs = Some(rootfs);
        self
    }

    #[must_use]
    pub fn with_env(mut self, env: impl IntoIterator<Item = String>) -> Self {
        self.env = env.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_vf_pool(mut self, vf_pool: impl IntoIterator<Item = BlueFieldVfSlot>) -> Self {
        self.vf_pool = vf_pool.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_vf_slot(mut self, slot: BlueFieldVfSlot) -> Self {
        self.vf_pool.push(slot);
        self
    }

    pub(crate) fn validate(&self) -> AttachmentProviderResult<()> {
        let mut slot_ids = HashSet::new();
        let mut host_bdfs = HashSet::new();
        for slot in &self.vf_pool {
            validate_required("vf_pool.id", &slot.id)?;
            validate_required("vf_pool.host_bdf", &slot.host_bdf)?;
            if !slot_ids.insert(slot.id.as_str()) {
                return Err(AttachmentProviderError::invalid_argument(format!(
                    "duplicate BlueField VF slot id '{}'",
                    slot.id
                )));
            }
            if !host_bdfs.insert(slot.host_bdf.as_str()) {
                return Err(AttachmentProviderError::invalid_argument(format!(
                    "duplicate BlueField VF host BDF '{}'",
                    slot.host_bdf
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn allocate_vf_slot<'a>(
        &'a self,
        active_leases: &[proto::AttachmentLease],
    ) -> AttachmentProviderResult<Option<&'a BlueFieldVfSlot>> {
        if self.vf_pool.is_empty() {
            return Ok(None);
        }

        let leased_slots = active_leases
            .iter()
            .filter_map(|lease| lease.metadata.get(METADATA_VF_SLOT_ID).map(String::as_str))
            .collect::<HashSet<_>>();
        self.vf_pool
            .iter()
            .find(|slot| !leased_slots.contains(slot.id.as_str()))
            .map(Some)
            .ok_or_else(|| {
                AttachmentProviderError::failed_precondition("no free BlueField VF slots available")
            })
    }

    pub(crate) fn plan_for(
        &self,
        request: &proto::AttachRequest,
        vf_slot: Option<&BlueFieldVfSlot>,
    ) -> proto::AttachmentPlan {
        let mut network = self.network.clone();
        if let Some(vf_slot) = vf_slot {
            network.push(proto::NetworkAttachment {
                kind: Some(proto::network_attachment::Kind::VfioPci(
                    proto::VfioPciNetworkAttachment {
                        bdf: vf_slot.host_bdf.clone(),
                        mac: vf_slot.mac.clone(),
                    },
                )),
            });
        }

        proto::AttachmentPlan {
            replace_network: self.replace_network || vf_slot.is_some(),
            network,
            devices: self.devices.clone(),
            rootfs: self.rootfs.clone().or_else(|| request.rootfs.clone()),
            env: self.env.clone(),
        }
    }
}

fn validate_required(field: &str, value: &str) -> AttachmentProviderResult<()> {
    if value.trim().is_empty() {
        return Err(AttachmentProviderError::invalid_argument(format!(
            "{field} is required"
        )));
    }
    Ok(())
}
