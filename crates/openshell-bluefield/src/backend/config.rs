// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Backend configuration.

use crate::backend::inventory::BlueFieldInventory;
use crate::provider::{
    AttachmentProviderError, AttachmentProviderResult, CAPABILITY_NETWORK_OVS,
    CAPABILITY_NETWORK_VFIO_PCI, CAPABILITY_STORAGE_PROVIDER_PROVISIONED,
};

#[derive(Debug, Clone, PartialEq)]
pub struct BlueFieldAttachmentBackendConfig {
    pub host_id: String,
    pub attachment_id_prefix: String,
    pub capabilities: Vec<String>,
    pub inventory: BlueFieldInventory,
}

impl BlueFieldAttachmentBackendConfig {
    pub fn new(host_id: impl Into<String>) -> Self {
        Self {
            host_id: host_id.into(),
            attachment_id_prefix: "bluefield".to_string(),
            capabilities: default_capabilities(),
            inventory: BlueFieldInventory::default(),
        }
    }

    #[must_use]
    pub fn with_attachment_id_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.attachment_id_prefix = prefix.into();
        self
    }

    #[must_use]
    pub fn with_capabilities(mut self, capabilities: impl IntoIterator<Item = String>) -> Self {
        self.capabilities = capabilities.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_inventory(mut self, inventory: BlueFieldInventory) -> Self {
        self.inventory = inventory;
        self
    }

    pub(crate) fn validate(&self) -> AttachmentProviderResult<()> {
        validate_required("host_id", &self.host_id)?;
        validate_required("attachment_id_prefix", &self.attachment_id_prefix)?;
        if self.capabilities.is_empty() {
            return Err(AttachmentProviderError::invalid_argument(
                "at least one backend capability is required",
            ));
        }
        self.inventory.validate()?;
        Ok(())
    }
}

impl Default for BlueFieldAttachmentBackendConfig {
    fn default() -> Self {
        Self::new("bluefield")
    }
}

fn default_capabilities() -> Vec<String> {
    [
        CAPABILITY_NETWORK_OVS,
        CAPABILITY_NETWORK_VFIO_PCI,
        CAPABILITY_STORAGE_PROVIDER_PROVISIONED,
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn validate_required(field: &str, value: &str) -> AttachmentProviderResult<()> {
    if value.trim().is_empty() {
        return Err(AttachmentProviderError::invalid_argument(format!(
            "{field} is required"
        )));
    }
    Ok(())
}
