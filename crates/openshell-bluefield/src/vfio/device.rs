// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! VFIO device model and preparation contract.

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VfioDeviceId {
    pub bdf: String,
}

impl VfioDeviceId {
    pub fn new(bdf: impl Into<String>) -> Self {
        Self { bdf: bdf.into() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedVfioDevice {
    pub id: VfioDeviceId,
    pub iommu_group: Option<String>,
}

#[derive(Debug, Error)]
pub enum VfioDeviceError {
    #[error("VFIO PCI BDF is required")]
    EmptyBdf,
    #[error("invalid VFIO PCI BDF '{0}'")]
    InvalidBdf(String),
    #[error("VFIO device {bdf} is not present")]
    MissingDevice { bdf: String },
    #[error("failed to prepare VFIO device {bdf}: {message}")]
    Prepare { bdf: String, message: String },
}

pub trait VfioDeviceManager: std::fmt::Debug + Send + Sync + 'static {
    fn prepare_for_passthrough(
        &self,
        id: &VfioDeviceId,
    ) -> Result<PreparedVfioDevice, VfioDeviceError>;

    fn release_from_passthrough(&self, id: &VfioDeviceId) -> Result<(), VfioDeviceError>;
}

pub(crate) fn validate_pci_bdf(bdf: &str) -> Result<(), VfioDeviceError> {
    if bdf.trim().is_empty() {
        return Err(VfioDeviceError::EmptyBdf);
    }
    let parts = bdf.split(':').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(VfioDeviceError::InvalidBdf(bdf.to_string()));
    }
    if parts[0].len() != 4
        || parts[1].len() != 2
        || !parts[2].contains('.')
        || !parts
            .iter()
            .flat_map(|part| part.split('.'))
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(VfioDeviceError::InvalidBdf(bdf.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_canonical_pci_bdf() {
        validate_pci_bdf("0000:03:00.2").unwrap();
    }

    #[test]
    fn rejects_empty_pci_bdf() {
        assert!(matches!(
            validate_pci_bdf(" "),
            Err(VfioDeviceError::EmptyBdf)
        ));
    }

    #[test]
    fn rejects_malformed_pci_bdf() {
        assert!(matches!(
            validate_pci_bdf("03:00.2"),
            Err(VfioDeviceError::InvalidBdf(_))
        ));
    }
}
