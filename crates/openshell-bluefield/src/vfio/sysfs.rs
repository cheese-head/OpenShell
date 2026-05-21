// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sysfs-backed VFIO preparation.

use std::path::{Path, PathBuf};

use crate::vfio::device::{
    PreparedVfioDevice, VfioDeviceError, VfioDeviceId, VfioDeviceManager, validate_pci_bdf,
};

pub const DEFAULT_SYSFS_PCI_DEVICES: &str = "/sys/bus/pci/devices";
pub const VFIO_PCI_DRIVER: &str = "vfio-pci";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VfioBindPlan {
    pub bdf: String,
    pub device_path: PathBuf,
    pub driver_override_path: PathBuf,
    pub drivers_probe_path: PathBuf,
    pub current_driver: Option<String>,
    pub target_driver: String,
}

#[derive(Debug, Clone)]
pub struct SysfsVfioDeviceManager {
    devices: PathBuf,
    drivers: PathBuf,
    drivers_probe: PathBuf,
}

impl SysfsVfioDeviceManager {
    pub fn new(pci_devices_path: impl Into<PathBuf>) -> Self {
        let pci_devices_path = pci_devices_path.into();
        let pci_bus_path = pci_devices_path.parent().map_or_else(
            || PathBuf::from(DEFAULT_SYSFS_PCI_DEVICES),
            Path::to_path_buf,
        );
        Self {
            devices: pci_devices_path,
            drivers: pci_bus_path.join("drivers"),
            drivers_probe: pci_bus_path.join("drivers_probe"),
        }
    }

    pub fn system() -> Self {
        Self::new(DEFAULT_SYSFS_PCI_DEVICES)
    }

    pub fn bind_plan(&self, id: &VfioDeviceId) -> Result<VfioBindPlan, VfioDeviceError> {
        validate_pci_bdf(&id.bdf)?;
        let device_path = self.device_path(&id.bdf);
        if !device_path.exists() {
            return Err(VfioDeviceError::MissingDevice {
                bdf: id.bdf.clone(),
            });
        }
        Ok(VfioBindPlan {
            bdf: id.bdf.clone(),
            driver_override_path: device_path.join("driver_override"),
            drivers_probe_path: self.drivers_probe.clone(),
            current_driver: current_driver_name(&device_path),
            target_driver: VFIO_PCI_DRIVER.to_string(),
            device_path,
        })
    }

    fn device_path(&self, bdf: &str) -> PathBuf {
        self.devices.join(bdf)
    }

    fn driver_path(&self, driver: &str) -> PathBuf {
        self.drivers.join(driver)
    }
}

impl Default for SysfsVfioDeviceManager {
    fn default() -> Self {
        Self::system()
    }
}

impl VfioDeviceManager for SysfsVfioDeviceManager {
    fn prepare_for_passthrough(
        &self,
        id: &VfioDeviceId,
    ) -> Result<PreparedVfioDevice, VfioDeviceError> {
        let bind_plan = self.bind_plan(id)?;
        if bind_plan.current_driver.as_deref() != Some(VFIO_PCI_DRIVER) {
            write_sysfs(&bind_plan.driver_override_path, VFIO_PCI_DRIVER, &id.bdf)?;
            if bind_plan.current_driver.is_some() {
                write_sysfs(
                    &bind_plan.device_path.join("driver/unbind"),
                    &id.bdf,
                    &id.bdf,
                )?;
            }
            write_sysfs(&bind_plan.drivers_probe_path, &id.bdf, &id.bdf)?;
        }

        Ok(PreparedVfioDevice {
            id: VfioDeviceId::new(bind_plan.bdf),
            iommu_group: iommu_group_name(&bind_plan.device_path),
        })
    }

    fn release_from_passthrough(&self, id: &VfioDeviceId) -> Result<(), VfioDeviceError> {
        validate_pci_bdf(&id.bdf)?;
        let device_path = self.device_path(&id.bdf);
        if !device_path.exists() {
            return Ok(());
        }

        if current_driver_name(&device_path).as_deref() == Some(VFIO_PCI_DRIVER) {
            write_sysfs(&device_path.join("driver_override"), "", &id.bdf)?;
            write_sysfs(
                &self.driver_path(VFIO_PCI_DRIVER).join("unbind"),
                &id.bdf,
                &id.bdf,
            )?;
        }
        Ok(())
    }
}

fn iommu_group_name(device_path: &Path) -> Option<String> {
    let link = device_path.join("iommu_group");
    std::fs::read_link(link).ok().and_then(|path| {
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
    })
}

fn current_driver_name(device_path: &Path) -> Option<String> {
    std::fs::read_link(device_path.join("driver"))
        .ok()
        .and_then(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
}

fn write_sysfs(path: &Path, value: &str, bdf: &str) -> Result<(), VfioDeviceError> {
    std::fs::write(path, format!("{value}\n")).map_err(|err| VfioDeviceError::Prepare {
        bdf: bdf.to_string(),
        message: format!("write '{}': {err}", path.display()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_plan_requires_existing_device() {
        let manager = SysfsVfioDeviceManager::new("/definitely/not/sysfs");

        let error = manager
            .bind_plan(&VfioDeviceId::new("0000:03:00.2"))
            .unwrap_err();

        assert!(matches!(error, VfioDeviceError::MissingDevice { .. }));
    }

    #[test]
    fn prepare_for_passthrough_writes_driver_override_and_probe() {
        let dir = tempfile::tempdir().unwrap();
        let pci_bus = dir.path().join("bus/pci");
        let device = pci_bus.join("devices/0000:03:00.2");
        std::fs::create_dir_all(&device).unwrap();
        std::fs::write(device.join("driver_override"), "").unwrap();
        std::fs::write(pci_bus.join("drivers_probe"), "").unwrap();

        let manager = SysfsVfioDeviceManager::new(pci_bus.join("devices"));

        manager
            .prepare_for_passthrough(&VfioDeviceId::new("0000:03:00.2"))
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(device.join("driver_override")).unwrap(),
            "vfio-pci\n"
        );
        assert_eq!(
            std::fs::read_to_string(pci_bus.join("drivers_probe")).unwrap(),
            "0000:03:00.2\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn release_from_passthrough_unbinds_vfio_driver() {
        let dir = tempfile::tempdir().unwrap();
        let pci_bus = dir.path().join("bus/pci");
        let device = pci_bus.join("devices/0000:03:00.2");
        let vfio_driver = pci_bus.join("drivers/vfio-pci");
        std::fs::create_dir_all(&device).unwrap();
        std::fs::create_dir_all(&vfio_driver).unwrap();
        std::fs::write(device.join("driver_override"), "vfio-pci\n").unwrap();
        std::fs::write(vfio_driver.join("unbind"), "").unwrap();
        std::os::unix::fs::symlink(&vfio_driver, device.join("driver")).unwrap();

        let manager = SysfsVfioDeviceManager::new(pci_bus.join("devices"));

        manager
            .release_from_passthrough(&VfioDeviceId::new("0000:03:00.2"))
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(device.join("driver_override")).unwrap(),
            "\n"
        );
        assert_eq!(
            std::fs::read_to_string(vfio_driver.join("unbind")).unwrap(),
            "0000:03:00.2\n"
        );
    }
}
