// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! File-backed configuration for the `openshell-bluefield` provider.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

use crate::backend::{BlueFieldAttachmentBackendConfig, BlueFieldInventory, BlueFieldVfSlot};

pub const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:50071";
pub const DEFAULT_ATTACHMENT_ID_PREFIX: &str = "bluefield";
pub const DEFAULT_OVS_BRIDGE: &str = "br-openshell";
pub const DEFAULT_LEASE_PATH: &str = "target/openshell-bluefield/leases.pb";
pub const DEFAULT_OVS_OFCTL: &str = "ovs-ofctl";
pub const DEFAULT_SYSFS_PCI_DEVICES: &str = "/sys/bus/pci/devices";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BlueFieldProviderConfig {
    pub bind_address: SocketAddr,
    pub host_id: String,
    pub attachment_id_prefix: String,
    pub lease_path: PathBuf,
    pub ovs_bridge: String,
    pub ovs_ofctl: String,
    pub vfio_mode: BlueFieldVfioMode,
    pub sysfs_pci_devices_path: PathBuf,
    pub vf_pool: Vec<BlueFieldVfSlotConfig>,
    pub tls: Option<BlueFieldProviderTlsConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BlueFieldVfioMode {
    Managed,
    Prebound,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlueFieldProviderTlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub client_ca: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlueFieldVfSlotConfig {
    pub id: String,
    pub host_bdf: String,
    pub mac: Option<String>,
    pub representor: Option<String>,
}

#[derive(Debug, Error)]
pub enum BlueFieldProviderConfigError {
    #[error("failed to read BlueField provider config {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse BlueField provider config {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
}

impl BlueFieldProviderConfig {
    pub fn load_from_file(path: &Path) -> Result<Self, BlueFieldProviderConfigError> {
        let contents =
            std::fs::read_to_string(path).map_err(|source| BlueFieldProviderConfigError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        toml::from_str(&contents).map_err(|source| BlueFieldProviderConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn backend_config(&self) -> BlueFieldAttachmentBackendConfig {
        BlueFieldAttachmentBackendConfig::new(self.host_id.clone())
            .with_attachment_id_prefix(self.attachment_id_prefix.clone())
            .with_inventory(self.inventory())
    }

    pub fn inventory(&self) -> BlueFieldInventory {
        BlueFieldInventory::empty()
            .with_vf_pool(self.vf_pool.iter().cloned().map(BlueFieldVfSlot::from))
    }
}

impl Default for BlueFieldProviderConfig {
    fn default() -> Self {
        Self {
            bind_address: DEFAULT_BIND_ADDRESS
                .parse()
                .expect("default BlueField provider bind address is valid"),
            host_id: "bluefield".to_string(),
            attachment_id_prefix: DEFAULT_ATTACHMENT_ID_PREFIX.to_string(),
            lease_path: PathBuf::from(DEFAULT_LEASE_PATH),
            ovs_bridge: DEFAULT_OVS_BRIDGE.to_string(),
            ovs_ofctl: DEFAULT_OVS_OFCTL.to_string(),
            vfio_mode: BlueFieldVfioMode::Managed,
            sysfs_pci_devices_path: PathBuf::from(DEFAULT_SYSFS_PCI_DEVICES),
            vf_pool: Vec::new(),
            tls: None,
        }
    }
}

impl From<BlueFieldVfSlotConfig> for BlueFieldVfSlot {
    fn from(value: BlueFieldVfSlotConfig) -> Self {
        let slot = Self::new(value.id, value.host_bdf);
        let slot = if let Some(mac) = value.mac {
            slot.with_mac(mac)
        } else {
            slot
        };
        if let Some(representor) = value.representor {
            slot.with_representor(representor)
        } else {
            slot
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_runnable_without_vfs() {
        let config = BlueFieldProviderConfig::default();

        assert_eq!(config.bind_address.to_string(), DEFAULT_BIND_ADDRESS);
        assert_eq!(config.host_id, "bluefield");
        assert_eq!(config.attachment_id_prefix, DEFAULT_ATTACHMENT_ID_PREFIX);
        assert_eq!(config.lease_path, PathBuf::from(DEFAULT_LEASE_PATH));
        assert_eq!(config.ovs_bridge, DEFAULT_OVS_BRIDGE);
        assert_eq!(config.ovs_ofctl, DEFAULT_OVS_OFCTL);
        assert_eq!(config.vfio_mode, BlueFieldVfioMode::Managed);
        assert_eq!(
            config.sysfs_pci_devices_path,
            PathBuf::from(DEFAULT_SYSFS_PCI_DEVICES)
        );
        assert!(config.vf_pool.is_empty());
        assert!(config.tls.is_none());
    }

    #[test]
    fn parses_vf_pool_config() {
        let config: BlueFieldProviderConfig = toml::from_str(
            r#"
bind_address = "0.0.0.0:50071"
host_id = "bf-a"
attachment_id_prefix = "bf"
lease_path = "/var/lib/openshell-bluefield/leases.pb"
ovs_bridge = "br-bluefield"
ovs_ofctl = "/usr/bin/ovs-ofctl"
vfio_mode = "prebound"
sysfs_pci_devices_path = "/sys/bus/pci/devices"

[[vf_pool]]
id = "vf0"
host_bdf = "0000:03:00.2"
mac = "02:00:00:00:00:10"
representor = "pf0vf0"

[[vf_pool]]
id = "vf1"
host_bdf = "0000:03:00.3"
"#,
        )
        .unwrap();

        assert_eq!(config.bind_address.to_string(), "0.0.0.0:50071");
        assert_eq!(
            config.lease_path,
            PathBuf::from("/var/lib/openshell-bluefield/leases.pb")
        );
        assert_eq!(config.ovs_ofctl, "/usr/bin/ovs-ofctl");
        assert_eq!(config.vfio_mode, BlueFieldVfioMode::Prebound);
        assert_eq!(config.vf_pool.len(), 2);

        let inventory = config.inventory();
        assert_eq!(inventory.vf_pool[0].id, "vf0");
        assert_eq!(inventory.vf_pool[0].host_bdf, "0000:03:00.2");
        assert_eq!(
            inventory.vf_pool[0].mac.as_deref(),
            Some("02:00:00:00:00:10")
        );
        assert_eq!(inventory.vf_pool[0].representor.as_deref(), Some("pf0vf0"));
    }
}
