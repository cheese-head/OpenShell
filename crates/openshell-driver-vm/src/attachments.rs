// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VmStorageAttachment {
    HostFile {
        path: PathBuf,
        #[serde(default)]
        read_only: bool,
    },
    HostBlockDevice {
        path: PathBuf,
        #[serde(default)]
        read_only: bool,
    },
    ProviderProvisioned {
        id: String,
        device: PathBuf,
        #[serde(default)]
        read_only: bool,
    },
}

impl VmStorageAttachment {
    pub fn host_file(path: PathBuf, read_only: bool) -> Self {
        Self::HostFile { path, read_only }
    }

    pub fn path(&self) -> &Path {
        match self {
            Self::HostFile { path, .. } | Self::HostBlockDevice { path, .. } => path,
            Self::ProviderProvisioned { device, .. } => device,
        }
    }

    pub fn read_only(&self) -> bool {
        match self {
            Self::HostFile { read_only, .. }
            | Self::HostBlockDevice { read_only, .. }
            | Self::ProviderProvisioned { read_only, .. } => *read_only,
        }
    }

    pub(crate) fn requires_regular_file(&self) -> bool {
        matches!(self, Self::HostFile { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmRootfsConfig {
    pub root: VmStorageAttachment,
    pub overlay: VmStorageAttachment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<VmStorageAttachment>,
}

impl VmRootfsConfig {
    pub fn host_files(root: PathBuf, overlay: PathBuf, image: Option<PathBuf>) -> Self {
        Self {
            root: VmStorageAttachment::host_file(root, true),
            overlay: VmStorageAttachment::host_file(overlay, false),
            image: image.map(|path| VmStorageAttachment::host_file(path, true)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VmNetworkAttachment {
    Tap {
        ifname: String,
        guest_ip: String,
        host_ip: String,
        mac: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gateway_port: Option<u16>,
    },
    VfioPci {
        bdf: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mac: Option<String>,
    },
    Vdpa {
        device: PathBuf,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mac: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VmDeviceAttachment {
    VfioPci {
        bdf: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    Vsock {
        cid: u32,
    },
}
