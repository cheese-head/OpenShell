// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StorageAttachment {
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

impl StorageAttachment {
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
pub struct RootfsConfig {
    pub root: StorageAttachment,
    pub overlay: StorageAttachment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<StorageAttachment>,
}

impl RootfsConfig {
    pub fn host_files(root: PathBuf, overlay: PathBuf, image: Option<PathBuf>) -> Self {
        Self {
            root: StorageAttachment::host_file(root, true),
            overlay: StorageAttachment::host_file(overlay, false),
            image: image.map(|path| StorageAttachment::host_file(path, true)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NetworkAttachment {
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
pub enum DeviceAttachment {
    VfioPci {
        bdf: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
    Vsock {
        cid: u32,
    },
}
