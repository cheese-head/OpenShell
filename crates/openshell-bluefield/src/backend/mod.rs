// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Concrete `BlueField` attachment-provider backend.

pub mod actuator;
pub mod config;
pub mod inventory;
pub mod lease;
pub mod service;

pub use actuator::{AttachmentActuator, BlueFieldHardwareActuator, NoopAttachmentActuator};
pub use config::BlueFieldAttachmentBackendConfig;
pub use inventory::{BlueFieldInventory, BlueFieldVfSlot};
pub use lease::{FileLeaseStore, InMemoryLeaseStore, LeaseStore};
pub use service::BlueFieldAttachmentBackend;
