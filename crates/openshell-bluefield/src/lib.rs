// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `BlueField` attachment provider primitives for `OpenShell` VM sandboxes.
//!
//! The crate contains `BlueField`-specific networking/storage building blocks
//! that implement `OpenShell`'s generic attachment-provider contract.

pub mod backend;
pub mod command;
pub mod config;
pub mod network;
pub mod provider;
pub mod vfio;
