// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

pub mod driver;
mod embedded_runtime;
pub mod extension;
mod ffi;
pub mod gpu;
mod nft_ruleset;
mod platform_config;
pub mod procguard;
mod rootfs;
mod runtime;

pub use driver::{VmDriver, VmDriverConfig};
pub use extension::{
    ExtensionStateMap, LaunchAbortReason, NoopVmLifecycleExtension, PersistedExtensionState,
    ReconcileOutcome, VmLaunchPlan, VmLifecycleContext, VmLifecycleError, VmLifecycleExtension,
    VmLifecycleExtensions, VmLifecycleHookResult, VmLifecycleResult,
};
pub use runtime::{
    VM_RUNTIME_DIR_ENV, VmBackend, VmDeviceAttachment, VmLaunchConfig, VmNetworkAttachment,
    VmRootfsConfig, VmStorageAttachment, cleanup_stale_tap_interfaces, configured_runtime_dir,
    run_vm,
};
