// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! VFIO preparation primitives for `BlueField` VF passthrough.

pub mod device;
pub mod sysfs;

pub use device::{PreparedVfioDevice, VfioDeviceError, VfioDeviceId, VfioDeviceManager};
pub use sysfs::{SysfsVfioDeviceManager, VfioBindPlan};
