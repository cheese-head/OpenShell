// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Stable flow ownership policy for `OpenShell`-managed `OpenFlow` entries.

mod cookie;
mod policy;

pub use cookie::{Cookie, FlowKind, flow_id_from_str};
pub use policy::{
    FlowOwnerPolicy, OPENSHELL_OWNER_PREFIX, OPENSHELL_TABLE_ADMISSION, OPENSHELL_TABLE_FORWARD,
    OPENSHELL_TABLE_RETURN,
};
