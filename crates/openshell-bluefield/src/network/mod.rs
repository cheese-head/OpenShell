// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `BlueField` network attachment primitives.
//!
//! This module owns the `BlueField` network side of attachment provisioning:
//! `OpenFlow` ownership, typed policy validation, and `OVS` command planning.

pub mod attachment;
pub mod flow_programmer;
pub mod ovs;
pub mod owner;
pub mod policy;

pub use attachment::BlueFieldNetworkAttachment;
pub use flow_programmer::{
    FlowProgrammer, FlowProgrammerError, OvsExecutionError, OvsFlowProgrammer, OvsOfctlExecutor,
    SandboxFlowPlan,
};
pub use ovs::{OvsOfctlCommand, add_flow_command, delete_exact_cookie_command};
pub use owner::{
    Cookie, FlowKind, FlowOwnerPolicy, OPENSHELL_OWNER_PREFIX, OPENSHELL_TABLE_ADMISSION,
    OPENSHELL_TABLE_FORWARD, OPENSHELL_TABLE_RETURN, flow_id_from_str,
};
pub use policy::{
    Action, CtAction, FlowSpec, MacLiteral, Match, NatAction, StampedFlow, Violation,
};
