// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Backend-neutral `BlueField` datapath flow model.
//!
//! The root module exposes the neutral [`FlowProgram`] IR and [`FlowBackend`]
//! trait. Protocol-specific details live behind backend modules such as
//! [`openflow`]. Additional datapath backends can be added later by
//! implementing [`FlowBackend`] without changing switch policy builders.

pub mod backend;
pub mod cookie;
pub mod openflow;
pub mod program;

pub use backend::{FlowBackend, FlowBackendError, FlowBackendResult};
pub use cookie::{
    FlowKind, OPENSHELL_OWNER_PREFIX, cookie, exact_mask, flow_id_from_str, kind_mask,
};
pub use program::{
    Action, CtIntent, CtNat, CtState, EtherType, FlowHandle, FlowProgram, FlowProgramError,
    MacAddress, Match, Port, Rule, Stage, StageKind,
};
