// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Typed `OpenFlow` policy builder and validator.

pub mod error;
pub mod flow;
pub mod render;

pub use error::Violation;
pub use flow::{Action, CtAction, FlowSpec, MacLiteral, Match, NatAction, StampedFlow};
