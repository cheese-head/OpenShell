// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Flow owner policy violations.

use thiserror::Error;

/// A flow rejected because it would leave the `OpenShell` ownership policy.
/// Each variant maps to one rule in the policy.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Violation {
    #[error("table {table} is outside OpenShell's reserved range {start}..={end}")]
    TableOutsideRange { table: u8, start: u8, end: u8 },

    #[error(
        "priority {priority} exceeds OpenShell's cap {cap} (higher priorities are reserved for cooperating controllers)"
    )]
    PriorityAboveCap { priority: u16, cap: u16 },

    #[error("conntrack zone {zone} is outside OpenShell's range {start}..={end}")]
    CtZoneOutsideRange { zone: u16, start: u16, end: u16 },

    #[error(
        "ct(table={table}) recirculation target is outside OpenShell's reserved range {start}..={end}"
    )]
    CtRecircOutsideRange { table: u8, start: u8, end: u8 },

    #[error("goto_table:{table} target is outside OpenShell's reserved range {start}..={end}")]
    GotoTableOutsideRange { table: u8, start: u8, end: u8 },

    #[error("an OpenFlow flow must declare at least one action")]
    EmptyActions,

    #[error("invalid port name {name:?}: OVS port names cannot be empty or contain commas")]
    InvalidPortName { name: String },

    #[error("invalid MAC literal {value:?}: expected aa:bb:cc:dd:ee:ff")]
    InvalidMac { value: String },

    #[error("vlan id {vlan} is outside the 1..=4094 range")]
    InvalidVlan { vlan: u16 },
}
