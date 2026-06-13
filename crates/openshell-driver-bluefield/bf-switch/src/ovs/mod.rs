// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OVS flow *policy* for `BlueField` sandbox endpoints.
//!
//! This layer decides *which* flows a sandbox needs (admission, deny-default,
//! SNAT egress) and expresses them with the neutral [`super::openflow`]
//! grammar. It does not own the cookie scheme or the renderer — those are
//! generic and live in `openflow/`.
//!
//! Flow application (running `ovs-ofctl`) is performed by
//! [`super::controller::local`]; this module only builds the argument
//! strings so they stay trivially testable.

pub mod endpoint;
pub mod l7_steer;
pub mod runner;
pub mod snat;

pub use runner::{NoopRunner, OvsError, OvsOfctlRunner, OvsResult, OvsRunner};

/// OVS ingress classifier. It hands sandbox ports to
/// [`OPENSHELL_TABLE_ADMISSION`].
pub const OVS_TABLE_CLASSIFIER: u8 = 0;
/// First OpenShell-owned table. A classifier in `table=0` hands sandbox
/// ports here via `goto_table`.
pub const OPENSHELL_TABLE_ADMISSION: u8 = 100;
/// Forward / SNAT path after admission.
pub const OPENSHELL_TABLE_FORWARD: u8 = 110;
/// Return / reverse-NAT demux table.
pub const OPENSHELL_TABLE_RETURN: u8 = 115;

/// Default OVS bridge `OpenShell` programs on a `BlueField`.
pub const DEFAULT_BRIDGE: &str = "br-openshell";

/// Shared conntrack zone for the `OpenShell` egress datapath.
///
/// A single zone keeps return-traffic demux simple (by destination IP in the
/// RETURN table) rather than requiring per-endpoint zone restoration on
/// ingress.
pub const CT_ZONE: u16 = 1;

/// A rendered set of `ovs-ofctl add-flow` argument strings for one bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowPlan {
    pub bridge: String,
    pub flows: Vec<String>,
}

impl FlowPlan {
    #[must_use]
    pub fn new(bridge: impl Into<String>) -> Self {
        Self {
            bridge: bridge.into(),
            flows: Vec::new(),
        }
    }
}
