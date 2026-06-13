// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Flow-cookie ownership scheme.
//!
//! This module is intentionally self-contained: it depends on nothing else
//! in the `bluefield` extension. If the `OpenFlow` grammar is ever promoted to
//! a higher-level crate, this file moves with `flow.rs` / `render.rs` as a
//! `git mv`, not a refactor.

use core::fmt;

/// Identity placed in bits 63..48 of every OpenShell-owned flow cookie so
/// cleanup can delete only our flows and cooperating controllers can
/// preserve them.
pub const OPENSHELL_OWNER_PREFIX: u16 = 0x0f05;

/// Family of an OpenShell-owned flow. Encoded in cookie bits 47..32.
///
/// These values are persisted in OVS cookies across process restarts and
/// must never be renumbered once shipped.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowKind {
    /// Per-endpoint (per-sandbox) admission / CT-punt / return flows.
    Endpoint = 0x0001,
    /// Per-SNAT-IP shared egress flows (ARP, return CT, deny-default).
    SnatShared = 0x0002,
    /// Per-sandbox L3/L4 policy projection flows.
    Policy = 0x0004,
}

impl fmt::Display for FlowKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Endpoint => f.write_str("endpoint"),
            Self::SnatShared => f.write_str("snat-shared"),
            Self::Policy => f.write_str("policy"),
        }
    }
}

/// Compose a 64-bit cookie: `owner_prefix(16) | kind(16) | flow_id(32)`.
#[must_use]
pub fn cookie(kind: FlowKind, flow_id: u32) -> u64 {
    (u64::from(OPENSHELL_OWNER_PREFIX) << 48) | (u64::from(kind as u16) << 32) | u64::from(flow_id)
}

/// Cookie + mask matching every flow of a single kind owned by `OpenShell`.
/// Suitable for surgical `del-flows cookie=value/mask`.
#[must_use]
pub fn kind_mask(kind: FlowKind) -> (u64, u64) {
    (
        (u64::from(OPENSHELL_OWNER_PREFIX) << 48) | (u64::from(kind as u16) << 32),
        0xffff_ffff_0000_0000_u64,
    )
}

/// Cookie + exact mask matching every flow of a single `(kind, flow_id)`.
///
/// Suitable for surgical per-sandbox / per-policy
/// `del-flows cookie=value/mask` that does not touch sibling flows of the
/// same kind.
#[must_use]
pub fn exact_mask(kind: FlowKind, flow_id: u32) -> (u64, u64) {
    (cookie(kind, flow_id), u64::MAX)
}

/// Derive a stable 32-bit flow id from an arbitrary identity string
/// (claim id, SNAT IP, etc.) via FNV-1a folded to 32 bits. Stable across
/// runs and process restarts.
#[must_use]
pub fn flow_id_from_str(input: &str) -> u32 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for b in input.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    let folded = (hash >> 32) ^ (hash & 0xffff_ffff);
    u32::try_from(folded).expect("folded FNV-1a hash fits in u32")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_layout_is_owner_kind_flow() {
        let c = cookie(FlowKind::Endpoint, 0xdead_beef);
        assert_eq!(c >> 48, u64::from(OPENSHELL_OWNER_PREFIX));
        assert_eq!((c >> 32) & 0xffff, FlowKind::Endpoint as u64);
        assert_eq!(c & 0xffff_ffff, 0xdead_beef);
    }

    #[test]
    fn kind_mask_isolates_kind() {
        let (value, mask) = kind_mask(FlowKind::Endpoint);
        assert_eq!(cookie(FlowKind::Endpoint, 1) & mask, value);
        assert_ne!(cookie(FlowKind::SnatShared, 1) & mask, value);
    }

    #[test]
    fn flow_id_is_stable_and_namespaced() {
        assert_eq!(flow_id_from_str("sandbox-1"), flow_id_from_str("sandbox-1"));
        assert_ne!(flow_id_from_str("sandbox-1"), flow_id_from_str("sandbox-2"));
    }
}
