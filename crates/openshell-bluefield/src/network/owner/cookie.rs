// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cookie and kind enum.

use core::fmt;

/// Family/kind of an `OpenShell` flow. Encoded in cookie bits 47..32.
///
/// New kinds are added as `OpenShell` flow ownership grows. Reserved enum values
/// must never be removed or renumbered because cookies can persist in `OVS`
/// across owner process restarts.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowKind {
    /// Per-endpoint (per-sandbox-attachment) flow: admission, in-flow CT
    /// punt, return demux. One [`FlowKind::Endpoint`] sub-family per
    /// attached sandbox.
    Endpoint = 0x0001,

    /// Per-SNAT-IP shared egress flow: ARP reply for the SNAT address,
    /// return-direction CT lookup, DNS pinning, default forward. Shared
    /// across all sandboxes that egress through the same SNAT IP.
    SnatShared = 0x0002,

    /// Handoff flow that lives in `OpenShell`'s space rather than another
    /// controller's. Reserved for deployments where another controller
    /// explicitly delegates the admission table to `OpenShell`.
    ExternalHandoff = 0x0003,
}

impl fmt::Display for FlowKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Endpoint => f.write_str("endpoint"),
            Self::SnatShared => f.write_str("snat-shared"),
            Self::ExternalHandoff => f.write_str("external-handoff"),
        }
    }
}

/// Newtype around a stamped 64-bit `OpenFlow` cookie.
///
/// The constructor is crate-private so the only way to obtain one is via
/// [`crate::network::owner::FlowOwnerPolicy::cookie`], which guarantees the
/// layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cookie(u64);

impl Cookie {
    pub(crate) fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:016x}", self.0)
    }
}

/// FNV-1a 64-bit hash truncated to 32 bits, used to derive a flow id from
/// a stable string (attachment id, SNAT IP, etc.). Stable across runs and
/// across owner process restarts.
pub fn flow_id_from_str(input: &str) -> u32 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for b in input.bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    // Fold the upper half into the lower half so we keep some of the
    // entropy that 32-bit FNV-1a would have lost.
    let folded = (hash >> 32) ^ (hash & 0xffff_ffff);
    u32::try_from(folded).expect("folded FNV-1a hash fits in u32")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_display_is_zero_padded_hex() {
        let c = Cookie::new(0x0f05_0001_0000_002a);
        assert_eq!(format!("{c}"), "0x0f0500010000002a");
    }

    #[test]
    fn flow_id_is_stable() {
        assert_eq!(flow_id_from_str("sandbox-1"), flow_id_from_str("sandbox-1"));
    }

    #[test]
    fn flow_id_is_namespaced() {
        assert_ne!(flow_id_from_str("sandbox-1"), flow_id_from_str("sandbox-2"));
    }

    #[test]
    fn flow_kind_repr_is_stable() {
        // These values are persisted in OVS cookies. They must never change
        // once shipped.
        assert_eq!(FlowKind::Endpoint as u16, 0x0001);
        assert_eq!(FlowKind::SnatShared as u16, 0x0002);
        assert_eq!(FlowKind::ExternalHandoff as u16, 0x0003);
    }
}
