// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Flow owner policy for `OpenShell`-managed `OpenFlow` entries.

use super::cookie::FlowKind;

/// `OpenShell` owner identity placed in bits 63..48 of every flow cookie.
///
/// Cooperating controllers can declare this same value as the cookie prefix to
/// preserve. The value is not derived at runtime so divergence is caught in
/// code review rather than at runtime.
pub const OPENSHELL_OWNER_PREFIX: u16 = 0x0f05;

/// First table owned by `OpenShell`. A controller or provider can emit
/// `goto_table:OPENSHELL_TABLE_ADMISSION` from `table=0` for sandbox ports.
pub const OPENSHELL_TABLE_ADMISSION: u8 = 100;

/// Forward / SNAT path after admission classification.
pub const OPENSHELL_TABLE_FORWARD: u8 = 110;

/// Return / reverse-NAT demux table.
pub const OPENSHELL_TABLE_RETURN: u8 = 115;

const OWNER_BRIDGE_DEFAULT: &str = "br-openshell";
const TABLE_RANGE_DEFAULT: (u8, u8) = (100, 119);
const PRIORITY_MAX_DEFAULT: u16 = 32767;
const CT_ZONE_RANGE_DEFAULT: (u16, u16) = (10_000, 19_999);

/// The `OpenShell`-owned `OpenFlow` namespace.
///
/// Constructed once at provider startup with [`FlowOwnerPolicy::openshell`]
/// and threaded through every flow install. The policy is the only place that
/// knows about the bridge name, cookie owner prefix, table range, priority cap,
/// and CT zone range; callers ask it to stamp/render flows rather than
/// formatting `OpenFlow` strings themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowOwnerPolicy {
    pub bridge: String,
    pub owner_prefix: u16,
    pub table_range: (u8, u8),
    pub priority_max: u16,
    pub ct_zone_range: (u16, u16),
}

impl FlowOwnerPolicy {
    /// Production `OpenShell` policy.
    ///
    /// `bridge` defaults to `br-openshell`; a different bridge can be set if a
    /// future deployment puts the `OpenShell` policy block on a dedicated
    /// bridge.
    pub fn openshell() -> Self {
        Self {
            bridge: OWNER_BRIDGE_DEFAULT.to_string(),
            owner_prefix: OPENSHELL_OWNER_PREFIX,
            table_range: TABLE_RANGE_DEFAULT,
            priority_max: PRIORITY_MAX_DEFAULT,
            ct_zone_range: CT_ZONE_RANGE_DEFAULT,
        }
    }

    /// Replace the bridge name. Used by tests and by deployments that put
    /// the policy block on a non-default bridge.
    #[must_use]
    pub fn with_bridge(mut self, bridge: impl Into<String>) -> Self {
        self.bridge = bridge.into();
        self
    }

    /// Cookie value (no mask applied) for a flow of the given kind and
    /// flow id. The high 16 bits carry [`OPENSHELL_OWNER_PREFIX`]; bits
    /// 47..32 carry the `kind` ordinal; bits 31..0 carry `flow_id`.
    pub fn cookie(&self, kind: FlowKind, flow_id: u32) -> u64 {
        (u64::from(self.owner_prefix) << 48) | (u64::from(kind as u16) << 32) | u64::from(flow_id)
    }

    /// 64-bit cookie mask matching every flow owned by `OpenShell`, regardless
    /// of kind. Cooperating controllers can preserve any cookie matching this
    /// mask.
    pub fn owner_mask(&self) -> (u64, u64) {
        (
            u64::from(self.owner_prefix) << 48,
            0xffff_0000_0000_0000_u64,
        )
    }

    /// 64-bit cookie mask scoped to a single kind. Used for surgical
    /// deletes: `del-flows cookie=v/mask` will not touch any other kind, and
    /// cannot touch another owner's flows because the owner prefix differs.
    pub fn kind_mask(&self, kind: FlowKind) -> (u64, u64) {
        (
            (u64::from(self.owner_prefix) << 48) | (u64::from(kind as u16) << 32),
            0xffff_ffff_0000_0000_u64,
        )
    }

    pub(crate) fn table_in_range(&self, table: u8) -> bool {
        table >= self.table_range.0 && table <= self.table_range.1
    }

    pub(crate) fn priority_in_range(&self, priority: u16) -> bool {
        priority <= self.priority_max
    }

    pub(crate) fn ct_zone_in_range(&self, zone: u16) -> bool {
        zone >= self.ct_zone_range.0 && zone <= self.ct_zone_range.1
    }
}

impl Default for FlowOwnerPolicy {
    fn default() -> Self {
        Self::openshell()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_openshell() {
        let c = FlowOwnerPolicy::default();
        assert_eq!(c.bridge, "br-openshell");
        assert_eq!(c.owner_prefix, 0x0f05);
        assert_eq!(c.table_range, (100, 119));
        assert_eq!(c.priority_max, 32767);
        assert_eq!(c.ct_zone_range, (10_000, 19_999));
    }

    #[test]
    fn cookie_layout_is_owner_kind_flow() {
        let c = FlowOwnerPolicy::openshell();
        let cookie = c.cookie(FlowKind::Endpoint, 0xdead_beef);
        assert_eq!(cookie >> 48, 0x0f05);
        assert_eq!((cookie >> 32) & 0xffff, FlowKind::Endpoint as u64);
        assert_eq!(cookie & 0xffff_ffff, 0xdead_beef);
    }

    #[test]
    fn owner_mask_covers_all_kinds() {
        let c = FlowOwnerPolicy::openshell();
        let (value, mask) = c.owner_mask();
        assert_eq!(value, 0x0f05_0000_0000_0000);
        assert_eq!(mask, 0xffff_0000_0000_0000);

        let ep = c.cookie(FlowKind::Endpoint, 0xaaaa_bbbb);
        let sn = c.cookie(FlowKind::SnatShared, 0xcccc_dddd);
        assert_eq!(ep & mask, value);
        assert_eq!(sn & mask, value);
    }

    #[test]
    fn kind_mask_isolates_kind() {
        let c = FlowOwnerPolicy::openshell();
        let (value, mask) = c.kind_mask(FlowKind::Endpoint);
        let ep = c.cookie(FlowKind::Endpoint, 1);
        let sn = c.cookie(FlowKind::SnatShared, 1);
        assert_eq!(ep & mask, value);
        assert_ne!(sn & mask, value);
    }

    #[test]
    fn table_range_check_is_inclusive() {
        let c = FlowOwnerPolicy::openshell();
        assert!(!c.table_in_range(99));
        assert!(c.table_in_range(100));
        assert!(c.table_in_range(119));
        assert!(!c.table_in_range(120));
    }

    #[test]
    fn priority_cap_leaves_controller_headroom() {
        let c = FlowOwnerPolicy::openshell();
        assert!(c.priority_in_range(0));
        assert!(c.priority_in_range(32767));
        assert!(!c.priority_in_range(32768));
        assert!(!c.priority_in_range(65535));
    }

    #[test]
    fn ct_zone_range_is_inclusive() {
        let c = FlowOwnerPolicy::openshell();
        assert!(!c.ct_zone_in_range(9_999));
        assert!(c.ct_zone_in_range(10_000));
        assert!(c.ct_zone_in_range(19_999));
        assert!(!c.ct_zone_in_range(20_000));
    }
}
