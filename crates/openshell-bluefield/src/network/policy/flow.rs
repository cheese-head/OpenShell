// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Typed `OpenFlow` flow specification.
//!
//! The variants here cover the `OpenShell`-owned SNAT/CT pipeline. New behaviors
//! are added by extending
//! the [`Match`] / [`Action`] enums (and the renderer + tests in
//! `render.rs`), not by an untyped escape hatch. Avoiding an escape hatch
//! is intentional: it forces every new flow shape to pass through the
//! validator.

use core::net::Ipv4Addr;

use crate::network::owner::{Cookie, FlowKind};

/// A flow before validation/stamping. Built by callers and handed to
/// [`crate::network::FlowOwnerPolicy`] to produce a [`StampedFlow`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSpec {
    pub kind: FlowKind,
    /// Flow id encoded in cookie bits 31..0. Use
    /// [`crate::network::flow_id_from_str`] to derive this from a stable
    /// caller-side identity such as the attachment id or SNAT IP.
    pub flow_id: u32,
    pub table: u8,
    pub priority: u16,
    pub matches: Vec<Match>,
    pub actions: Vec<Action>,
}

impl FlowSpec {
    pub fn new(kind: FlowKind, flow_id: u32, table: u8, priority: u16) -> Self {
        Self {
            kind,
            flow_id,
            table,
            priority,
            matches: Vec::new(),
            actions: Vec::new(),
        }
    }

    #[must_use]
    pub fn matches(mut self, matches: impl IntoIterator<Item = Match>) -> Self {
        self.matches.extend(matches);
        self
    }

    #[must_use]
    pub fn add_match(mut self, m: Match) -> Self {
        self.matches.push(m);
        self
    }

    #[must_use]
    pub fn actions(mut self, actions: impl IntoIterator<Item = Action>) -> Self {
        self.actions.extend(actions);
        self
    }

    #[must_use]
    pub fn add_action(mut self, a: Action) -> Self {
        self.actions.push(a);
        self
    }
}

/// One match token. Multiple tokens are conjuncted in `OVS` match order.
///
/// Variants that imply an `eth_type` (such as [`Match::Arp`] or [`Match::Ip`])
/// must be added in the conventional `OVS` order — the renderer emits tokens
/// in the same order they appear in the [`FlowSpec::matches`] vector and
/// does not re-sort.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Match {
    InPort(String),
    DlSrc(MacLiteral),
    DlVlan(u16),
    Arp,
    ArpOp(u8),
    ArpTpa(Ipv4Addr),
    Ip,
    NwSrc(Ipv4Addr),
    NwDst(Ipv4Addr),
    Udp,
    Tcp,
    TpDst(u16),
    /// `ct_state=` followed by the value. We accept the raw string here
    /// because the `OVS` grammar for `ct_state` masks (`+trk+est`, `+trk+inv`,
    /// etc.) does not benefit from further typing; it is parsed only on
    /// the `OVS` side. The renderer escapes whitespace and commas defensively.
    CtState(String),
}

/// One action token. Action ordering is significant in `OpenFlow` and is
/// preserved by the renderer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Drop,
    Output(String),
    /// Composite ARP responder action. Renders to the standard
    /// `move/set_field/load/IN_PORT` sequence that turns the matched ARP
    /// request into a reply with the given MAC/IP.
    ArpReply {
        mac: MacLiteral,
        ip: Ipv4Addr,
    },
    Ct(CtAction),
    ModDlSrc(MacLiteral),
    ModDlDst(MacLiteral),
    DecTtl,
    PushVlan(u16),
    StripVlan,
    /// `goto_table:N`. Validator enforces N is inside the `OpenShell`
    /// table range.
    GotoTable(u8),
}

/// Connection-tracking action.
///
/// The combination of fields models the `OVS` variants we actually emit:
///
/// - `ct(table=N,zone=Z)` — punt into table N for a tracked lookup
/// - `ct(table=N,zone=Z,nat)` — same plus reverse-NAT restore on return
/// - `ct(commit,zone=Z,nat(src=IP))` — commit with source NAT
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CtAction {
    pub commit: bool,
    pub zone: u16,
    /// `ct(table=...)`. Validator enforces the target is inside the
    /// `OpenShell` range when present.
    pub recirc_table: Option<u8>,
    pub nat: Option<NatAction>,
}

/// Conntrack NAT action variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatAction {
    /// `nat(src=IP)` — apply source NAT to the given address on commit.
    SrcIp(Ipv4Addr),
    /// `nat` — restore the original 5-tuple for reverse traffic.
    Restore,
}

/// Validated MAC literal. Constructed via [`MacLiteral::parse`] which
/// enforces the canonical `aa:bb:cc:dd:ee:ff` form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacLiteral(String);

impl MacLiteral {
    pub fn parse(value: &str) -> Result<Self, crate::network::Violation> {
        if !is_canonical_mac(value) {
            return Err(crate::network::Violation::InvalidMac {
                value: value.to_string(),
            });
        }
        Ok(Self(value.to_ascii_lowercase()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn is_canonical_mac(value: &str) -> bool {
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() != 6 {
        return false;
    }
    parts
        .into_iter()
        .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// A validated flow ready for `ovs-ofctl add-flow` (via [`StampedFlow::ovs_ofctl_arg`])
/// or for inspection by the audit loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StampedFlow {
    pub cookie: Cookie,
    pub kind: FlowKind,
    pub flow_id: u32,
    pub table: u8,
    pub priority: u16,
    rendered: String,
}

impl StampedFlow {
    pub(crate) fn new(
        cookie: Cookie,
        kind: FlowKind,
        flow_id: u32,
        table: u8,
        priority: u16,
        rendered: String,
    ) -> Self {
        Self {
            cookie,
            kind,
            flow_id,
            table,
            priority,
            rendered,
        }
    }

    /// The exact string a caller can hand to `ovs-ofctl add-flow`.
    /// Includes the cookie, table, priority, matches, and actions.
    pub fn as_ovs_arg(&self) -> &str {
        &self.rendered
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::Violation;

    #[test]
    fn mac_literal_parses_canonical_form() {
        assert!(MacLiteral::parse("02:bf:00:00:00:01").is_ok());
        assert!(MacLiteral::parse("02:BF:00:00:00:01").is_ok());
    }

    #[test]
    fn mac_literal_rejects_garbage() {
        assert_eq!(
            MacLiteral::parse("nope").unwrap_err(),
            Violation::InvalidMac {
                value: "nope".to_string(),
            }
        );
        assert!(MacLiteral::parse("02-bf-00-00-00-01").is_err());
        assert!(MacLiteral::parse("02:bf:00:00:00").is_err());
        assert!(MacLiteral::parse("02:bf:00:00:00:01:02").is_err());
    }

    #[test]
    fn mac_literal_normalizes_case() {
        let m = MacLiteral::parse("02:BF:00:00:00:01").unwrap();
        assert_eq!(m.as_str(), "02:bf:00:00:00:01");
    }
}
