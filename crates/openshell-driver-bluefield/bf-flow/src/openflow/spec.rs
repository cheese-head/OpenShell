// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Typed `OpenFlow` flow specification.
//!
//! New behaviors are added by extending the [`Match`] / [`Action`] enums and
//! the renderer in `render.rs`. This module is self-contained and has no
//! dependency on anything `BlueField`-specific.

use core::net::Ipv4Addr;
use core::str::FromStr;

use crate::cookie::FlowKind;

/// Ethernet MAC address rendered in canonical lowercase colon form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddress(String);

impl MacAddress {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn hex_no_separators(&self) -> String {
        self.0.replace(':', "")
    }
}

impl FromStr for MacAddress {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = value.trim().split(':').collect();
        if parts.len() != 6 {
            return Err(format!("invalid MAC address {value:?}: expected 6 octets"));
        }
        let mut normalized = Vec::with_capacity(6);
        for part in parts {
            if part.len() != 2 || !part.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!(
                    "invalid MAC address {value:?}: octets must be two hex digits"
                ));
            }
            normalized.push(part.to_ascii_lowercase());
        }
        Ok(Self(normalized.join(":")))
    }
}

impl core::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A flow before rendering. Built by callers and handed to
/// [`super::render::render`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSpec {
    pub kind: FlowKind,
    /// Flow id encoded in cookie bits 31..0. Derive via
    /// [`crate::cookie::flow_id_from_str`] from a stable identity.
    pub flow_id: u32,
    pub table: u8,
    pub priority: u16,
    pub matches: Vec<Match>,
    pub actions: Vec<Action>,
}

impl FlowSpec {
    #[must_use]
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
    pub fn match_(mut self, m: Match) -> Self {
        self.matches.push(m);
        self
    }

    #[must_use]
    pub fn action(mut self, a: Action) -> Self {
        self.actions.push(a);
        self
    }
}

/// One match token. Tokens are conjuncted in the order they appear.
///
/// This is a deliberately small starter set covering the endpoint/SNAT
/// pipeline stubs; extend it (and the renderer) as flow shapes grow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Match {
    InPort(String),
    Ip,
    /// Match ARP (`arp` shorthand).
    Arp,
    /// Match ARP target protocol address (`arp_tpa=IP`).
    ArpTpa(Ipv4Addr),
    /// Match ARP opcode (`arp_op=N`; request is 1, reply is 2).
    ArpOp(u16),
    NwSrc(Ipv4Addr),
    NwDst(Ipv4Addr),
    /// Match TCP (`tcp` shorthand; implies `ip,nw_proto=6`).
    Tcp,
    /// Match the L4 destination port. Requires a protocol match (e.g.
    /// [`Match::Tcp`]) earlier in the conjunction.
    TpDst(u16),
    /// Raw `ct_state=` value (e.g. `+trk+est`). Kept as a string because the
    /// OVS `ct_state` grammar does not benefit from further typing.
    CtState(String),
    /// Connection-tracking zone (`ct_zone=`).
    CtZone(u16),
}

/// Connection-tracking action (`ct(...)`): optionally commit, recirculate to
/// a table, pin a zone, and/or apply NAT. Models the subset of OVS `ct()`
/// the egress pipeline needs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CtAction {
    /// Commit the connection to the conntrack table (`commit`).
    pub commit: bool,
    /// Recirculate matched packets to this table after CT (`table=N`).
    pub table: Option<u8>,
    /// Conntrack zone (`zone=Z`).
    pub zone: Option<u16>,
    /// Apply existing conntrack NAT state (`nat`).
    pub nat: bool,
    /// Source-NAT committed connections to this address (`nat(src=IP)`).
    pub snat_to: Option<Ipv4Addr>,
}

impl CtAction {
    /// `ct(table=N,zone=Z)` — track and recirculate, no commit/NAT.
    #[must_use]
    pub fn track(table: u8, zone: u16) -> Self {
        Self {
            commit: false,
            table: Some(table),
            zone: Some(zone),
            nat: false,
            snat_to: None,
        }
    }

    /// `ct(table=N,zone=Z,nat)` — track, apply existing NAT state, and
    /// recirculate.
    #[must_use]
    pub fn track_nat(table: u8, zone: u16) -> Self {
        Self {
            commit: false,
            table: Some(table),
            zone: Some(zone),
            nat: true,
            snat_to: None,
        }
    }

    /// `ct(commit,zone=Z,nat(src=IP))` — commit + source-NAT.
    #[must_use]
    pub fn commit_snat(zone: u16, snat_to: Ipv4Addr) -> Self {
        Self {
            commit: true,
            table: None,
            zone: Some(zone),
            nat: false,
            snat_to: Some(snat_to),
        }
    }
}

/// One action token. Action ordering is significant and preserved by the
/// renderer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Drop,
    Output(String),
    GotoTable(u8),
    /// `NORMAL` — hand to the switch's normal L2/L3 pipeline (used for ARP).
    Normal,
    /// `resubmit(,N)` — reprocess in table N.
    Resubmit(u8),
    /// `ct(...)` connection-tracking action.
    Ct(CtAction),
    /// Rewrite Ethernet source address (`mod_dl_src:MAC`).
    SetEthSrc(MacAddress),
    /// Rewrite Ethernet destination address (`mod_dl_dst:MAC`).
    SetEthDst(MacAddress),
    /// Move one OpenFlow/NXM field to another (`move:SRC->DST`).
    MoveField {
        src: String,
        dst: String,
    },
    /// Load a hexadecimal immediate into an OpenFlow/NXM field.
    LoadHex {
        value: String,
        dst: String,
    },
    /// Output to the ingress port (`IN_PORT`).
    InPort,
}
