// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Render a [`FlowSpec`] into the exact `ovs-ofctl add-flow` argument string.
//!
//! This is the only place that turns typed flow tokens into the string OVS
//! sees. Self-contained: no `BlueField` imports.

use core::fmt::Write;

use crate::cookie::cookie;

use super::spec::{Action, CtAction, FlowSpec, Match};

/// Render a flow to the `cookie=...,table=...,priority=...,<matches>,actions=<actions>`
/// string accepted by `ovs-ofctl add-flow`.
#[must_use]
pub fn render(spec: &FlowSpec) -> String {
    let cookie = cookie(spec.kind, spec.flow_id);
    let mut out = String::with_capacity(96);
    write!(
        out,
        "cookie=0x{cookie:016x},table={t},priority={p}",
        t = spec.table,
        p = spec.priority
    )
    .expect("writing to String never fails");
    for m in &spec.matches {
        out.push(',');
        render_match(&mut out, m);
    }
    out.push_str(",actions=");
    for (i, a) in spec.actions.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        render_action(&mut out, a);
    }
    out
}

fn render_match(out: &mut String, m: &Match) {
    match m {
        Match::InPort(p) => write!(out, "in_port={p}").unwrap(),
        Match::Ip => out.push_str("ip"),
        Match::Arp => out.push_str("arp"),
        Match::ArpTpa(ip) => write!(out, "arp_tpa={ip}").unwrap(),
        Match::ArpOp(op) => write!(out, "arp_op={op}").unwrap(),
        Match::NwSrc(ip) => write!(out, "nw_src={ip}").unwrap(),
        Match::NwDst(ip) => write!(out, "nw_dst={ip}").unwrap(),
        Match::Tcp => out.push_str("tcp"),
        Match::TpDst(port) => write!(out, "tp_dst={port}").unwrap(),
        Match::CtState(s) => write!(out, "ct_state={s}").unwrap(),
        Match::CtZone(z) => write!(out, "ct_zone={z}").unwrap(),
    }
}

fn render_action(out: &mut String, a: &Action) {
    match a {
        Action::Drop => out.push_str("drop"),
        Action::Output(p) => write!(out, "output:{p}").unwrap(),
        Action::GotoTable(t) => write!(out, "goto_table:{t}").unwrap(),
        Action::Normal => out.push_str("NORMAL"),
        Action::Resubmit(t) => write!(out, "resubmit(,{t})").unwrap(),
        Action::Ct(ct) => render_ct(out, ct),
        Action::SetEthSrc(mac) => write!(out, "mod_dl_src:{mac}").unwrap(),
        Action::SetEthDst(mac) => write!(out, "mod_dl_dst:{mac}").unwrap(),
        Action::MoveField { src, dst } => write!(out, "move:{src}->{dst}").unwrap(),
        Action::LoadHex { value, dst } => write!(out, "load:0x{value}->{dst}").unwrap(),
        Action::InPort => out.push_str("IN_PORT"),
    }
}

fn render_ct(out: &mut String, ct: &CtAction) {
    out.push_str("ct(");
    let mut first = true;
    let mut sep = |out: &mut String| {
        if first {
            first = false;
        } else {
            out.push(',');
        }
    };
    if ct.commit {
        sep(out);
        out.push_str("commit");
    }
    if let Some(t) = ct.table {
        sep(out);
        write!(out, "table={t}").unwrap();
    }
    if let Some(z) = ct.zone {
        sep(out);
        write!(out, "zone={z}").unwrap();
    }
    if let Some(ip) = ct.snat_to {
        sep(out);
        write!(out, "nat(src={ip})").unwrap();
    } else if ct.nat {
        sep(out);
        out.push_str("nat");
    }
    out.push(')');
}

#[cfg(test)]
mod tests {
    use crate::cookie::FlowKind;

    use super::super::spec::{Action, CtAction, FlowSpec, MacAddress, Match};
    use super::render;
    use std::str::FromStr;

    #[test]
    fn renders_cookie_table_priority_match_actions() {
        let spec = FlowSpec::new(FlowKind::Endpoint, 0xdead_beef, 100, 100)
            .match_(Match::InPort("pf0vf0".to_string()))
            .action(Action::GotoTable(110));
        assert_eq!(
            render(&spec),
            "cookie=0x0f050001deadbeef,table=100,priority=100,in_port=pf0vf0,actions=goto_table:110"
        );
    }

    #[test]
    fn renders_deny_default() {
        let spec = FlowSpec::new(FlowKind::Endpoint, 1, 100, 0)
            .match_(Match::InPort("pf0vf0".to_string()))
            .action(Action::Drop);
        assert!(render(&spec).ends_with("actions=drop"));
    }

    #[test]
    fn renders_bare_conntrack_nat() {
        let spec = FlowSpec::new(FlowKind::SnatShared, 1, 100, 90)
            .match_(Match::Ip)
            .action(Action::Ct(CtAction::track_nat(115, 1)));
        assert!(render(&spec).ends_with("actions=ct(table=115,zone=1,nat)"));
    }

    #[test]
    fn renders_mac_rewrites_and_arp_matches() {
        let vip_mac = MacAddress::from_str("02:50:00:78:02:50").unwrap();
        let guest_mac = MacAddress::from_str("86:7f:6e:5b:e0:7b").unwrap();
        let spec = FlowSpec::new(FlowKind::Endpoint, 2, 100, 250)
            .match_(Match::InPort("osuplink".to_string()))
            .match_(Match::Arp)
            .match_(Match::ArpTpa("10.0.120.250".parse().unwrap()))
            .match_(Match::ArpOp(1))
            .action(Action::SetEthSrc(vip_mac))
            .action(Action::SetEthDst(guest_mac));
        assert!(render(&spec).contains("arp_tpa=10.0.120.250,arp_op=1"));
        assert!(render(&spec).contains("mod_dl_src:02:50:00:78:02:50"));
        assert!(render(&spec).contains("mod_dl_dst:86:7f:6e:5b:e0:7b"));
    }
}
