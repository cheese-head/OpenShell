// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Validation + rendering of a [`FlowSpec`] into an `ovs-ofctl` argument.
//!
//! This module is the only place that turns typed flow tokens into the
//! string `OVS` sees. Every render path also enforces the policy; there
//! is intentionally no rendering API that skips validation.

use core::fmt::Write;

use crate::network::owner::{Cookie, FlowOwnerPolicy};
use crate::network::policy::error::Violation;
use crate::network::policy::flow::{Action, CtAction, FlowSpec, Match, NatAction, StampedFlow};

impl FlowOwnerPolicy {
    /// Validate and render a [`FlowSpec`]. The returned [`StampedFlow`]
    /// carries the stamped cookie and the `OVS`-ready argument string.
    ///
    /// Validation happens before any rendering work; on error nothing is
    /// emitted and the caller learns exactly which rule was broken.
    pub fn stamp(&self, spec: &FlowSpec) -> Result<StampedFlow, Violation> {
        self.validate(spec)?;
        let cookie = Cookie::new(self.cookie(spec.kind, spec.flow_id));
        let rendered = render_flow(spec, cookie);
        Ok(StampedFlow::new(
            cookie,
            spec.kind,
            spec.flow_id,
            spec.table,
            spec.priority,
            rendered,
        ))
    }

    /// Validate-only. Used by tests that want to inspect rejections
    /// without comparing strings, and by an upcoming audit pass that
    /// re-validates flows discovered via `dump-flows`.
    pub fn validate(&self, spec: &FlowSpec) -> Result<(), Violation> {
        if !self.table_in_range(spec.table) {
            return Err(Violation::TableOutsideRange {
                table: spec.table,
                start: self.table_range.0,
                end: self.table_range.1,
            });
        }
        if !self.priority_in_range(spec.priority) {
            return Err(Violation::PriorityAboveCap {
                priority: spec.priority,
                cap: self.priority_max,
            });
        }
        if spec.actions.is_empty() {
            return Err(Violation::EmptyActions);
        }
        for m in &spec.matches {
            validate_match(m)?;
        }
        for a in &spec.actions {
            validate_action(self, a)?;
        }
        Ok(())
    }
}

fn validate_match(m: &Match) -> Result<(), Violation> {
    match m {
        Match::InPort(name) => validate_port_name(name),
        Match::DlVlan(v) => {
            if *v == 0 || *v > 4094 {
                return Err(Violation::InvalidVlan { vlan: *v });
            }
            Ok(())
        }
        Match::DlSrc(_)
        | Match::Arp
        | Match::ArpOp(_)
        | Match::ArpTpa(_)
        | Match::Ip
        | Match::NwSrc(_)
        | Match::NwDst(_)
        | Match::Udp
        | Match::Tcp
        | Match::TpDst(_)
        | Match::CtState(_) => Ok(()),
    }
}

fn validate_action(policy: &FlowOwnerPolicy, a: &Action) -> Result<(), Violation> {
    match a {
        Action::Output(name) => validate_port_name(name),
        Action::PushVlan(v) => {
            if *v == 0 || *v > 4094 {
                return Err(Violation::InvalidVlan { vlan: *v });
            }
            Ok(())
        }
        Action::GotoTable(t) => {
            if !policy.table_in_range(*t) {
                return Err(Violation::GotoTableOutsideRange {
                    table: *t,
                    start: policy.table_range.0,
                    end: policy.table_range.1,
                });
            }
            Ok(())
        }
        Action::Ct(ct) => validate_ct(policy, ct),
        Action::ModDlSrc(_)
        | Action::ModDlDst(_)
        | Action::Drop
        | Action::DecTtl
        | Action::StripVlan
        | Action::ArpReply { .. } => Ok(()),
    }
}

fn validate_ct(policy: &FlowOwnerPolicy, ct: &CtAction) -> Result<(), Violation> {
    if !policy.ct_zone_in_range(ct.zone) {
        return Err(Violation::CtZoneOutsideRange {
            zone: ct.zone,
            start: policy.ct_zone_range.0,
            end: policy.ct_zone_range.1,
        });
    }
    if let Some(target) = ct.recirc_table
        && !policy.table_in_range(target)
    {
        return Err(Violation::CtRecircOutsideRange {
            table: target,
            start: policy.table_range.0,
            end: policy.table_range.1,
        });
    }
    Ok(())
}

fn validate_port_name(name: &str) -> Result<(), Violation> {
    if name.is_empty() || name.contains(',') || name.contains(' ') {
        return Err(Violation::InvalidPortName {
            name: name.to_string(),
        });
    }
    Ok(())
}

fn render_flow(spec: &FlowSpec, cookie: Cookie) -> String {
    let mut out = String::with_capacity(128);
    write!(
        out,
        "cookie={cookie},table={t},priority={p}",
        t = spec.table,
        p = spec.priority
    )
    .expect("write to String never fails");
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
        Match::InPort(p) => {
            write!(out, "in_port={p}").unwrap();
        }
        Match::DlSrc(mac) => {
            write!(out, "dl_src={}", mac.as_str()).unwrap();
        }
        Match::DlVlan(v) => {
            write!(out, "dl_vlan={v}").unwrap();
        }
        Match::Arp => out.push_str("arp"),
        Match::ArpOp(op) => {
            write!(out, "arp_op={op}").unwrap();
        }
        Match::ArpTpa(ip) => {
            write!(out, "arp_tpa={ip}").unwrap();
        }
        Match::Ip => out.push_str("ip"),
        Match::NwSrc(ip) => {
            write!(out, "nw_src={ip}").unwrap();
        }
        Match::NwDst(ip) => {
            write!(out, "nw_dst={ip}").unwrap();
        }
        Match::Udp => out.push_str("udp"),
        Match::Tcp => out.push_str("tcp"),
        Match::TpDst(p) => {
            write!(out, "tp_dst={p}").unwrap();
        }
        Match::CtState(s) => {
            write!(out, "ct_state={s}").unwrap();
        }
    }
}

fn render_action(out: &mut String, a: &Action) {
    match a {
        Action::Drop => out.push_str("drop"),
        Action::Output(p) => {
            write!(out, "output:{p}").unwrap();
        }
        Action::ArpReply { mac, ip } => {
            // The composite ARP responder mirrors the move/set/load sequence
            // OpenShell already shipped before this crate existed. Rendered
            // as a comma-separated chain of sub-actions: the caller wraps
            // it as one logical "action" and the renderer expands it.
            write!(
                out,
                "move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],mod_dl_src:{m},load:0x2->NXM_OF_ARP_OP[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],set_field:{m}->arp_sha,set_field:{ip}->arp_spa,IN_PORT",
                m = mac.as_str()
            )
            .unwrap();
        }
        Action::Ct(ct) => render_ct(out, ct),
        Action::ModDlSrc(mac) => {
            write!(out, "mod_dl_src:{}", mac.as_str()).unwrap();
        }
        Action::ModDlDst(mac) => {
            write!(out, "mod_dl_dst:{}", mac.as_str()).unwrap();
        }
        Action::DecTtl => out.push_str("dec_ttl"),
        Action::PushVlan(v) => {
            // Standard 802.1Q tag with the given VID. We always pair push
            // with set_field on the vid because OVS will otherwise default
            // to vid=0.
            write!(
                out,
                "push_vlan:0x8100,set_field:{val}->vlan_vid",
                val = 0x1000 | *v
            )
            .unwrap();
        }
        Action::StripVlan => out.push_str("strip_vlan"),
        Action::GotoTable(t) => {
            write!(out, "goto_table:{t}").unwrap();
        }
    }
}

fn render_ct(out: &mut String, ct: &CtAction) {
    out.push_str("ct(");
    let mut wrote_field = if ct.commit {
        out.push_str("commit");
        true
    } else {
        false
    };
    if let Some(table) = ct.recirc_table {
        if wrote_field {
            out.push(',');
        }
        write!(out, "table={table}").unwrap();
        wrote_field = true;
    }
    if wrote_field {
        out.push(',');
    }
    write!(out, "zone={z}", z = ct.zone).unwrap();
    match &ct.nat {
        None => {}
        Some(NatAction::Restore) => out.push_str(",nat"),
        Some(NatAction::SrcIp(ip)) => {
            write!(out, ",nat(src={ip})").unwrap();
        }
    }
    out.push(')');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::owner::FlowKind;
    use core::net::Ipv4Addr;

    fn policy() -> FlowOwnerPolicy {
        FlowOwnerPolicy::openshell()
    }

    fn mac(s: &str) -> crate::network::policy::MacLiteral {
        crate::network::policy::MacLiteral::parse(s).unwrap()
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn stamp_emits_cookie_table_priority_match_actions() {
        let c = policy();
        let spec = FlowSpec::new(FlowKind::Endpoint, 0xdead_beef, 100, 240)
            .add_match(Match::InPort("pf0vf1".to_string()))
            .add_match(Match::DlSrc(mac("02:bf:00:00:00:01")))
            .add_match(Match::Ip)
            .add_match(Match::NwSrc(ip("100.96.1.3")))
            .add_action(Action::Ct(CtAction {
                commit: false,
                zone: 10000,
                recirc_table: Some(110),
                nat: None,
            }));
        let stamped = c.stamp(&spec).unwrap();
        assert_eq!(
            stamped.as_ovs_arg(),
            "cookie=0x0f050001deadbeef,table=100,priority=240,in_port=pf0vf1,dl_src=02:bf:00:00:00:01,ip,nw_src=100.96.1.3,actions=ct(table=110,zone=10000)"
        );
        assert_eq!(stamped.cookie.as_u64(), 0x0f05_0001_dead_beef);
        assert_eq!(stamped.table, 100);
    }

    #[test]
    fn rejects_table_outside_range() {
        let c = policy();
        let spec = FlowSpec::new(FlowKind::Endpoint, 1, 0, 100).add_action(Action::Drop);
        assert_eq!(
            c.stamp(&spec).unwrap_err(),
            Violation::TableOutsideRange {
                table: 0,
                start: 100,
                end: 119,
            }
        );
    }

    #[test]
    fn rejects_priority_above_cap() {
        let c = policy();
        let spec = FlowSpec::new(FlowKind::Endpoint, 1, 100, 40000).add_action(Action::Drop);
        assert_eq!(
            c.stamp(&spec).unwrap_err(),
            Violation::PriorityAboveCap {
                priority: 40000,
                cap: 32767,
            }
        );
    }

    #[test]
    fn rejects_empty_actions() {
        let c = policy();
        let spec = FlowSpec::new(FlowKind::Endpoint, 1, 100, 100);
        assert_eq!(c.stamp(&spec).unwrap_err(), Violation::EmptyActions);
    }

    #[test]
    fn rejects_ct_zone_outside_range() {
        let c = policy();
        let spec =
            FlowSpec::new(FlowKind::Endpoint, 1, 100, 100).add_action(Action::Ct(CtAction {
                commit: false,
                zone: 5,
                recirc_table: None,
                nat: None,
            }));
        assert_eq!(
            c.stamp(&spec).unwrap_err(),
            Violation::CtZoneOutsideRange {
                zone: 5,
                start: 10_000,
                end: 19_999,
            }
        );
    }

    #[test]
    fn rejects_ct_recirc_outside_range() {
        let c = policy();
        let spec =
            FlowSpec::new(FlowKind::Endpoint, 1, 100, 100).add_action(Action::Ct(CtAction {
                commit: false,
                zone: 10000,
                recirc_table: Some(10),
                nat: None,
            }));
        assert_eq!(
            c.stamp(&spec).unwrap_err(),
            Violation::CtRecircOutsideRange {
                table: 10,
                start: 100,
                end: 119,
            }
        );
    }

    #[test]
    fn rejects_goto_table_outside_range() {
        let c = policy();
        let spec = FlowSpec::new(FlowKind::Endpoint, 1, 100, 100).add_action(Action::GotoTable(0));
        assert_eq!(
            c.stamp(&spec).unwrap_err(),
            Violation::GotoTableOutsideRange {
                table: 0,
                start: 100,
                end: 119,
            }
        );
    }

    #[test]
    fn renders_arp_reply_composite() {
        let c = policy();
        let spec = FlowSpec::new(FlowKind::SnatShared, 7, 100, 250)
            .add_match(Match::Arp)
            .add_match(Match::InPort("p0".to_string()))
            .add_match(Match::ArpOp(1))
            .add_match(Match::ArpTpa(ip("10.0.120.250")))
            .add_action(Action::ArpReply {
                mac: mac("58:a2:e1:dc:f8:8e"),
                ip: ip("10.0.120.250"),
            });
        let stamped = c.stamp(&spec).unwrap();
        let arg = stamped.as_ovs_arg();
        assert!(arg.contains("arp_tpa=10.0.120.250"));
        assert!(arg.contains("set_field:58:a2:e1:dc:f8:8e->arp_sha"));
        assert!(arg.contains("set_field:10.0.120.250->arp_spa"));
        assert!(arg.ends_with(",IN_PORT"));
    }

    #[test]
    fn renders_ct_commit_with_src_nat_and_vlan_push() {
        let c = policy();
        let spec = FlowSpec::new(FlowKind::SnatShared, 7, 110, 100)
            .add_match(Match::CtState("+trk".to_string()))
            .add_match(Match::Ip)
            .add_action(Action::Ct(CtAction {
                commit: true,
                zone: 10000,
                recirc_table: None,
                nat: Some(NatAction::SrcIp(ip("10.185.182.152"))),
            }))
            .add_action(Action::ModDlSrc(mac("aa:bb:cc:dd:ee:ff")))
            .add_action(Action::ModDlDst(mac("11:22:33:44:55:66")))
            .add_action(Action::DecTtl)
            .add_action(Action::PushVlan(308))
            .add_action(Action::Output("p0".to_string()));
        let stamped = c.stamp(&spec).unwrap();
        let arg = stamped.as_ovs_arg();
        assert!(arg.contains("ct(commit,zone=10000,nat(src=10.185.182.152))"));
        assert!(arg.contains("push_vlan:0x8100,set_field:4404->vlan_vid"));
        assert!(arg.ends_with("output:p0"));
    }

    #[test]
    fn renders_ct_recirc_with_nat_restore() {
        let c = policy();
        let spec = FlowSpec::new(FlowKind::SnatShared, 7, 100, 230)
            .add_match(Match::InPort("p0".to_string()))
            .add_match(Match::Ip)
            .add_match(Match::NwDst(ip("10.0.120.250")))
            .add_action(Action::Ct(CtAction {
                commit: false,
                zone: 10000,
                recirc_table: Some(115),
                nat: Some(NatAction::Restore),
            }));
        let stamped = c.stamp(&spec).unwrap();
        assert!(
            stamped
                .as_ovs_arg()
                .contains("ct(table=115,zone=10000,nat)")
        );
    }

    #[test]
    fn validates_port_names() {
        let c = policy();
        let spec = FlowSpec::new(FlowKind::Endpoint, 1, 100, 100)
            .add_match(Match::InPort("bad port".to_string()))
            .add_action(Action::Drop);
        assert_eq!(
            c.stamp(&spec).unwrap_err(),
            Violation::InvalidPortName {
                name: "bad port".to_string(),
            }
        );
    }

    #[test]
    fn validates_vlan_range() {
        let c = policy();
        let spec = FlowSpec::new(FlowKind::Endpoint, 1, 100, 100)
            .add_match(Match::DlVlan(0))
            .add_action(Action::Drop);
        assert_eq!(
            c.stamp(&spec).unwrap_err(),
            Violation::InvalidVlan { vlan: 0 },
        );
    }
}
