// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared uplink-ingress flows.
//!
//! Egress source-NAT and per-flow commit live per-endpoint (see
//! [`super::endpoint`]). What is genuinely shared across all endpoints on an
//! uplink is the *ingress* handling of return traffic: pass ARP to `NORMAL`,
//! and recirculate inbound IP through conntrack with `nat` into the RETURN
//! table where per-endpoint flows demux it to the right representor by
//! destination IP.
//!
//! These flows carry the `SnatShared` cookie keyed by the uplink port, so
//! they are installed once and outlive any single sandbox.

use core::net::Ipv4Addr;

use super::super::openflow::{
    Action, CtAction, FlowKind, FlowSpec, MacAddress, Match, flow_id_from_str, render,
};
use super::{
    CT_ZONE, FlowPlan, OPENSHELL_TABLE_ADMISSION, OPENSHELL_TABLE_RETURN, OVS_TABLE_CLASSIFIER,
};

/// Build the shared uplink-ingress flow set. `snat_ip` is retained for
/// correlation/auditing of the SNAT identity this uplink serves.
#[must_use]
pub fn snat_flows(
    bridge: &str,
    snat_ip: Ipv4Addr,
    snat_mac: Option<&MacAddress>,
    uplink_port: &str,
) -> FlowPlan {
    let flow_id = flow_id_from_str(&format!("snat:{snat_ip}:{uplink_port}"));
    let mut plan = FlowPlan::new(bridge);

    // CLASSIFIER: hand the uplink to the OpenShell pipeline for ARP and
    // reverse-NAT return handling.
    plan.flows.push(render(
        &FlowSpec::new(FlowKind::SnatShared, flow_id, OVS_TABLE_CLASSIFIER, 230)
            .match_(Match::InPort(uplink_port.to_string()))
            .action(Action::Resubmit(OPENSHELL_TABLE_ADMISSION)),
    ));

    // ADMISSION: answer upstream ARP for the shared SNAT VIP when a stable
    // DPU-owned MAC is configured.
    if let Some(mac) = snat_mac {
        plan.flows.push(render(
            &FlowSpec::new(
                FlowKind::SnatShared,
                flow_id,
                OPENSHELL_TABLE_ADMISSION,
                250,
            )
            .match_(Match::InPort(uplink_port.to_string()))
            .match_(Match::Arp)
            .match_(Match::ArpTpa(snat_ip))
            .match_(Match::ArpOp(1))
            .action(Action::MoveField {
                src: "NXM_OF_ETH_SRC[]".to_string(),
                dst: "NXM_OF_ETH_DST[]".to_string(),
            })
            .action(Action::SetEthSrc(mac.clone()))
            .action(Action::LoadHex {
                value: "2".to_string(),
                dst: "NXM_OF_ARP_OP[]".to_string(),
            })
            .action(Action::MoveField {
                src: "NXM_NX_ARP_SHA[]".to_string(),
                dst: "NXM_NX_ARP_THA[]".to_string(),
            })
            .action(Action::MoveField {
                src: "NXM_OF_ARP_SPA[]".to_string(),
                dst: "NXM_OF_ARP_TPA[]".to_string(),
            })
            .action(Action::LoadHex {
                value: mac.hex_no_separators(),
                dst: "NXM_NX_ARP_SHA[]".to_string(),
            })
            .action(Action::LoadHex {
                value: format!("{:x}", u32::from_be_bytes(snat_ip.octets())),
                dst: "NXM_OF_ARP_SPA[]".to_string(),
            })
            .action(Action::InPort),
        ));
    }

    // ADMISSION: ARP arriving on the uplink goes to NORMAL.
    plan.flows.push(render(
        &FlowSpec::new(
            FlowKind::SnatShared,
            flow_id,
            OPENSHELL_TABLE_ADMISSION,
            190,
        )
        .match_(Match::InPort(uplink_port.to_string()))
        .match_(Match::Arp)
        .action(Action::Normal),
    ));

    // ADMISSION: inbound IP on the uplink. Recirculate through conntrack with
    // `nat` so OVS applies the reverse mapping created by the outbound
    // `nat(src=...)` commit before the RETURN-table destination-IP demux.
    plan.flows.push(render(
        &FlowSpec::new(FlowKind::SnatShared, flow_id, OPENSHELL_TABLE_ADMISSION, 90)
            .match_(Match::InPort(uplink_port.to_string()))
            .match_(Match::Ip)
            .action(Action::Ct(CtAction::track_nat(
                OPENSHELL_TABLE_RETURN,
                CT_ZONE,
            ))),
    ));

    plan
}

#[cfg(test)]
mod tests {
    use super::snat_flows;

    #[test]
    fn builds_arp_normal_and_ingress_ct() {
        let plan = snat_flows(
            "br-openshell",
            "10.0.120.60".parse().unwrap(),
            None,
            "osuplink",
        );
        assert_eq!(plan.flows.len(), 3);
        assert!(plan.flows[0].contains("in_port=osuplink"));
        assert!(plan.flows[0].ends_with("actions=resubmit(,100)"));
        assert!(plan.flows[1].contains("arp"));
        assert!(plan.flows[1].ends_with("actions=NORMAL"));
        assert!(plan.flows[2].contains("ct(table=115,zone=1,nat)"));
    }

    #[test]
    fn builds_vip_arp_responder_when_snat_mac_is_configured() {
        let mac = "02:50:00:78:02:50".parse().unwrap();
        let plan = snat_flows(
            "br-openshell",
            "10.0.120.250".parse().unwrap(),
            Some(&mac),
            "osuplink",
        );
        let arp = plan
            .flows
            .iter()
            .find(|flow| flow.contains("arp_tpa=10.0.120.250"))
            .expect("vip ARP responder flow");
        assert!(arp.contains("arp_op=1"));
        assert!(arp.contains("mod_dl_src:02:50:00:78:02:50"));
        assert!(arp.contains("load:0x025000780250->NXM_NX_ARP_SHA[]"));
        assert!(arp.contains("load:0xa0078fa->NXM_OF_ARP_SPA[]"));
        assert!(arp.ends_with("IN_PORT"));
    }
}
