// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-endpoint (per-sandbox) egress pipeline.
//!
//! The full connection-tracked egress path for one VF representor, expressed
//! through the typed `OpenFlow` grammar. All flows carry this endpoint's
//! `Endpoint` cookie so detach can surgically remove exactly this sandbox's
//! state ([`super::super::openflow::exact_mask`]).
//!
//! Pipeline (all in the shared [`CT_ZONE`](super::CT_ZONE)):
//! - **ADMISSION**: answer ARP for the DPU-owned guest gateway when configured,
//!   pass other ARP to `NORMAL`, start conntrack on IP and recirculate to
//!   FORWARD; deny-default everything else from the representor.
//! - **FORWARD**: new connections commit + source-NAT and leave via the
//!   uplink; established connections leave via the uplink.
//! - **RETURN**: established replies destined to this guest's datapath IP are
//!   delivered back to its representor. Return demux is by destination IP, so
//!   the shared uplink-ingress flow ([`super::snat`]) only has to recirculate
//!   into the RETURN table.

use core::{fmt, net::Ipv4Addr, str::FromStr};
use std::collections::BTreeSet;

use super::super::openflow::{
    Action, CtAction, FlowKind, FlowSpec, MacAddress, Match, flow_id_from_str, render,
};
use super::{
    CT_ZONE, FlowPlan, OPENSHELL_TABLE_ADMISSION, OPENSHELL_TABLE_FORWARD, OPENSHELL_TABLE_RETURN,
    OVS_TABLE_CLASSIFIER,
};

/// Forced explicit-proxy admission for one sandbox VF.
///
/// When configured, guest-originated IP traffic is admitted only to the DPU
/// explicit proxy listener. Direct egress from the VF representor is dropped
/// before conntrack/SNAT, so the proxy becomes the only L7 path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForcedProxyEgress {
    pub proxy_ip: Ipv4Addr,
    pub proxy_port: u16,
    /// Guest data subnet reachable through the explicit proxy OVS port.
    ///
    /// The controller installs this route once per process instead of adding
    /// one kernel host route for each sandbox.
    pub proxy_subnet: Ipv4Cidr,
    pub proxy_ovs_port: String,
    pub proxy_mac: Option<MacAddress>,
}

/// A service route endpoint admitted for sandbox datapath traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRouteEgress {
    pub name: String,
    pub ip: Ipv4Addr,
    pub port: u16,
    pub ovs_port: String,
    pub mac: MacAddress,
}

/// IPv4 CIDR prefix used for DPU-side kernel route configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Cidr {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Cidr {
    pub fn new(address: Ipv4Addr, prefix_len: u8) -> Result<Self, String> {
        if prefix_len > 32 {
            return Err(format!("invalid IPv4 CIDR prefix length {prefix_len}"));
        }
        let mask = if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - u32::from(prefix_len))
        };
        let network = Ipv4Addr::from(u32::from(address) & mask);
        Ok(Self {
            network,
            prefix_len,
        })
    }

    #[must_use]
    pub fn network(self) -> Ipv4Addr {
        self.network
    }

    #[must_use]
    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }
}

impl fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

impl FromStr for Ipv4Cidr {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (ip, prefix_len) = value
            .split_once('/')
            .ok_or_else(|| format!("IPv4 CIDR {value:?} must be address/prefix"))?;
        if ip.is_empty() || prefix_len.is_empty() {
            return Err(format!("IPv4 CIDR {value:?} must be address/prefix"));
        }
        let ip = ip
            .parse::<Ipv4Addr>()
            .map_err(|err| format!("invalid IPv4 CIDR address {ip:?}: {err}"))?;
        let prefix_len = prefix_len
            .parse::<u8>()
            .map_err(|err| format!("invalid IPv4 CIDR prefix {prefix_len:?}: {err}"))?;
        Self::new(ip, prefix_len)
    }
}

/// Build the egress pipeline flows for a sandbox VF `representor`.
///
/// `guest_ip` is the guest's datapath address used for RETURN-table demux;
/// when `None` the return flow is omitted (egress still works, replies fall to
/// the bridge default). `snat_ip` / `uplink_port` are the shared egress
/// parameters (see [`super::snat`]). When `snat_mac` is set, outbound frames
/// use that stable Ethernet source so the upstream router learns the DPU VIP
/// owner. When `upstream_gateway_mac` is set, outbound frames are rewritten to
/// the upstream router's Ethernet destination before leaving the uplink. When
/// `guest_mac` is set, return frames are rewritten to the VF MAC before
/// delivery to the representor. When `guest_gateway_mac` is set, return frames
/// use that DPU-owned gateway MAC as their Ethernet source.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn endpoint_flows(
    bridge: &str,
    claim_id: &str,
    representor: &str,
    guest_ip: Option<Ipv4Addr>,
    snat_ip: Ipv4Addr,
    snat_mac: Option<&MacAddress>,
    guest_mac: Option<&MacAddress>,
    guest_gateway_ip: Option<Ipv4Addr>,
    guest_gateway_mac: Option<&MacAddress>,
    upstream_gateway_mac: Option<&MacAddress>,
    uplink_port: &str,
) -> FlowPlan {
    endpoint_flows_with_forced_proxy(
        bridge,
        claim_id,
        representor,
        guest_ip,
        snat_ip,
        snat_mac,
        guest_mac,
        guest_gateway_ip,
        guest_gateway_mac,
        upstream_gateway_mac,
        uplink_port,
        None,
    )
}

/// Build the endpoint pipeline, optionally forcing all guest IP traffic
/// through the DPU explicit proxy listener.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn endpoint_flows_with_forced_proxy(
    bridge: &str,
    claim_id: &str,
    representor: &str,
    guest_ip: Option<Ipv4Addr>,
    snat_ip: Ipv4Addr,
    snat_mac: Option<&MacAddress>,
    guest_mac: Option<&MacAddress>,
    guest_gateway_ip: Option<Ipv4Addr>,
    guest_gateway_mac: Option<&MacAddress>,
    upstream_gateway_mac: Option<&MacAddress>,
    uplink_port: &str,
    forced_proxy: Option<&ForcedProxyEgress>,
) -> FlowPlan {
    endpoint_flows_with_forced_proxy_and_service_routes(
        bridge,
        claim_id,
        representor,
        guest_ip,
        snat_ip,
        snat_mac,
        guest_mac,
        guest_gateway_ip,
        guest_gateway_mac,
        upstream_gateway_mac,
        uplink_port,
        forced_proxy,
        &[],
    )
}

/// Build the endpoint pipeline, optionally forcing guest IP traffic through
/// the DPU explicit proxy while admitting declared service routes.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn endpoint_flows_with_forced_proxy_and_service_routes(
    bridge: &str,
    claim_id: &str,
    representor: &str,
    guest_ip: Option<Ipv4Addr>,
    snat_ip: Ipv4Addr,
    snat_mac: Option<&MacAddress>,
    guest_mac: Option<&MacAddress>,
    guest_gateway_ip: Option<Ipv4Addr>,
    guest_gateway_mac: Option<&MacAddress>,
    upstream_gateway_mac: Option<&MacAddress>,
    uplink_port: &str,
    forced_proxy: Option<&ForcedProxyEgress>,
    service_routes: &[ServiceRouteEgress],
) -> FlowPlan {
    let flow_id = flow_id_from_str(claim_id);
    let mut plan = FlowPlan::new(bridge);

    // CLASSIFIER: hand this sandbox representor to the OpenShell pipeline.
    plan.flows.push(render(
        &FlowSpec::new(FlowKind::Endpoint, flow_id, OVS_TABLE_CLASSIFIER, 240)
            .match_(Match::InPort(representor.to_string()))
            .action(Action::Resubmit(OPENSHELL_TABLE_ADMISSION)),
    ));

    // ADMISSION: answer ARP for the DPU-owned guest gateway. This enables
    // private VM datapath subnets where the DPU acts as the first hop.
    if let (Some(gateway_ip), Some(gateway_mac)) = (guest_gateway_ip, guest_gateway_mac) {
        plan.flows.push(render(
            &FlowSpec::new(FlowKind::Endpoint, flow_id, OPENSHELL_TABLE_ADMISSION, 250)
                .match_(Match::InPort(representor.to_string()))
                .match_(Match::Arp)
                .match_(Match::ArpTpa(gateway_ip))
                .match_(Match::ArpOp(1))
                .action(Action::MoveField {
                    src: "NXM_OF_ETH_SRC[]".to_string(),
                    dst: "NXM_OF_ETH_DST[]".to_string(),
                })
                .action(Action::SetEthSrc(gateway_mac.clone()))
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
                    value: gateway_mac.hex_no_separators(),
                    dst: "NXM_NX_ARP_SHA[]".to_string(),
                })
                .action(Action::LoadHex {
                    value: format!("{:x}", u32::from_be_bytes(gateway_ip.octets())),
                    dst: "NXM_OF_ARP_SPA[]".to_string(),
                })
                .action(Action::InPort),
        ));
    }

    // ADMISSION: let other ARP through so legacy same-subnet setups can resolve
    // their upstream gateway via NORMAL.
    plan.flows.push(render(
        &FlowSpec::new(FlowKind::Endpoint, flow_id, OPENSHELL_TABLE_ADMISSION, 200)
            .match_(Match::InPort(representor.to_string()))
            .match_(Match::Arp)
            .action(Action::Normal),
    ));

    push_service_route_flows(
        &mut plan,
        flow_id,
        representor,
        guest_ip,
        guest_mac,
        service_routes,
    );

    if let Some(proxy) = forced_proxy {
        if let Some(ip) = guest_ip {
            let mut ret = FlowSpec::new(FlowKind::Endpoint, flow_id, OVS_TABLE_CLASSIFIER, 250)
                .match_(Match::InPort(proxy.proxy_ovs_port.clone()))
                .match_(Match::Ip)
                .match_(Match::NwDst(ip));
            if let Some(mac) = &proxy.proxy_mac {
                ret = ret.action(Action::SetEthSrc(mac.clone()));
            }
            if let Some(mac) = guest_mac {
                ret = ret.action(Action::SetEthDst(mac.clone()));
            }
            plan.flows
                .push(render(&ret.action(Action::Output(representor.to_string()))));
        }

        let mut allow_proxy =
            FlowSpec::new(FlowKind::Endpoint, flow_id, OPENSHELL_TABLE_ADMISSION, 150)
                .match_(Match::InPort(representor.to_string()))
                .match_(Match::Tcp);
        if let Some(ip) = guest_ip {
            allow_proxy = allow_proxy.match_(Match::NwSrc(ip));
        }
        allow_proxy = allow_proxy
            .match_(Match::NwDst(proxy.proxy_ip))
            .match_(Match::TpDst(proxy.proxy_port));
        if let Some(mac) = &proxy.proxy_mac {
            allow_proxy = allow_proxy.action(Action::SetEthDst(mac.clone()));
        }
        plan.flows.push(render(
            &allow_proxy.action(Action::Output(proxy.proxy_ovs_port.clone())),
        ));
        plan.flows.push(render(
            &FlowSpec::new(FlowKind::Endpoint, flow_id, OPENSHELL_TABLE_ADMISSION, 100)
                .match_(Match::InPort(representor.to_string()))
                .match_(Match::Ip)
                .action(Action::Drop),
        ));
        plan.flows.push(render(
            &FlowSpec::new(FlowKind::Endpoint, flow_id, OPENSHELL_TABLE_ADMISSION, 0)
                .match_(Match::InPort(representor.to_string()))
                .action(Action::Drop),
        ));
        return plan;
    }

    // ADMISSION: start conntrack on IP traffic and recirculate to FORWARD.
    let mut track = FlowSpec::new(FlowKind::Endpoint, flow_id, OPENSHELL_TABLE_ADMISSION, 100)
        .match_(Match::InPort(representor.to_string()))
        .match_(Match::Ip);
    if let Some(ip) = guest_ip {
        track = track.match_(Match::NwSrc(ip));
    }
    plan.flows
        .push(render(&track.action(Action::Ct(CtAction::track_nat(
            OPENSHELL_TABLE_FORWARD,
            CT_ZONE,
        )))));

    // ADMISSION: deny-default everything else from the representor.
    plan.flows.push(render(
        &FlowSpec::new(FlowKind::Endpoint, flow_id, OPENSHELL_TABLE_ADMISSION, 0)
            .match_(Match::InPort(representor.to_string()))
            .action(Action::Drop),
    ));

    // FORWARD: new connections — commit + source-NAT, then leave via uplink.
    let mut forward_new = FlowSpec::new(FlowKind::Endpoint, flow_id, OPENSHELL_TABLE_FORWARD, 110)
        .match_(Match::InPort(representor.to_string()))
        .match_(Match::Ip)
        .match_(Match::CtState("+new+trk".to_string()))
        .action(Action::Ct(CtAction::commit_snat(CT_ZONE, snat_ip)));
    if let Some(mac) = snat_mac {
        forward_new = forward_new.action(Action::SetEthSrc(mac.clone()));
    }
    if let Some(mac) = upstream_gateway_mac {
        forward_new = forward_new.action(Action::SetEthDst(mac.clone()));
    }
    plan.flows.push(render(
        &forward_new.action(Action::Output(uplink_port.to_string())),
    ));

    // FORWARD: established connections — leave via uplink.
    let mut forward_est = FlowSpec::new(FlowKind::Endpoint, flow_id, OPENSHELL_TABLE_FORWARD, 100)
        .match_(Match::InPort(representor.to_string()))
        .match_(Match::Ip)
        .match_(Match::CtState("+est+trk".to_string()));
    if let Some(mac) = snat_mac {
        forward_est = forward_est.action(Action::SetEthSrc(mac.clone()));
    }
    if let Some(mac) = upstream_gateway_mac {
        forward_est = forward_est.action(Action::SetEthDst(mac.clone()));
    }
    plan.flows.push(render(
        &forward_est.action(Action::Output(uplink_port.to_string())),
    ));

    // RETURN: established replies for this guest go back to its representor.
    if let Some(ip) = guest_ip {
        let mut ret = FlowSpec::new(FlowKind::Endpoint, flow_id, OPENSHELL_TABLE_RETURN, 100)
            .match_(Match::Ip)
            .match_(Match::NwDst(ip))
            .match_(Match::CtState("+est+trk".to_string()));
        if let Some(mac) = guest_gateway_mac {
            ret = ret.action(Action::SetEthSrc(mac.clone()));
        }
        if let Some(mac) = guest_mac {
            ret = ret.action(Action::SetEthDst(mac.clone()));
        }
        plan.flows
            .push(render(&ret.action(Action::Output(representor.to_string()))));
    }

    plan
}

fn push_service_route_flows(
    plan: &mut FlowPlan,
    flow_id: u32,
    representor: &str,
    guest_ip: Option<Ipv4Addr>,
    guest_mac: Option<&MacAddress>,
    services: &[ServiceRouteEgress],
) {
    let mut return_ports = BTreeSet::new();

    for service in services {
        plan.flows.push(render(
            &FlowSpec::new(FlowKind::Endpoint, flow_id, OPENSHELL_TABLE_ADMISSION, 240)
                .match_(Match::InPort(representor.to_string()))
                .match_(Match::Arp)
                .match_(Match::ArpTpa(service.ip))
                .match_(Match::ArpOp(1))
                .action(Action::MoveField {
                    src: "NXM_OF_ETH_SRC[]".to_string(),
                    dst: "NXM_OF_ETH_DST[]".to_string(),
                })
                .action(Action::SetEthSrc(service.mac.clone()))
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
                    value: service.mac.hex_no_separators(),
                    dst: "NXM_NX_ARP_SHA[]".to_string(),
                })
                .action(Action::LoadHex {
                    value: format!("{:x}", u32::from_be_bytes(service.ip.octets())),
                    dst: "NXM_OF_ARP_SPA[]".to_string(),
                })
                .action(Action::InPort),
        ));
        let mut allow = FlowSpec::new(FlowKind::Endpoint, flow_id, OPENSHELL_TABLE_ADMISSION, 160)
            .match_(Match::InPort(representor.to_string()))
            .match_(Match::Tcp);
        if let Some(ip) = guest_ip {
            allow = allow.match_(Match::NwSrc(ip));
        }
        plan.flows.push(render(
            &allow
                .match_(Match::NwDst(service.ip))
                .match_(Match::TpDst(service.port))
                .action(Action::SetEthDst(service.mac.clone()))
                .action(Action::Output(service.ovs_port.clone())),
        ));
        return_ports.insert((service.ovs_port.clone(), service.mac.clone()));
    }

    let Some(ip) = guest_ip else {
        return;
    };

    for (ovs_port, service_mac) in return_ports {
        let mut ret = FlowSpec::new(FlowKind::Endpoint, flow_id, OVS_TABLE_CLASSIFIER, 245)
            .match_(Match::InPort(ovs_port))
            .match_(Match::Ip)
            .match_(Match::NwDst(ip))
            .action(Action::SetEthSrc(service_mac));
        if let Some(mac) = guest_mac {
            ret = ret.action(Action::SetEthDst(mac.clone()));
        }
        plan.flows
            .push(render(&ret.action(Action::Output(representor.to_string()))));
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{
        ForcedProxyEgress, Ipv4Cidr, ServiceRouteEgress, endpoint_flows,
        endpoint_flows_with_forced_proxy, endpoint_flows_with_forced_proxy_and_service_routes,
    };

    fn plan() -> Vec<String> {
        endpoint_flows(
            "br-openshell",
            "claim-sandbox-1",
            "pf0vf0",
            Some("10.0.120.10".parse().unwrap()),
            "10.0.120.1".parse().unwrap(),
            None,
            None,
            None,
            None,
            None,
            "osuplink",
        )
        .flows
    }

    #[test]
    fn admission_allows_arp_and_tracks_ip() {
        let flows = plan();
        assert!(flows[0].contains("table=0"));
        assert!(flows[0].contains("in_port=pf0vf0"));
        assert!(flows[0].ends_with("actions=resubmit(,100)"));
        assert!(flows[1].contains("arp"));
        assert!(flows[1].ends_with("actions=NORMAL"));
        assert!(flows[2].contains("in_port=pf0vf0"));
        assert!(flows[2].contains("ct(table=110,zone=1,nat)"));
        assert!(flows[3].ends_with("actions=drop"));
    }

    #[test]
    fn admission_tracks_only_configured_guest_source_and_applies_nat() {
        let flows = plan();
        let track = flows
            .iter()
            .find(|flow| flow.contains("ct(table=110"))
            .expect("conntrack admission flow");
        assert!(track.contains("nw_src=10.0.120.10"));
        assert!(track.contains("ct(table=110,zone=1,nat)"));
    }

    #[test]
    fn forward_commits_and_snats_new_connections() {
        let flows = plan();
        let new = flows
            .iter()
            .find(|f| f.contains("ct_state=+new+trk"))
            .expect("new-connection flow");
        assert!(new.contains("ct(commit,zone=1,nat(src=10.0.120.1))"));
        assert!(new.ends_with("output:osuplink"));
    }

    #[test]
    fn return_demuxes_to_representor_by_guest_ip() {
        let flows = plan();
        let ret = flows
            .iter()
            .find(|f| f.contains("nw_dst=10.0.120.10"))
            .expect("return flow");
        assert!(ret.contains("ct_state=+est+trk"));
        assert!(ret.ends_with("output:pf0vf0"));
    }

    #[test]
    fn return_flow_omitted_without_guest_ip() {
        let flows = endpoint_flows(
            "br-openshell",
            "c",
            "pf0vf0",
            None,
            "10.0.120.1".parse().unwrap(),
            None,
            None,
            None,
            None,
            None,
            "osuplink",
        )
        .flows;
        assert!(flows.iter().all(|f| !f.contains("table=115")));
    }

    #[test]
    fn l2_rewrites_use_configured_snat_and_guest_macs() {
        let snat_mac = "02:50:00:78:02:50".parse().unwrap();
        let guest_mac = "86:7f:6e:5b:e0:7b".parse().unwrap();
        let flows = endpoint_flows(
            "br-openshell",
            "claim-sandbox-1",
            "pf0vf0",
            Some("10.0.120.10".parse().unwrap()),
            "10.0.120.250".parse().unwrap(),
            Some(&snat_mac),
            Some(&guest_mac),
            None,
            None,
            None,
            "osuplink",
        )
        .flows;

        let new = flows
            .iter()
            .find(|f| f.contains("ct_state=+new+trk"))
            .expect("new-connection flow");
        assert!(new.contains("mod_dl_src:02:50:00:78:02:50"));

        let ret = flows
            .iter()
            .find(|f| f.contains("table=115"))
            .expect("return flow");
        assert!(ret.contains("mod_dl_dst:86:7f:6e:5b:e0:7b"));
        assert!(ret.ends_with("output:pf0vf0"));
    }

    #[test]
    fn router_mode_answers_gateway_arp_and_rewrites_l2_next_hops() {
        let snat_mac = "02:50:00:78:02:50".parse().unwrap();
        let guest_mac = "86:7f:6e:5b:e0:7b".parse().unwrap();
        let gateway_mac = "02:bf:64:04:00:01".parse().unwrap();
        let upstream_mac = "52:54:00:8f:c9:6a".parse().unwrap();
        let flows = endpoint_flows(
            "br-openshell",
            "claim-sandbox-1",
            "pf0vf0",
            Some("100.64.4.10".parse().unwrap()),
            "10.0.120.250".parse().unwrap(),
            Some(&snat_mac),
            Some(&guest_mac),
            Some("100.64.4.1".parse().unwrap()),
            Some(&gateway_mac),
            Some(&upstream_mac),
            "osuplink",
        )
        .flows;

        let gateway_arp = flows
            .iter()
            .find(|f| f.contains("arp_tpa=100.64.4.1"))
            .expect("guest gateway ARP responder");
        assert!(gateway_arp.contains("arp_op=1"));
        assert!(gateway_arp.contains("mod_dl_src:02:bf:64:04:00:01"));
        assert!(gateway_arp.contains("load:0x02bf64040001->NXM_NX_ARP_SHA[]"));
        assert!(gateway_arp.contains("load:0x64400401->NXM_OF_ARP_SPA[]"));
        assert!(gateway_arp.ends_with("IN_PORT"));

        let new = flows
            .iter()
            .find(|f| f.contains("ct_state=+new+trk"))
            .expect("new-connection flow");
        assert!(new.contains("mod_dl_src:02:50:00:78:02:50"));
        assert!(new.contains("mod_dl_dst:52:54:00:8f:c9:6a"));
        assert!(new.ends_with("output:osuplink"));

        let ret = flows
            .iter()
            .find(|f| f.contains("table=115"))
            .expect("return flow");
        assert!(ret.contains("mod_dl_src:02:bf:64:04:00:01"));
        assert!(ret.contains("mod_dl_dst:86:7f:6e:5b:e0:7b"));
        assert!(ret.ends_with("output:pf0vf0"));
    }

    #[test]
    fn forced_proxy_admits_only_explicit_proxy_listener() {
        let proxy = ForcedProxyEgress {
            proxy_ip: "100.64.4.1".parse().unwrap(),
            proxy_port: 3128,
            proxy_subnet: "100.64.4.0/24".parse().unwrap(),
            proxy_ovs_port: "osproxy".to_string(),
            proxy_mac: Some("02:bf:64:04:00:01".parse().unwrap()),
        };
        let flows = endpoint_flows_with_forced_proxy(
            "br-openshell",
            "claim-sandbox-1",
            "pf0vf0",
            Some("100.64.4.10".parse().unwrap()),
            "10.0.120.250".parse().unwrap(),
            None,
            None,
            Some("100.64.4.1".parse().unwrap()),
            Some(&"02:bf:64:04:00:01".parse().unwrap()),
            None,
            "osuplink",
            Some(&proxy),
        )
        .flows;

        let allow = flows
            .iter()
            .find(|flow| flow.contains("tcp") && flow.contains("tp_dst=3128"))
            .expect("explicit proxy allow flow");
        assert!(allow.contains("nw_src=100.64.4.10"));
        assert!(allow.contains("nw_dst=100.64.4.1"));
        assert!(allow.contains("mod_dl_dst:02:bf:64:04:00:01"));
        assert!(allow.ends_with("output:osproxy"));

        let ret = flows
            .iter()
            .find(|flow| flow.contains("in_port=osproxy") && flow.contains("nw_dst=100.64.4.10"))
            .expect("explicit proxy return flow");
        assert!(ret.contains("table=0"));
        assert!(ret.contains("mod_dl_src:02:bf:64:04:00:01"));
        assert!(ret.ends_with("output:pf0vf0"));

        let ip_drop = flows
            .iter()
            .find(|flow| flow.contains("priority=100") && flow.contains("ip"))
            .expect("direct IP drop flow");
        assert!(ip_drop.ends_with("actions=drop"));
        assert!(
            flows
                .iter()
                .all(|flow| !flow.contains("ct(commit") && !flow.contains("output:osuplink"))
        );
    }

    #[test]
    fn ipv4_cidr_parses_and_normalizes_network_address() {
        let cidr: Ipv4Cidr = "100.64.4.35/24".parse().unwrap();
        assert_eq!(cidr.network(), "100.64.4.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(cidr.prefix_len(), 24);
        assert_eq!(cidr.to_string(), "100.64.4.0/24");
    }

    #[test]
    fn ipv4_cidr_rejects_invalid_prefix() {
        assert!("100.64.4.0/33".parse::<Ipv4Cidr>().is_err());
        assert!("100.64.4.0".parse::<Ipv4Cidr>().is_err());
    }

    #[test]
    fn forced_proxy_admits_declared_service_route() {
        let services = vec![ServiceRouteEgress {
            name: "otel".to_string(),
            ip: "100.64.4.2".parse().unwrap(),
            port: 4318,
            ovs_port: "osotel".to_string(),
            mac: "02:bf:64:40:04:02".parse().unwrap(),
        }];
        let flows = endpoint_flows_with_forced_proxy_and_service_routes(
            "br-openshell",
            "claim-sandbox-1",
            "pf0vf0",
            Some("100.64.4.10".parse().unwrap()),
            "10.0.120.1".parse().unwrap(),
            None,
            Some(&"86:7f:6e:5b:e0:7b".parse().unwrap()),
            None,
            None,
            None,
            "osuplink",
            Some(&ForcedProxyEgress {
                proxy_ip: "100.64.4.1".parse().unwrap(),
                proxy_port: 3128,
                proxy_subnet: "100.64.4.0/24".parse().unwrap(),
                proxy_ovs_port: "osproxy".to_string(),
                proxy_mac: Some("02:bf:64:04:00:01".parse().unwrap()),
            }),
            &services,
        )
        .flows;

        let arp_otel = flows
            .iter()
            .find(|flow| flow.contains("arp_tpa=100.64.4.2"))
            .expect("OTEL ARP responder");
        assert!(arp_otel.contains("arp_op=1"));
        assert!(arp_otel.contains("mod_dl_src:02:bf:64:40:04:02"));
        assert!(arp_otel.contains("load:0x02bf64400402->NXM_NX_ARP_SHA[]"));
        assert!(arp_otel.contains("load:0x64400402->NXM_OF_ARP_SPA[]"));
        assert!(arp_otel.ends_with("IN_PORT"));

        let allow_otel = flows
            .iter()
            .find(|flow| flow.contains("nw_dst=100.64.4.2") && flow.contains("tp_dst=4318"))
            .expect("OTEL allow flow");
        assert!(allow_otel.contains("nw_src=100.64.4.10"));
        assert!(allow_otel.contains("mod_dl_dst:02:bf:64:40:04:02"));
        assert!(allow_otel.ends_with("output:osotel"));

        let return_otel = flows
            .iter()
            .find(|flow| flow.contains("in_port=osotel") && flow.contains("nw_dst=100.64.4.10"))
            .expect("OTEL return flow");
        assert!(return_otel.contains("mod_dl_src:02:bf:64:40:04:02"));
        assert!(return_otel.contains("mod_dl_dst:86:7f:6e:5b:e0:7b"));
        assert!(return_otel.ends_with("output:pf0vf0"));

        let direct_drop = flows
            .iter()
            .find(|flow| {
                flow.contains("in_port=pf0vf0")
                    && flow.contains("priority=100")
                    && flow.contains("ip")
            })
            .expect("direct guest IP drop");
        assert!(direct_drop.ends_with("actions=drop"));
    }
}
