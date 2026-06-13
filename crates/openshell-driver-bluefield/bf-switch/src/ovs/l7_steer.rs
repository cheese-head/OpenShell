// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Steer a sandbox VF's egress to the tier-2 L7 proxy.
//!
//! These flows are **L3/L4 only**. They match a 5-tuple on the representor
//! and output to the proxy's OVS port; OVS never inspects payload. The proxy
//! (a separate, org-trust-domain process on the DPU) is the sole L7 vantage
//! point. This keeps the datapath/controller free of L7 policy while still
//! routing egress through the tier-2 proxy.

use super::super::openflow::{
    Action, FlowKind, FlowSpec, MacAddress, Match, flow_id_from_str, render,
};
use super::{FlowPlan, OPENSHELL_TABLE_FORWARD};

/// Build the flow that redirects TCP egress arriving on `representor` and
/// destined to `endpoint_port` to the proxy's OVS port (`proxy_port`).
///
/// Priority is above the plain SNAT forward flow so proxied endpoints win.
/// Transparent interception on the proxy side recovers the original
/// destination; no DNAT is rendered here. When `proxy_mac` is available, the
/// flow rewrites the Ethernet destination so the Linux netdev accepts the
/// steered frame as local traffic instead of `PACKET_OTHERHOST`.
#[must_use]
pub fn steer_to_proxy(
    bridge: &str,
    workload_id: &str,
    representor: &str,
    endpoint_port: u16,
    proxy_port: &str,
    proxy_mac: Option<&MacAddress>,
) -> FlowPlan {
    let flow_id = flow_id_from_str(&format!("l7:{workload_id}:{endpoint_port}"));
    let mut plan = FlowPlan::new(bridge);
    let mut flow = FlowSpec::new(FlowKind::Policy, flow_id, OPENSHELL_TABLE_FORWARD, 200)
        .match_(Match::InPort(representor.to_string()))
        .match_(Match::Tcp)
        .match_(Match::TpDst(endpoint_port));
    if let Some(mac) = proxy_mac {
        flow = flow.action(Action::SetEthDst(mac.clone()));
    }
    plan.flows
        .push(render(&flow.action(Action::Output(proxy_port.to_string()))));
    plan
}

#[cfg(test)]
mod tests {
    use super::steer_to_proxy;

    #[test]
    fn steers_tcp_dst_port_to_proxy_port() {
        let plan = steer_to_proxy(
            "br-openshell",
            "workload-1",
            "pf0vf0",
            443,
            "osl7proxy",
            None,
        );
        assert_eq!(plan.flows.len(), 1);
        let flow = &plan.flows[0];
        assert!(flow.contains("in_port=pf0vf0"));
        assert!(flow.contains("tcp"));
        assert!(flow.contains("tp_dst=443"));
        assert!(flow.ends_with("output:osl7proxy"));
    }

    #[test]
    fn rewrites_destination_mac_when_proxy_mac_is_known() {
        let proxy_mac = "06:5e:29:f8:ab:cb".parse().unwrap();
        let plan = steer_to_proxy(
            "br-openshell",
            "workload-1",
            "pf0vf0",
            443,
            "osl7proxy",
            Some(&proxy_mac),
        );
        let flow = &plan.flows[0];
        assert!(flow.contains("mod_dl_dst:06:5e:29:f8:ab:cb"));
        assert!(flow.ends_with("output:osl7proxy"));
    }
}
