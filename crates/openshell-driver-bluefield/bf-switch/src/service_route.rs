// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Service route declarations for `BlueField` deployments.
//!
//! These routes make a DPU-resident service IP reachable from sandbox datapath
//! traffic. Application policy still decides which sandbox processes may use
//! the endpoint.

use core::{fmt, net::Ipv4Addr, str::FromStr};
use std::collections::HashSet;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Derive a stable locally-administered MAC for a service route IP.
#[must_use]
pub fn service_route_mac(address: Ipv4Addr) -> String {
    let octets = address.octets();
    format!(
        "02:bf:{:02x}:{:02x}:{:02x}:{:02x}",
        octets[0], octets[1], octets[2], octets[3]
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4AddressCidr {
    address: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4AddressCidr {
    pub fn new(address: Ipv4Addr, prefix_len: u8) -> Result<Self, String> {
        if prefix_len > 32 {
            return Err(format!("invalid IPv4 CIDR prefix length {prefix_len}"));
        }
        Ok(Self {
            address,
            prefix_len,
        })
    }

    pub fn address(self) -> Ipv4Addr {
        self.address
    }

    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }
}

impl fmt::Display for Ipv4AddressCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

impl FromStr for Ipv4AddressCidr {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix_len) = value
            .split_once('/')
            .ok_or_else(|| format!("IPv4 address CIDR {value:?} must be address/prefix"))?;
        if address.is_empty() || prefix_len.is_empty() {
            return Err(format!(
                "IPv4 address CIDR {value:?} must be address/prefix"
            ));
        }
        let address = address
            .parse::<Ipv4Addr>()
            .map_err(|err| format!("invalid IPv4 address {address:?}: {err}"))?;
        let prefix_len = prefix_len
            .parse::<u8>()
            .map_err(|err| format!("invalid IPv4 CIDR prefix {prefix_len:?}: {err}"))?;
        Self::new(address, prefix_len)
    }
}

impl Serialize for Ipv4AddressCidr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Ipv4AddressCidr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceRouteInterfaceKind {
    OvsInternal,
}

impl fmt::Display for ServiceRouteInterfaceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OvsInternal => f.write_str("ovs_internal"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceRouteProtocol {
    Tcp,
}

impl fmt::Display for ServiceRouteProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => f.write_str("tcp"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRoutePortConfig {
    pub protocol: ServiceRouteProtocol,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRouteConfig {
    pub name: String,
    pub address: Ipv4AddressCidr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<String>,
    pub interface_name: String,
    pub interface_kind: ServiceRouteInterfaceKind,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub ports: Vec<ServiceRoutePortConfig>,
}

impl ServiceRouteConfig {
    pub fn resolved_bridge<'a>(&'a self, default_bridge: &'a str) -> &'a str {
        self.bridge.as_deref().unwrap_or(default_bridge)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("service route name cannot be empty".to_string());
        }
        if self.interface_name.trim().is_empty() {
            return Err(format!(
                "service route {} interface_name cannot be empty",
                self.name
            ));
        }
        if self.bridge.as_deref().is_some_and(str::is_empty) {
            return Err(format!(
                "service route {} bridge cannot be empty",
                self.name
            ));
        }
        if self.ports.is_empty() {
            return Err(format!(
                "service route {} must declare at least one port",
                self.name
            ));
        }
        let mut ports = HashSet::new();
        for port in &self.ports {
            if port.port == 0 {
                return Err(format!("service route {} has invalid port 0", self.name));
            }
            if !ports.insert((port.protocol, port.port)) {
                return Err(format!(
                    "service route {} declares duplicate {} port {}",
                    self.name, port.protocol, port.port
                ));
            }
        }
        Ok(())
    }

    pub fn tcp_ports(&self) -> impl Iterator<Item = u16> + '_ {
        self.ports.iter().map(|port| match port.protocol {
            ServiceRouteProtocol::Tcp => port.port,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRoutesConfigFile {
    #[serde(default)]
    pub service_routes: Vec<ServiceRouteConfig>,
}

pub fn parse_service_routes_toml(raw: &str) -> Result<Vec<ServiceRouteConfig>, String> {
    let file: ServiceRoutesConfigFile =
        toml::from_str(raw).map_err(|err| format!("parse service routes TOML: {err}"))?;
    validate_service_routes(&file.service_routes)?;
    Ok(file.service_routes)
}

pub fn validate_service_routes(services: &[ServiceRouteConfig]) -> Result<(), String> {
    let mut names = HashSet::new();
    let mut interfaces = HashSet::new();
    for service in services {
        service.validate()?;
        if !names.insert(service.name.as_str()) {
            return Err(format!("duplicate service route name {}", service.name));
        }
        if !interfaces.insert((
            service.bridge.as_deref().unwrap_or_default(),
            service.interface_name.as_str(),
        )) {
            return Err(format!(
                "duplicate service route interface {} on bridge {}",
                service.interface_name,
                service.bridge.as_deref().unwrap_or("<default>")
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_service_routes_toml() {
        let raw = r#"
[[service_routes]]
name = "otel"
address = "100.64.4.2/24"
bridge = "br-openshell"
interface_name = "osotel"
interface_kind = "ovs_internal"
required = true

[[service_routes.ports]]
protocol = "tcp"
port = 4318
purpose = "otlp_http"
"#;

        let services = parse_service_routes_toml(raw).unwrap();

        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, "otel");
        assert_eq!(services[0].address.to_string(), "100.64.4.2/24");
        assert_eq!(
            services[0].address.address(),
            "100.64.4.2".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            services[0].interface_kind,
            ServiceRouteInterfaceKind::OvsInternal
        );
        assert_eq!(services[0].tcp_ports().collect::<Vec<_>>(), vec![4318]);
    }

    #[test]
    fn derives_stable_service_route_mac() {
        assert_eq!(
            service_route_mac("100.64.4.2".parse().unwrap()),
            "02:bf:64:40:04:02"
        );
    }

    #[test]
    fn rejects_duplicate_service_route_names() {
        let raw = r#"
[[service_routes]]
name = "otel"
address = "100.64.4.2/24"
interface_name = "osotel"
interface_kind = "ovs_internal"
ports = [{ protocol = "tcp", port = 4318 }]

[[service_routes]]
name = "otel"
address = "100.64.4.3/24"
interface_name = "osotel2"
interface_kind = "ovs_internal"
ports = [{ protocol = "tcp", port = 4319 }]
"#;

        let err = parse_service_routes_toml(raw).unwrap_err();

        assert!(err.contains("duplicate service route name otel"));
    }
}
