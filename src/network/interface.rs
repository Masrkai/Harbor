// src/network/interface.rs
use pnet::datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface};
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub name: String,
    pub index: u32,
    pub mac: Option<String>,
    pub ips: Vec<String>,
    pub is_up: bool,
    pub is_loopback: bool,
}

impl InterfaceInfo {
    pub fn from_interface(iface: &NetworkInterface) -> Self {
        let ips: Vec<String> = iface.ips.iter().map(|ip| ip.to_string()).collect();

        Self {
            name: iface.name.clone(),
            index: iface.index,
            mac: iface.mac.map(|m| m.to_string()),
            ips,
            is_up: iface.is_up(),
            is_loopback: iface.is_loopback(),
        }
    }

    pub fn display_name(&self) -> String {
        let status = if self.is_up { "●" } else { "○" };
        let loopback = if self.is_loopback { " [LOOPBACK]" } else { "" };
        format!("{} {}{}", status, self.name, loopback)
    }

    pub fn has_ipv4(&self) -> bool {
        self.ips.iter().any(|ip| ip.contains('.'))
    }

    pub fn primary_ipv4(&self) -> Option<Ipv4Addr> {
        self.ips.iter().find_map(|ip| {
            ip.parse::<std::net::IpAddr>().ok().and_then(|ip| match ip {
                std::net::IpAddr::V4(v4) => Some(v4),
                _ => None,
            })
        })
    }
}

pub fn list_interfaces() -> Vec<InterfaceInfo> {
    datalink::interfaces()
        .iter()
        .map(InterfaceInfo::from_interface)
        .collect()
}

pub fn get_active_interfaces() -> Vec<InterfaceInfo> {
    list_interfaces()
        .into_iter()
        .filter(|iface| iface.is_up && !iface.is_loopback && iface.has_ipv4())
        .collect()
}
