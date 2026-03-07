// src/network/packet.rs
use pnet::packet::Packet;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct ArpRequest {
    pub target_ip: Ipv4Addr,
    pub sender_ip: Ipv4Addr,
    pub sender_mac: MacAddr,
}

impl ArpRequest {
    pub fn new(target_ip: Ipv4Addr, sender_ip: Ipv4Addr, sender_mac: MacAddr) -> Self {
        Self {
            target_ip,
            sender_ip,
            sender_mac,
        }
    }

    // Serialize to raw bytes for transmission
    // Memory safety: Fixed-size buffer, no heap allocation in hot path
    pub fn to_bytes(&self) -> [u8; 42] {
        let mut buffer = [0u8; 42]; // 14 eth + 28 arp

        let mut eth_packet =
            MutableEthernetPacket::new(&mut buffer[..14]).expect("14 bytes is valid ethernet size");
        eth_packet.set_destination(MacAddr::broadcast());
        eth_packet.set_source(self.sender_mac);
        eth_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_packet =
            MutableArpPacket::new(&mut buffer[14..]).expect("28 bytes is valid arp size");
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(self.sender_mac);
        arp_packet.set_sender_proto_addr(self.sender_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(self.target_ip);

        buffer
    }
}

#[derive(Debug, Clone)]
pub struct ArpReply {
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

impl ArpReply {
    // Parse from raw bytes
    // Safety: Validates length before parsing, returns Option
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 42 {
            return None;
        }

        let eth = EthernetPacket::new(data)?;
        if eth.get_ethertype() != EtherTypes::Arp {
            return None;
        }

        let arp = ArpPacket::new(eth.payload())?;
        if arp.get_operation() != ArpOperations::Reply {
            return None;
        }

        Some(Self {
            sender_mac: arp.get_sender_hw_addr(),
            sender_ip: arp.get_sender_proto_addr(),
            target_mac: arp.get_target_hw_addr(),
            target_ip: arp.get_target_proto_addr(),
        })
    }
}
