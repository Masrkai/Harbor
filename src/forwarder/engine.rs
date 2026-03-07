// src/forwarder/engine.rs
use super::{ForwardRule, ForwarderCommand};
use crate::host::table::HostTable;
use pnet::datalink::{DataLinkReceiver, DataLinkSender};
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, mpsc};

pub struct PacketForwarder {
    our_mac: MacAddr,
    sender: Arc<Mutex<dyn DataLinkSender>>,
    receiver: Arc<Mutex<dyn DataLinkReceiver>>,
    host_table: Arc<RwLock<HostTable>>,

    active_rules: HashMap<crate::host::table::HostId, ForwardRule>,

    cmd_tx: mpsc::Sender<ForwarderCommand>,
    cmd_rx: Arc<Mutex<mpsc::Receiver<ForwarderCommand>>>,

    original_ip_forward: bool,
}

impl PacketForwarder {
    pub fn new(
        our_mac: MacAddr,
        sender: Arc<Mutex<dyn DataLinkSender>>,
        receiver: Arc<Mutex<dyn DataLinkReceiver>>,
        host_table: Arc<RwLock<HostTable>>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let (cmd_tx, cmd_rx) = mpsc::channel(32);

        let original_ip_forward = Self::read_ip_forward()?;
        Self::write_ip_forward(true)?;

        Ok(Self {
            our_mac,
            sender,
            receiver,
            host_table,
            active_rules: HashMap::new(),
            cmd_tx,
            cmd_rx: Arc::new(Mutex::new(cmd_rx)),
            original_ip_forward,
        })
    }

    pub fn command_sender(&self) -> mpsc::Sender<ForwarderCommand> {
        self.cmd_tx.clone()
    }

    fn read_ip_forward() -> Result<bool, Box<dyn std::error::Error>> {
        let val = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?;
        Ok(val.trim() == "1")
    }

    fn write_ip_forward(enabled: bool) -> Result<(), Box<dyn std::error::Error>> {
        let val = if enabled { "1" } else { "0" };
        std::fs::write("/proc/sys/net/ipv4/ip_forward", val)?;
        Ok(())
    }

    pub async fn run(mut self) {
        println!("[*] PacketForwarder started");
        println!("    IP forwarding enabled in kernel");

        let cmd_rx_arc = Arc::clone(&self.cmd_rx);
        let mut cmd_rx = cmd_rx_arc.lock().await;

        let receiver = Arc::clone(&self.receiver);
        let sender = Arc::clone(&self.sender);
        let rules = Arc::new(Mutex::new(self.active_rules.clone()));
        let our_mac = self.our_mac;

        let packet_task = tokio::spawn(async move {
            let mut receiver = receiver.lock().await;

            loop {
                match receiver.next() {
                    Ok(packet_data) => {
                        if let Some(eth) = EthernetPacket::new(packet_data) {
                            let dst_mac = eth.get_destination();
                            let src_mac = eth.get_source();

                            if dst_mac == our_mac {
                                if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                                    let rules_guard = rules.lock().await;

                                    for rule in rules_guard.values() {
                                        let is_from_victim = src_mac == rule.victim_mac
                                            && ipv4.get_source() == rule.victim_ip;
                                        let is_from_gateway = src_mac == rule.gateway_mac
                                            && ipv4.get_source() == rule.gateway_ip;

                                        if is_from_victim {
                                            let mut sender_guard = sender.lock().await;
                                            Self::relay_packet(
                                                &mut *sender_guard, // Now correctly typed
                                                packet_data,
                                                rule.gateway_mac,
                                                our_mac,
                                            );
                                            break;
                                        } else if is_from_gateway {
                                            let mut sender_guard = sender.lock().await;
                                            Self::relay_packet(
                                                &mut *sender_guard, // Now correctly typed
                                                packet_data,
                                                rule.victim_mac,
                                                our_mac,
                                            );
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[!] Packet receive error: {}", e);
                    }
                }
            }
        });

        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                ForwarderCommand::Enable(rule) => {
                    self.enable_forwarding(rule).await;
                }
                ForwarderCommand::Disable(host_id) => {
                    self.disable_forwarding(host_id).await;
                }
                ForwarderCommand::DisableAll => {
                    self.disable_all().await;
                    packet_task.abort();
                    break;
                }
                ForwarderCommand::UpdateRateLimit(host_id, rate) => {
                    self.update_rate_limit(host_id, rate).await;
                }
            }
        }

        let _ = Self::write_ip_forward(self.original_ip_forward);
        println!("[*] PacketForwarder shut down");
    }

    fn relay_packet(
        sender: &mut dyn DataLinkSender, // Changed: direct type, not &mut dyn
        original: &[u8],
        new_dst_mac: MacAddr,
        our_mac: MacAddr,
    ) {
        let mut buffer = original.to_vec();

        if let Some(mut eth) = MutableEthernetPacket::new(&mut buffer) {
            eth.set_source(our_mac);
            eth.set_destination(new_dst_mac);

            match sender.send_to(&buffer, None) {
                Some(Ok(())) => {}
                Some(Err(e)) => {
                    eprintln!("[!] Forward error: {}", e);
                }
                None => {
                    eprintln!("[!] Forward channel closed");
                }
            }
        }
    }

    async fn enable_forwarding(&mut self, rule: ForwardRule) {
        let host_id = rule.host_id;
        println!("[*] Enabling packet forwarding for host {}:", host_id);
        println!("    {} <-> {}", rule.victim_ip, rule.gateway_ip);

        self.active_rules.insert(host_id, rule);
        println!("[+] Forwarding enabled for host {}", host_id);
    }

    async fn disable_forwarding(&mut self, host_id: crate::host::table::HostId) {
        if self.active_rules.remove(&host_id).is_some() {
            println!("[+] Forwarding disabled for host {}", host_id);
        } else {
            println!("[!] Host {} not being forwarded", host_id);
        }
    }

    async fn disable_all(&mut self) {
        self.active_rules.clear();
        println!("[+] All forwarding disabled");
    }

    async fn update_rate_limit(&mut self, host_id: crate::host::table::HostId, rate: Option<u64>) {
        if let Some(rule) = self.active_rules.get(&host_id) {
            if let Some(kbps) = rate {
                println!("[*] Rate limit for host {}: {} kbps", host_id, kbps);
            } else {
                println!("[*] Rate limit removed for host {}", host_id);
            }
        }
    }
}

impl Drop for PacketForwarder {
    fn drop(&mut self) {
        let _ = Self::write_ip_forward(self.original_ip_forward);
    }
}
