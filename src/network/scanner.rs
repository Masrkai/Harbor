// src/network/scanner.rs
use super::{
    IpRange, NetworkError,
    packet::{ArpReply, ArpRequest},
};
use pnet::datalink::{self, Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, watch};
use tokio::time::interval;

// ─────────────────────────────────────────────────────────────────────────────
// Scan configuration
// ─────────────────────────────────────────────────────────────────────────────

/// All timing knobs in one place, chosen per interface type.
///
/// Wireless quirks we account for:
///   • 802.11 power-save: a device may sleep through the first ARP request
///     and only wake on the beacon interval (100 ms typical) → multi-pass
///   • Higher base RTT + retransmission jitter → longer idle cutoff
///   • Channel congestion → conservative send pacing to avoid flooding the AP
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Delay between individual ARP sends within one pass (ms).
    pub send_interval_ms: u64,

    /// Number of full range sweeps.
    /// Extra passes catch devices that were asleep or dropped the first frame.
    pub passes: u32,

    /// Pause between consecutive passes (ms).
    /// Gives sleeping wireless clients time to wake and process earlier requests.
    pub inter_pass_delay_ms: u64,

    /// Minimum collection window *after* the last send finishes (ms).
    /// We never exit before this, even if the network looks quiet.
    pub post_send_min_ms: u64,

    /// Early-exit trigger: if no *new* host has been seen for this long (ms),
    /// consider the scan done (subject to post_send_min_ms).
    pub idle_cutoff_ms: u64,

    /// Hard ceiling — scan never runs longer than this regardless of activity.
    pub hard_timeout_secs: u64,
}

impl ScanConfig {
    /// Wired Ethernet: low latency, reliable delivery, no power-save.
    pub fn ethernet() -> Self {
        Self {
            send_interval_ms: 2,
            passes: 2,
            inter_pass_delay_ms: 400,
            post_send_min_ms: 800,
            idle_cutoff_ms: 400,
            hard_timeout_secs: 15,
        }
    }

    /// 802.11 wireless: higher latency, packet loss, power-save clients.
    pub fn wireless() -> Self {
        Self {
            send_interval_ms: 8,        // gentler pacing — AP queue can back up fast
            passes: 1,                  // extra sweeps for sleeping devices
            inter_pass_delay_ms: 1_500, // ≥ 1 beacon interval for power-save wakeup
            post_send_min_ms: 4_000,    // far clients can have 2–3 s RTT
            idle_cutoff_ms: 2_000,      // wireless is noisy; wait longer for stragglers
            hard_timeout_secs: 60,
        }
    }

    pub fn for_interface(name: &str) -> Self {
        if is_wireless_iface(name) {
            Self::wireless()
        } else {
            Self::ethernet()
        }
    }
}

fn is_wireless_iface(name: &str) -> bool {
    // Covers: wlan0, wlp3s0, wlo1, wl* (generic)
    name.starts_with("wlan")
        || name.starts_with("wlp")
        || name.starts_with("wlo")
        || name.starts_with("wl")
}

// ─────────────────────────────────────────────────────────────────────────────
// Scanner
// ─────────────────────────────────────────────────────────────────────────────

pub struct ArpScanner {
    interface: NetworkInterface,
    local_mac: MacAddr,
    local_ip: Ipv4Addr,
    sender: Arc<Mutex<Box<dyn DataLinkSender>>>,
    receiver: Arc<Mutex<Box<dyn DataLinkReceiver>>>,
    pub config: ScanConfig,
}

impl ArpScanner {
    pub async fn new(interface_name: &str) -> Result<Self, NetworkError> {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| NetworkError::InterfaceNotFound(interface_name.to_string()))?;

        let local_mac = interface.mac.ok_or_else(|| {
            NetworkError::InterfaceNotFound(format!("{} has no MAC", interface_name))
        })?;

        let local_ip = interface
            .ips
            .iter()
            .find_map(|ip| match ip.ip() {
                std::net::IpAddr::V4(v4) => Some(v4),
                _ => None,
            })
            .ok_or_else(|| {
                NetworkError::InterfaceNotFound(format!("{} has no IPv4", interface_name))
            })?;

        let config = ScanConfig::for_interface(interface_name);

        let (sender, receiver) = match datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                return Err(NetworkError::PermissionDenied(
                    "Non-ethernet interface".to_string(),
                ));
            }
            Err(e) => return Err(NetworkError::PermissionDenied(e.to_string())),
        };

        Ok(Self {
            interface,
            local_mac,
            local_ip,
            sender: Arc::new(Mutex::new(sender)),
            receiver: Arc::new(Mutex::new(receiver)),
            config,
        })
    }

    pub async fn scan(&self, range: IpRange) -> Result<Vec<DiscoveredHost>, NetworkError> {
        self.scan_with_config(range, self.config.clone()).await
    }

    pub async fn scan_with_config(
        &self,
        range: IpRange,
        config: ScanConfig,
    ) -> Result<Vec<DiscoveredHost>, NetworkError> {
        let is_wireless = is_wireless_iface(self.interface_name());

        println!(
            "[*] Scan config: {} | {} pass(es) | send interval {}ms | idle cutoff {}ms",
            if is_wireless { "wireless" } else { "ethernet" },
            config.passes,
            config.send_interval_ms,
            config.idle_cutoff_ms,
        );

        let results: Arc<Mutex<HashMap<Ipv4Addr, DiscoveredHost>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // watch channel: receiver publishes the Instant it last saw a *new* host.
        // The main task reads this to decide when to stop waiting.
        let (new_host_tx, new_host_rx) = watch::channel(Instant::now());

        let local_ip = self.local_ip;
        let local_mac = self.local_mac;

        // ── Receiver — runs entirely on a blocking OS thread ─────────────────
        //
        // pnet's DataLinkReceiver::next() is synchronous/blocking and offers no
        // async or timeout variant. Calling it inside tokio::spawn() blocks the
        // worker thread for the full duration of the scan, preventing other tasks
        // from running on that thread. Moving it to spawn_blocking gives it a
        // dedicated thread from the blocking pool and keeps the async scheduler
        // healthy.
        let receiver_arc = Arc::clone(&self.receiver);
        let results_for_recv = Arc::clone(&results);
        let hard_timeout = Duration::from_secs(config.hard_timeout_secs);

        let receiver_handle = tokio::task::spawn_blocking(move || {
            let deadline = Instant::now() + hard_timeout;
            // blocking_lock is available on tokio::sync::Mutex from a sync context
            let mut guard = receiver_arc.blocking_lock();

            loop {
                if Instant::now() >= deadline {
                    break;
                }

                match guard.next() {
                    Ok(data) => {
                        if let Some(reply) = ArpReply::from_bytes(data) {
                            if range.contains(reply.sender_ip) && reply.target_ip == local_ip {
                                let host = DiscoveredHost {
                                    ip: reply.sender_ip,
                                    mac: reply.sender_mac,
                                    hostname: None,
                                    vendor: None,
                                    last_seen: Instant::now(),
                                };

                                let mut res = results_for_recv.blocking_lock();
                                let is_new = !res.contains_key(&reply.sender_ip);
                                res.insert(reply.sender_ip, host);

                                // Notify the main task only when a genuinely new
                                // host appears (not a duplicate reply).
                                if is_new {
                                    let _ = new_host_tx.send(Instant::now());
                                    println!(
                                        "[+] Discovered {} (total: {})",
                                        reply.sender_ip,
                                        res.len()
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[!] Receive error: {e}");
                        break;
                    }
                }
            }
        });

        // ── Sender — multi-pass ──────────────────────────────────────────────
        //
        // Each pass sweeps the full range. The inter-pass delay is the key
        // knob for wireless: it lets 802.11 power-save clients (which may have
        // slept through pass 1) wake up before pass 2 arrives.
        let sender_arc = Arc::clone(&self.sender);
        let passes = config.passes;
        let send_interval = Duration::from_millis(config.send_interval_ms);
        let inter_pass_delay = Duration::from_millis(config.inter_pass_delay_ms);

        let sender_handle = tokio::spawn(async move {
            for pass in 0..passes {
                if pass > 0 {
                    println!(
                        "[*] ARP scan pass {}/{} (waiting {}ms before retry)…",
                        pass + 1,
                        passes,
                        inter_pass_delay.as_millis()
                    );
                    tokio::time::sleep(inter_pass_delay).await;
                } else {
                    println!("[*] ARP scan pass 1/{passes}…");
                }

                // Approach one, BAD
                // let mut ticker = interval(Duration::from_millis(config.send_interval_ms));
                // let mut sender = sender_arc.lock().await;

                // for target_ip in range.iter().filter(|&ip| ip != local_ip) {
                //     ticker.tick().await;
                //     let bytes = ArpRequest::new(target_ip, local_ip, local_mac).to_bytes();
                //     sender.send_to(&bytes, None);
                // }

                // Approach two, GOOD
                // Pre-build all packets — zero allocation in the hot path
                let packets: Vec<[u8; 42]> = range
                    .iter()
                    .filter(|&ip| ip != local_ip)
                    .map(|ip| ArpRequest::new(ip, local_ip, local_mac).to_bytes())
                    .collect();

                println!("[*] ARP scan pass {}/{passes}…", pass + 1);

                let sender_arc_clone = Arc::clone(&sender_arc);
                tokio::task::spawn_blocking(move || {
                    let mut sender = sender_arc_clone.blocking_lock();
                    for bytes in &packets {
                        sender.send_to(bytes, None);
                    }
                })
                .await
                .unwrap();
            }
            println!("[*] All {passes} ARP pass(es) complete");
        });

        // ── Wait for sender to finish ────────────────────────────────────────
        let _ = sender_handle.await;
        let send_finished_at = Instant::now();

        // ── Adaptive collection window ───────────────────────────────────────
        //
        // We poll every 100 ms and apply two independent exit conditions:
        //
        //   1. Minimum window (post_send_min_ms) — always honoured so that
        //      far-away wireless clients that replied during the last pass still
        //      have time for their packets to arrive.
        //
        //   2. Idle cutoff (idle_cutoff_ms) — exit early once *both* conditions
        //      are met: the minimum window has passed AND no new host has been
        //      seen for idle_cutoff_ms. This avoids sitting out the full minimum
        //      on a quiet, fast, wired network.
        //
        //   3. Hard timeout — absolute ceiling.
        let post_send_min = Duration::from_millis(config.post_send_min_ms);
        let idle_cutoff = Duration::from_millis(config.idle_cutoff_ms);
        let hard_deadline = send_finished_at + Duration::from_secs(config.hard_timeout_secs);

        println!(
            "[*] Collecting replies (min {}ms, idle cutoff {}ms)…",
            config.post_send_min_ms, config.idle_cutoff_ms
        );

        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;

            let now = Instant::now();

            if now >= hard_deadline {
                println!("[!] Hard timeout reached");
                break;
            }

            let elapsed_since_send = now.duration_since(send_finished_at);
            let last_new_host = *new_host_rx.borrow();
            let idle_for = now.duration_since(last_new_host);

            if elapsed_since_send >= post_send_min && idle_for >= idle_cutoff {
                println!(
                    "[*] Network quiet for {}ms — scan complete",
                    idle_for.as_millis()
                );
                break;
            }
        }

        receiver_handle.abort();

        let final_results = {
            let res = results.lock().await;
            res.values().cloned().collect::<Vec<_>>()
        };

        println!(
            "[+] Scan finished — {} host(s) discovered",
            final_results.len()
        );

        Ok(final_results)
    }

    // ── Accessors ────────────────────────────────────────────────────────────

    pub fn interface_name(&self) -> &str {
        &self.interface.name
    }

    pub fn local_mac(&self) -> MacAddr {
        self.local_mac
    }

    pub fn local_ip(&self) -> Ipv4Addr {
        self.local_ip
    }

    pub fn get_sender(&self) -> Arc<Mutex<Box<dyn DataLinkSender>>> {
        Arc::clone(&self.sender)
    }

    pub fn get_receiver(&self) -> Arc<Mutex<Box<dyn DataLinkReceiver>>> {
        Arc::clone(&self.receiver)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Discovered host
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DiscoveredHost {
    pub ip: Ipv4Addr,
    pub mac: MacAddr,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub last_seen: std::time::Instant,
}

impl DiscoveredHost {
    pub async fn resolve_hostname(&mut self) {
        // Reverse DNS lookup — placeholder for future implementation.
        self.hostname = None;
    }
}
