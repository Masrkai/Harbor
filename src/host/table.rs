// src/host/table.rs
use crate::network::scanner::DiscoveredHost;
use pnet::util::MacAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

pub type HostId = usize;

pub struct HostTable {
    hosts: HashMap<HostId, HostEntry>,
    ip_to_id: HashMap<Ipv4Addr, HostId>,
    mac_to_id: HashMap<MacAddr, HostId>,
    next_id: HostId,
}

pub struct HostEntry {
    pub id: HostId,
    pub host: DiscoveredHost,
    pub state: HostState,
    pub added_at: Instant,
    pub scan_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostState {
    Discovered,
    Poisoning,
    Limited,
    Blocked,
    Error,
}

impl HostTable {
    pub fn new() -> Self {
        Self {
            hosts: HashMap::new(),
            ip_to_id: HashMap::new(),
            mac_to_id: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn insert(&mut self, host: DiscoveredHost) -> HostId {
        if let Some(&existing_id) = self.ip_to_id.get(&host.ip) {
            if let Some(entry) = self.hosts.get_mut(&existing_id) {
                entry.host.last_seen = host.last_seen;
                if host.vendor.is_some() {
                    entry.host.vendor = host.vendor;
                }
                entry.scan_count += 1;
            }
            return existing_id;
        }

        if let Some(&existing_id) = self.mac_to_id.get(&host.mac) {
            if let Some(entry) = self.hosts.get_mut(&existing_id) {
                self.ip_to_id.remove(&entry.host.ip);
                self.ip_to_id.insert(host.ip, existing_id);
                entry.host.ip = host.ip;
                entry.host.last_seen = host.last_seen;
                if host.vendor.is_some() {
                    entry.host.vendor = host.vendor;
                }
                entry.scan_count += 1;
            }
            return existing_id;
        }

        let id = self.next_id;
        self.next_id += 1;

        let entry = HostEntry {
            id,
            host,
            state: HostState::Discovered,
            added_at: Instant::now(),
            scan_count: 1,
        };

        self.ip_to_id.insert(entry.host.ip, id);
        self.mac_to_id.insert(entry.host.mac, id);
        self.hosts.insert(id, entry);

        id
    }

    /// Reassigns all IDs in ascending IP order.
    ///
    /// Call this once after a bulk insert (e.g. after a full scan) so that
    /// ID 1 always means "lowest IP on the network", ID 2 the next, and so on.
    /// Any code that stored an old HostId (e.g. the spoofer) must refresh its
    /// references afterwards — this is intentionally a post-scan, pre-display
    /// operation.
    pub fn reindex_by_ip(&mut self) {
        // Pull every entry out, sorted by IP
        let mut entries: Vec<HostEntry> = self.hosts.drain().map(|(_, e)| e).collect();
        entries.sort_by_key(|e| e.host.ip.octets());

        // Rebuild all three maps from scratch with sequential IDs
        self.ip_to_id.clear();
        self.mac_to_id.clear();
        self.next_id = 1;

        for entry in entries {
            let new_id = self.next_id;
            self.next_id += 1;

            let reindexed = HostEntry {
                id: new_id,
                ..entry
            };

            self.ip_to_id.insert(reindexed.host.ip, new_id);
            self.mac_to_id.insert(reindexed.host.mac, new_id);
            self.hosts.insert(new_id, reindexed);
        }
    }

    pub fn get_by_id(&self, id: HostId) -> Option<&HostEntry> {
        self.hosts.get(&id)
    }

    pub fn get_by_id_mut(&mut self, id: HostId) -> Option<&mut HostEntry> {
        self.hosts.get_mut(&id)
    }

    pub fn get_by_ip(&self, ip: Ipv4Addr) -> Option<&HostEntry> {
        self.ip_to_id.get(&ip).and_then(|id| self.hosts.get(id))
    }

    pub fn get_by_mac(&self, mac: MacAddr) -> Option<&HostEntry> {
        self.mac_to_id.get(&mac).and_then(|id| self.hosts.get(id))
    }

    pub fn update_state(&mut self, id: HostId, state: HostState) -> bool {
        if let Some(entry) = self.hosts.get_mut(&id) {
            entry.state = state;
            true
        } else {
            false
        }
    }

    pub fn remove(&mut self, id: HostId) -> Option<HostEntry> {
        let entry = self.hosts.remove(&id)?;
        self.ip_to_id.remove(&entry.host.ip);
        self.mac_to_id.remove(&entry.host.mac);
        Some(entry)
    }

    pub fn clear(&mut self) {
        self.hosts.clear();
        self.ip_to_id.clear();
        self.mac_to_id.clear();
        self.next_id = 1;
    }

    pub fn iter(&self) -> impl Iterator<Item = &HostEntry> {
        self.hosts.values()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut HostEntry> {
        self.hosts.values_mut()
    }

    pub fn len(&self) -> usize {
        self.hosts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    pub fn display(&self) {
        println!(
            "\n{:<5} {:<16} {:<18} {:<12} {:<6} {:<24} {}",
            "ID", "IP Address", "MAC Address", "Status", "Seen", "Vendor", "Hostname"
        );
        println!("{}", "-".repeat(100));

        // IDs are already in IP order after reindex_by_ip(), so sort by ID
        // rather than re-sorting by IP — they are equivalent and cheaper.
        let mut entries: Vec<&HostEntry> = self.hosts.values().collect();
        entries.sort_by_key(|e| e.id);

        for entry in &entries {
            let age = format_duration(entry.host.last_seen.elapsed());
            let vendor = entry.host.vendor.as_deref().unwrap_or("Unknown");
            let hostname = entry.host.hostname.as_deref().unwrap_or("Unknown");

            println!(
                "{:<5} {:<16} {:<18} {:<12} {:<6} {:<24} {}",
                entry.id,
                entry.host.ip,
                entry.host.mac,
                format!("{:?}", entry.state),
                age,
                if vendor.len() > 22 {
                    format!("{:.21}…", vendor)
                } else {
                    vendor.to_string()
                },
                hostname,
            );
        }

        println!("{}\n", "-".repeat(100));
        println!("Total hosts: {}", self.len());
    }

    pub fn get_stale_hosts(&self, max_age: Duration) -> Vec<HostId> {
        self.hosts
            .values()
            .filter(|e| e.host.last_seen.elapsed() > max_age)
            .map(|e| e.id)
            .collect()
    }
}

fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        format!("{}h", secs / 3600)
    }
}

impl Default for HostTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_table_insertion() {
        let mut table = HostTable::new();

        let host1 = DiscoveredHost {
            ip: Ipv4Addr::new(192, 168, 1, 10),
            mac: MacAddr::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
            hostname: None,
            vendor: None,
            last_seen: Instant::now(),
        };

        let id1 = table.insert(host1.clone());
        assert_eq!(table.len(), 1);
        assert_eq!(table.get_by_id(id1).unwrap().host.ip, host1.ip);

        let host1_dup = DiscoveredHost {
            ip: Ipv4Addr::new(192, 168, 1, 10),
            mac: MacAddr::new(0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF),
            hostname: None,
            vendor: None,
            last_seen: Instant::now(),
        };
        let id1_again = table.insert(host1_dup);
        assert_eq!(id1, id1_again);
        assert_eq!(table.len(), 1);
        assert_eq!(table.get_by_id(id1).unwrap().scan_count, 2);
    }

    #[test]
    fn test_reindex_by_ip() {
        let mut table = HostTable::new();

        // Insert in reverse IP order to prove reindex corrects it
        for last_octet in [30u8, 10, 20] {
            table.insert(DiscoveredHost {
                ip: Ipv4Addr::new(192, 168, 1, last_octet),
                mac: MacAddr::new(0, 0, 0, 0, 0, last_octet),
                hostname: None,
                vendor: None,
                last_seen: Instant::now(),
            });
        }

        table.reindex_by_ip();

        // After reindex: .10 → id 1, .20 → id 2, .30 → id 3
        assert_eq!(
            table.get_by_ip(Ipv4Addr::new(192, 168, 1, 10)).unwrap().id,
            1
        );
        assert_eq!(
            table.get_by_ip(Ipv4Addr::new(192, 168, 1, 20)).unwrap().id,
            2
        );
        assert_eq!(
            table.get_by_ip(Ipv4Addr::new(192, 168, 1, 30)).unwrap().id,
            3
        );
    }
}
