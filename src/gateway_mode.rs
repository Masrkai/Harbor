// src/gateway_mode.rs
//
// ─────────────────────────────────────────────────────────────────────────────
// Gateway mode — bandwidth shaping for clients on a network you host
// ─────────────────────────────────────────────────────────────────────────────
//
// This module is the "I AM the router" path.  No ARP poisoning, no userspace
// packet forwarder, no MITM position.  The kernel already routes traffic
// through this machine (because we are the actual gateway / hotspot AP), so
// all we need is tc HTB shaping on the interface that serves the clients.
//
// Flow (interactive):
//   1. Discover clients via ARP scan + passive sniff on the hotspot interface.
//   2. Present the TargetSelector so the operator picks who to shape.
//   3. Initialise TcManager and apply the requested rate.
//   4. Block until Ctrl-C or 'q', then tear down the tc qdiscs cleanly.
//
// Flow (bypass — --target given):
//   1. Resolve only the specified IPs via targeted ARP.
//   2. Skip TargetSelector entirely — all resolved hosts are shaped.
//   3. Same tc + shutdown flow as above.
//
// Stdin discipline:
//   The 'q'-reader shutdown thread is started ONLY after all interactive
//   prompts (interface selector, target selector, bandwidth prompt) are
//   complete.  Starting it earlier would cause it to race with those prompts
//   and consume their input, making the tool appear to immediately exit.
//
// What is deliberately NOT done here:
//   • No ip_forward manipulation — the kernel should already have it enabled.
//   • No KernelState / rp_filter changes — irrelevant without MITM routing.
//   • No SpooferEngine, no PacketForwarder.
//   • No nftables rpfilter gate — we don't touch the FORWARD hook.
//
// ─────────────────────────────────────────────────────────────────────────────

use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::cli::color::Color;
use crate::cli::selector::InterfaceSelector;
use crate::cli::target_selector::{SelectionResult, TargetSelector};
use crate::host::table::HostTable;
use crate::network::calculator::get_cidr;
use crate::network::scanner::ArpScanner;
use crate::network::IpRange;
use crate::utils::logger::Logger;
use crate::utils::oui::lookup_vendor;
use crate::utils::tc::TcManager;

const COLOR_OK: Color = Color::from_hex(b"#50C878");
const COLOR_WARN: Color = Color::from_hex(b"#FFB347");
const COLOR_KEYWORD: Color = Color::from_hex(b"#C792EA");

// ─────────────────────────────────────────────────────────────────────────────
// Public config
// ─────────────────────────────────────────────────────────────────────────────

pub struct GatewayModeConfig {
    /// Interface that clients connect to (the hotspot / LAN interface).
    pub interface: Option<String>,
    /// Pre-selected bandwidth cap in kbps.
    /// When Some, the TargetSelector bandwidth prompt is skipped.
    pub bandwidth_kbps: Option<u64>,
    /// Optional list of pre-specified target IPs (from --target flags).
    /// When non-empty the ARP scan and TargetSelector are both skipped.
    pub targets: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────

pub async fn run(cfg: GatewayModeConfig) -> Result<(), Box<dyn std::error::Error>> {
    let mut logger = Logger::new();

    logger.info_fmt(format_args!(
        "{}",
        COLOR_OK.paint("Gateway mode — shaping clients on a network you host")
    ));
    logger.info_fmt(format_args!(
        "No ARP poisoning. Kernel routing handles forwarding."
    ));

    // ── Interface selection ──────────────────────────────────────────────────
    let interface_name = match cfg.interface {
        Some(ref name) => {
            logger.info_fmt(format_args!(
                "Interface (from args): {}",
                COLOR_KEYWORD.paint(name)
            ));
            name.clone()
        }
        None => match InterfaceSelector::select(true) {
            Some(name) => name,
            None => {
                logger.error_fmt(format_args!("No interface selected. Exiting."));
                std::process::exit(1);
            }
        },
    };

    // ── Scanner ──────────────────────────────────────────────────────────────
    let scanner = ArpScanner::new(&interface_name).await?;
    let our_ip = scanner.local_ip();
    logger.info_fmt(format_args!(
        "Local MAC: {}  Local IP: {}",
        COLOR_KEYWORD.paint(&scanner.local_mac().to_string()),
        COLOR_KEYWORD.paint(&our_ip.to_string()),
    ));

    // ── Host discovery ───────────────────────────────────────────────────────
    // Two paths: bypass (--target given) or full scan.
    let (discovered, bypass_mode) = if !cfg.targets.is_empty() {
        let ips = expand_targets(&cfg.targets, &mut logger);
        logger.info_fmt(format_args!(
            "Bypass mode — resolving {} IP(s)…",
            ips.len()
        ));
        (scanner.resolve_hosts(&ips).await?, true)
    } else {
        let cidr = get_cidr(&interface_name)
            .ok_or("could not determine CIDR for interface")?;
        let range = IpRange::from_cidr(&cidr)?;
        logger.info_fmt(format_args!(
            "Scanning {} → {}",
            COLOR_KEYWORD.paint(&range.start.to_string()),
            COLOR_KEYWORD.paint(&range.end.to_string()),
        ));

        logger.info_fmt(format_args!("Passive ARP sniff (5 s)…"));
        let passive = scanner
            .passive_sniff(std::time::Duration::from_secs(5))
            .await?;

        let mut d = scanner.scan(range).await?;
        d.extend(passive);

        logger.info_fmt(format_args!("Post-scan passive sniff (3 s)…"));
        d.extend(
            scanner
                .passive_sniff(std::time::Duration::from_secs(3))
                .await?,
        );
        (d, false)
    };

    // ── Vendor resolution ────────────────────────────────────────────────────
    let mut discovered = discovered;
    logger.info_fmt(format_args!(
        "Resolving vendors for {} host(s)…",
        discovered.len()
    ));
    for host in &mut discovered {
        host.vendor = Some(lookup_vendor(host.mac));
    }

    // ── Build host table (skip ourselves) ───────────────────────────────────
    drop(scanner); // release datalink channel before tc opens its own resources

    let host_table = Arc::new(RwLock::new(HostTable::new()));
    {
        let mut t = host_table.write().await;
        for host in discovered {
            if host.ip == our_ip {
                continue;
            }
            t.insert(host);
        }
        t.reindex_by_ip();
    }
    {
        host_table.read().await.display();
    }

    if host_table.read().await.is_empty() {
        logger.error_fmt(format_args!("No clients found on {}.", interface_name));
        return Ok(());
    }

    // ── Target + bandwidth selection ─────────────────────────────────────────
    // IMPORTANT: All stdin interaction must complete here, BEFORE the
    // 'q'-reader thread is spawned below.  If the thread starts earlier it
    // races with these prompts and consumes their input, causing an immediate
    // spurious exit.
    let selection: SelectionResult = if bypass_mode {
        // Bypass: shape every resolved host, no interactive prompting needed
        // for target selection.  Bandwidth still needs resolving.
        let ids: Vec<_> = host_table.read().await.iter().map(|e| e.id).collect();
        if ids.is_empty() {
            logger.error_fmt(format_args!("No targets after resolution."));
            return Ok(());
        }
        logger.info_fmt(format_args!("Bypass: {} target(s) selected.", ids.len()));

        let kbps = match cfg.bandwidth_kbps {
            Some(k) => {
                logger.info_fmt(format_args!("Bandwidth (from args): {} kbps", k));
                Some(k)
            }
            None => prompt_bandwidth_once(),
        };

        SelectionResult {
            host_ids: ids,
            bandwidth_kbps: kbps,
        }
    } else {
        // Interactive: full TargetSelector UI.
        // Pass our_ip as the "gateway_ip" so TargetSelector excludes us.
        // If --bandwidth was provided we override the prompt's answer with it.
        let t = host_table.read().await;
        match TargetSelector::select(&t, our_ip) {
            Some(mut s) => {
                if let Some(k) = cfg.bandwidth_kbps {
                    s.bandwidth_kbps = Some(k);
                    logger.info_fmt(format_args!("Bandwidth (from args): {} kbps", k));
                }
                s
            }
            None => {
                logger.info_fmt(format_args!("No targets selected. Exiting."));
                return Ok(());
            }
        }
    };

    // ── Resolve final bandwidth ──────────────────────────────────────────────
    let kbps = match selection.bandwidth_kbps {
        Some(0) => {
            logger.error_fmt(format_args!(
                "Bandwidth 0 is not valid in gateway mode \
                 (blocking is a MITM-mode feature). \
                 Use a positive kbps value or omit --bandwidth for no cap."
            ));
            return Ok(());
        }
        Some(k) => k,
        None => 0, // no cap: tc is initialised but limit_host is not called
    };

    // ── tc initialisation ────────────────────────────────────────────────────
    let mut tc = TcManager::new(&interface_name);

    match tc.init() {
        Err(e) => {
            logger.error_fmt(format_args!("tc init failed: {e}"));
            std::process::exit(1);
        }
        Ok(()) => {
            logger.info_fmt(format_args!(
                "tc: HTB + IFB shaping initialised on {}.",
                interface_name
            ));
        }
    }

    if kbps > 0 {
        let table = host_table.read().await;
        for &id in &selection.host_ids {
            if let Some(entry) = table.get_by_id(id) {
                match tc.limit_host(id, entry.host.ip, kbps) {
                    Ok(()) => logger.info_fmt(format_args!(
                        "tc: [{}] {} → {} kbps",
                        id,
                        COLOR_WARN.paint(&entry.host.ip.to_string()),
                        kbps,
                    )),
                    Err(e) => logger.error_fmt(format_args!(
                        "tc limit_host [{}] {}: {e}",
                        id,
                        entry.host.ip,
                    )),
                }
            }
        }
    } else {
        logger.info_fmt(format_args!(
            "No bandwidth cap — {} client(s) forwarded at line rate.",
            selection.host_ids.len()
        ));
    }

    // ── Status ───────────────────────────────────────────────────────────────
    println!();
    let status_msg = if kbps > 0 {
        format!(
            "Shaping {} client(s) at {} kbps each. \
             Press Ctrl-C or 'q' + Enter to stop.",
            selection.host_ids.len(),
            kbps,
        )
    } else {
        format!(
            "Monitoring {} client(s) (no bandwidth cap). \
             Press Ctrl-C or 'q' + Enter to stop.",
            selection.host_ids.len(),
        )
    };
    logger.info_fmt(format_args!("{}", COLOR_OK.paint(&status_msg)));

    // ── Shutdown listener ────────────────────────────────────────────────────
    // Spawned HERE — after ALL stdin interaction is complete.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_tx = Arc::new(std::sync::Mutex::new(Some(shutdown_tx)));

    {
        let tx = Arc::clone(&shutdown_tx);
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(tokio::signal::ctrl_c()).ok();
            if let Some(sender) = tx.lock().unwrap().take() {
                let _ = sender.send(());
            }
        });
    }

    {
        let tx = Arc::clone(&shutdown_tx);
        std::thread::spawn(move || {
            use std::io::BufRead;
            let stdin = std::io::stdin();
            for line in stdin.lock().lines() {
                match line {
                    Ok(l) if l.trim().eq_ignore_ascii_case("q") => {
                        println!();
                        if let Some(sender) = tx.lock().unwrap().take() {
                            let _ = sender.send(());
                        }
                        break;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
    }

    let _ = shutdown_rx.await;

    // ── Teardown ──────────────────────────────────────────────────────────────
    println!();
    logger.info_fmt(format_args!("Shutting down gateway mode…"));
    tc.cleanup();
    logger.info_fmt(format_args!("tc qdiscs removed. Network restored."));
    logger.info_fmt(format_args!("Done."));

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn expand_targets(raw_targets: &[String], logger: &mut Logger) -> Vec<Ipv4Addr> {
    let mut ips: Vec<Ipv4Addr> = Vec::new();
    for raw in raw_targets {
        match expand_one(raw) {
            Ok(v) => {
                logger.info_fmt(format_args!(
                    "Target '{}' → {} IP(s)",
                    COLOR_KEYWORD.paint(raw),
                    v.len()
                ));
                ips.extend(v);
            }
            Err(e) => {
                logger.error_fmt(format_args!("{e}"));
                std::process::exit(1);
            }
        }
    }
    ips.sort_unstable();
    ips.dedup();
    ips
}

fn expand_one(s: &str) -> Result<Vec<Ipv4Addr>, String> {
    if s.contains('/') {
        let range = IpRange::from_cidr(s)
            .map_err(|e| format!("invalid CIDR '{s}': {e}"))?;
        return Ok(range.iter().collect());
    }
    if let Some((prefix, range_part)) = s.rsplit_once('.') {
        if let Some((lo_s, hi_s)) = range_part.split_once('-') {
            let octs = format!("{prefix}.0")
                .parse::<Ipv4Addr>()
                .map_err(|_| format!("invalid prefix '{prefix}'"))?
                .octets();
            let lo: u8 = lo_s.parse().map_err(|_| format!("bad range start in '{s}'"))?;
            let hi: u8 = hi_s.parse().map_err(|_| format!("bad range end in '{s}'"))?;
            if lo > hi {
                return Err(format!("range start > end in '{s}'"));
            }
            return Ok((lo..=hi)
                .map(|n| Ipv4Addr::new(octs[0], octs[1], octs[2], n))
                .collect());
        }
    }
    s.parse::<Ipv4Addr>()
        .map(|ip| vec![ip])
        .map_err(|_| format!("cannot parse '{s}' as IP, CIDR, or range"))
}

fn prompt_bandwidth_once() -> Option<u64> {
    use std::io::Write as _;
    print!("Bandwidth cap in kbps per client (leave blank = unlimited): ");
    std::io::stdout().flush().unwrap();
    let mut buf = String::new();
    if std::io::stdin().read_line(&mut buf).is_ok() {
        return TargetSelector::parse_bandwidth(buf.trim());
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_with_all_fields() {
        let cfg = GatewayModeConfig {
            interface: Some("eth0".to_string()),
            bandwidth_kbps: Some(1024),
            targets: vec!["10.0.0.1".to_string()],
        };
        assert_eq!(cfg.interface.as_deref(), Some("eth0"));
        assert_eq!(cfg.bandwidth_kbps, Some(1024));
        assert_eq!(cfg.targets.len(), 1);
    }

    #[test]
    fn test_config_empty_targets_means_full_scan() {
        let cfg = GatewayModeConfig {
            interface: None,
            bandwidth_kbps: None,
            targets: vec![],
        };
        assert!(cfg.targets.is_empty());
    }

    #[test]
    fn test_expand_one_single_ip() {
        assert_eq!(
            expand_one("192.168.1.5").unwrap(),
            vec!["192.168.1.5".parse::<Ipv4Addr>().unwrap()]
        );
    }

    #[test]
    fn test_expand_one_cidr_slash_30() {
        let ips = expand_one("10.0.0.0/30").unwrap();
        assert_eq!(ips.len(), 2); // .1 and .2
    }

    #[test]
    fn test_expand_one_octet_range() {
        let ips = expand_one("10.0.0.1-3").unwrap();
        assert_eq!(ips.len(), 3);
        assert_eq!(ips[0], "10.0.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(ips[2], "10.0.0.3".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn test_expand_one_reversed_range_is_error() {
        assert!(expand_one("10.0.0.5-3").is_err());
    }

    #[test]
    fn test_expand_one_garbage_is_error() {
        assert!(expand_one("not_an_ip").is_err());
    }
}