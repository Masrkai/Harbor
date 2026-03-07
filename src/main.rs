// src/main.rs
mod cli;
mod host;
mod network;
mod utils;

use tokio::sync::RwLock;

use network::calculator::*;
use network::scanner::ArpScanner;

use cli::color::*;
use cli::selector::InterfaceSelector;

use host::table::HostTable;
use std::sync::Arc;

use utils::check_root::*;
use utils::logger::*;
use utils::oui::lookup_vendor;

const COLOR_KEYWORD: Color = Color::from_hex(b"#C792EA");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut logger = Logger::new();
    check_root();

    let interface_name = match InterfaceSelector::select(true) {
        Some(name) => name,
        None => {
            logger.error_fmt(format_args!("No interface selected. Exiting."));
            std::process::exit(1);
        }
    };

    logger.info_fmt(format_args!(
        "Starting ARP scan on interface: {}",
        COLOR_KEYWORD.paint(&interface_name)
    ));

    let host_table = Arc::new(RwLock::new(HostTable::new()));
    let scanner = ArpScanner::new(&interface_name).await?;

    logger.info_fmt(format_args!(
        "Local MAC: {}, Local IP: {}",
        COLOR_KEYWORD.paint(&scanner.local_mac().to_string()),
        COLOR_KEYWORD.paint(&scanner.local_ip().to_string()),
    ));

    let cidr = get_cidr(&interface_name).ok_or("could not determine network CIDR for interface")?;
    let range = network::IpRange::from_cidr(&cidr)?;

    logger.info_fmt(format_args!(
        "Scanning range: {} to {}",
        COLOR_KEYWORD.paint(&range.start.to_string()),
        COLOR_KEYWORD.paint(&range.end.to_string()),
    ));

    let mut discovered = scanner.scan(range).await?;

    // Batch vendor resolution — runs after scan so it never affects timing.
    // lookup_vendor is synchronous (in-process embedded DB), so no async needed.
    logger.info_fmt(format_args!(
        "Resolving vendors for {} hosts…",
        discovered.len()
    ));
    for host in &mut discovered {
        host.vendor = Some(lookup_vendor(host.mac));
    }

    {
        let mut table = host_table.write().await;
        for host in discovered {
            table.insert(host);
        }
        table.reindex_by_ip(); // ← this is missing
    }

    {
        let table = host_table.read().await;
        table.display();
    }

    Ok(())
}
