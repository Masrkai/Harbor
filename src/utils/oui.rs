// src/utils/oui.rs
//
// Wraps the `oui-data` crate (IEEE-sourced, fully embedded — no file needed)
// to resolve the first 3 octets of a MAC address to a vendor name.
//
// Called as a batch pass after scanning completes, so it never slows the
// ARP send/receive loop.

use pnet::util::MacAddr;

/// Looks up the vendor name for a MAC address using the embedded IEEE OUI database.
/// Returns `"Unknown"` when no match is found.
pub fn lookup_vendor(mac: MacAddr) -> String {
    // oui-data expects the OUI prefix in uppercase colon-separated form: "AA:BB:CC"
    let oui = format!("{:02X}:{:02X}:{:02X}", mac.0, mac.1, mac.2);

    oui_data::lookup(&oui)
        .map(|record| record.organization().to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}
