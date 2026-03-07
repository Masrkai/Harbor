// src/utils/gateway.rs
//
// Reads the default IPv4 gateway for a given interface from the Linux kernel's
// routing table at /proc/net/route.
//
// The file has one route per line (tab-separated after the header):
//
//   Iface  Destination  Gateway  Flags  RefCnt  Use  Metric  Mask  MTU  Window  IRTT
//   eth0   00000000     0101A8C0  0003   0       0    100     00000000  0  0  0
//
// All numeric fields are 32-bit little-endian hex.
// A default route has Destination == 00000000 and the RTF_GATEWAY flag (0x2) set.

use std::net::Ipv4Addr;

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the default gateway IP for `interface_name`, or `None` if not found.
pub fn get_gateway(interface_name: &str) -> Option<Ipv4Addr> {
    let content = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_route_table(&content, interface_name)
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure parsing — extracted so it can be unit-tested without touching the FS
// ─────────────────────────────────────────────────────────────────────────────

/// Parses the text content of `/proc/net/route` and returns the default
/// gateway IP for `interface_name`, or `None` if no matching route is found.
///
/// A matching row must satisfy all three conditions:
///   1. The `Iface` column equals `interface_name`.
///   2. The `Destination` column is `00000000` (default route).
///   3. The `Flags` column has bit 0x0002 (RTF_GATEWAY) set.
pub(crate) fn parse_route_table(content: &str, interface_name: &str) -> Option<Ipv4Addr> {
    for line in content.lines().skip(1) {
        let mut fields = line.split_whitespace();

        // Use explicit matching instead of `?` so that a row with fewer than
        // four columns is silently skipped rather than aborting the whole
        // function (which is what `?` does inside a loop that returns Option).
        let (iface, destination, gateway_hex, flags_hex) =
            match (fields.next(), fields.next(), fields.next(), fields.next()) {
                (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
                _ => continue,
            };

        if iface != interface_name {
            continue;
        }

        // Default route: destination is the all-zeros network.
        if destination != "00000000" {
            continue;
        }

        // RTF_GATEWAY (0x0002) must be set.
        let flags = u32::from_str_radix(flags_hex, 16).unwrap_or(0);
        if flags & 0x0002 == 0 {
            continue;
        }

        // Gateway address: 32-bit little-endian hex → bytes.
        // Use continue (not ?) so a bad hex field skips this row rather than
        // aborting the whole search — a later row might still be valid.
        let gw_u32 = match u32::from_str_radix(gateway_hex, 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let b = gw_u32.to_le_bytes();
        return Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]));
    }

    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Minimal valid /proc/net/route header — always the first line.
    const HEADER: &str =
        "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT";

    /// Builds a complete synthetic /proc/net/route table from a list of rows.
    /// Each row is (iface, destination_hex, gateway_hex, flags_hex).
    fn make_table(rows: &[(&str, &str, &str, &str)]) -> String {
        let mut out = format!("{}\n", HEADER);
        for (iface, dst, gw, flags) in rows {
            // The real file has more columns; split_whitespace() only reads
            // the first four, so extra columns don't matter.
            out.push_str(&format!(
                "{iface}\t{dst}\t{gw}\t{flags}\t0\t0\t100\t00000000\t0\t0\t0\n"
            ));
        }
        out
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    /// Standard single-interface table: 192.168.1.1 stored as 0101A8C0.
    #[test]
    fn test_standard_gateway_eth0() {
        // 192.168.1.1 in little-endian hex:
        //   0xC0 = 192, 0xA8 = 168, 0x01 = 1, 0x01 = 1  → 0101A8C0
        let table = make_table(&[("eth0", "00000000", "0101A8C0", "0003")]);
        let gw = parse_route_table(&table, "eth0");
        assert_eq!(gw, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    /// 10.0.0.1 stored as 0100000A.
    #[test]
    fn test_gateway_10_0_0_1() {
        // 10.0.0.1 LE: 0x0A=10, 0x00=0, 0x00=0, 0x01=1 → 0100000A
        let table = make_table(&[("wlan0", "00000000", "0100000A", "0003")]);
        let gw = parse_route_table(&table, "wlan0");
        assert_eq!(gw, Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    /// 172.16.0.1 stored as 010010AC.
    #[test]
    fn test_gateway_172_16_0_1() {
        // 172.16.0.1 LE: 0xAC=172, 0x10=16, 0x00=0, 0x01=1 → 010010AC
        let table = make_table(&[("enp3s0", "00000000", "010010AC", "0003")]);
        let gw = parse_route_table(&table, "enp3s0");
        assert_eq!(gw, Some(Ipv4Addr::new(172, 16, 0, 1)));
    }

    // ── Multi-interface table ─────────────────────────────────────────────────

    /// When multiple interfaces are present, only the matching one is returned.
    #[test]
    fn test_correct_interface_is_selected() {
        let table = make_table(&[
            ("eth0", "00000000", "0101A8C0", "0003"),  // 192.168.1.1
            ("wlan0", "00000000", "0100000A", "0003"), // 10.0.0.1
        ]);

        assert_eq!(
            parse_route_table(&table, "eth0"),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(
            parse_route_table(&table, "wlan0"),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    /// Non-default routes (destination ≠ 00000000) must be skipped even when
    /// the interface name matches.
    #[test]
    fn test_non_default_route_is_skipped() {
        let table = make_table(&[
            // Specific subnet route — not the default gateway row
            ("eth0", "0001A8C0", "0101A8C0", "0001"),
            // The real default route
            ("eth0", "00000000", "FE01A8C0", "0003"), // 192.168.1.254
        ]);
        let gw = parse_route_table(&table, "eth0");
        assert_eq!(gw, Some(Ipv4Addr::new(192, 168, 1, 254)));
    }

    /// The first matching row wins when multiple default routes exist for the
    /// same interface (unusual but valid in policy-routing setups).
    #[test]
    fn test_first_default_route_wins() {
        let table = make_table(&[
            ("eth0", "00000000", "0101A8C0", "0003"), // 192.168.1.1  ← first
            ("eth0", "00000000", "FE01A8C0", "0003"), // 192.168.1.254
        ]);
        let gw = parse_route_table(&table, "eth0");
        assert_eq!(gw, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    // ── RTF_GATEWAY flag checks ───────────────────────────────────────────────

    /// A row with destination 00000000 but RTF_GATEWAY bit (0x0002) NOT set
    /// must be skipped — it's a connected route, not a gateway.
    #[test]
    fn test_row_without_gateway_flag_is_skipped() {
        // Flags 0x0001 = RTF_UP only, no RTF_GATEWAY
        let table = make_table(&[("eth0", "00000000", "0101A8C0", "0001")]);
        let gw = parse_route_table(&table, "eth0");
        assert!(
            gw.is_none(),
            "row without RTF_GATEWAY flag must not be treated as a gateway"
        );
    }

    /// Flags 0x0003 = RTF_UP | RTF_GATEWAY — the combination used in practice.
    #[test]
    fn test_flags_0003_accepted() {
        let table = make_table(&[("eth0", "00000000", "0101A8C0", "0003")]);
        assert!(parse_route_table(&table, "eth0").is_some());
    }

    /// Flags 0x0007 = RTF_UP | RTF_GATEWAY | RTF_HOST — still has bit 0x0002.
    #[test]
    fn test_gateway_flag_in_combined_flags_accepted() {
        let table = make_table(&[("eth0", "00000000", "0101A8C0", "0007")]);
        assert!(parse_route_table(&table, "eth0").is_some());
    }

    // ── Negative cases ────────────────────────────────────────────────────────

    /// Requesting a gateway for an interface that isn't in the table → None.
    #[test]
    fn test_unknown_interface_returns_none() {
        let table = make_table(&[("eth0", "00000000", "0101A8C0", "0003")]);
        assert!(parse_route_table(&table, "wlan0").is_none());
    }

    /// An empty table (header only) returns None.
    #[test]
    fn test_empty_table_returns_none() {
        let table = format!("{}\n", HEADER);
        assert!(parse_route_table(&table, "eth0").is_none());
    }

    /// A completely empty string doesn't panic and returns None.
    #[test]
    fn test_empty_string_returns_none() {
        assert!(parse_route_table("", "eth0").is_none());
    }

    /// Rows with fewer than four columns are skipped without panicking.
    #[test]
    fn test_malformed_row_is_skipped_gracefully() {
        // One malformed row, then a valid one.
        let table = format!(
            "{}\n\
             eth0\tBAD\n\
             eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
            HEADER
        );
        let gw = parse_route_table(&table, "eth0");
        assert_eq!(gw, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    /// A gateway field with non-hex characters is skipped without panicking.
    #[test]
    fn test_non_hex_gateway_field_is_skipped() {
        let table = format!(
            "{}\n\
             eth0\t00000000\tZZZZZZZZ\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
            HEADER
        );
        assert!(parse_route_table(&table, "eth0").is_none());
    }

    // ── Little-endian byte order ──────────────────────────────────────────────

    /// The gateway field is 32-bit little-endian.
    /// 0x0204A8C0 → bytes [0xC0, 0xA8, 0x04, 0x02] → 192.168.4.2
    #[test]
    fn test_little_endian_byte_order_is_correct() {
        let table = make_table(&[("eth0", "00000000", "0204A8C0", "0003")]);
        let gw = parse_route_table(&table, "eth0");
        assert_eq!(gw, Some(Ipv4Addr::new(192, 168, 4, 2)));
    }

    /// 0x01020A0A → bytes [0x0A, 0x0A, 0x02, 0x01] → 10.10.2.1
    #[test]
    fn test_little_endian_10_10_2_1() {
        let table = make_table(&[("eth0", "00000000", "01020A0A", "0003")]);
        let gw = parse_route_table(&table, "eth0");
        assert_eq!(gw, Some(Ipv4Addr::new(10, 10, 2, 1)));
    }

    // ── Live integration (requires real Linux routing table) ──────────────────

    /// get_gateway() on any real interface must not panic.
    /// We don't assert the value because CI won't have a gateway.
    #[test]
    #[ignore]
    fn test_get_gateway_does_not_panic_on_live_system() {
        let _ = get_gateway("eth0");
        let _ = get_gateway("wlan0");
        let _ = get_gateway("does_not_exist");
    }
}
