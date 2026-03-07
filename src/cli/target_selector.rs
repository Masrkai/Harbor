// src/cli/target_selector.rs
//
// Prompts the user to pick one or more hosts from the HostTable after a scan.
// Accepted input formats:
//   "3"       — single host
//   "1-5"     — inclusive range
//   "1,3,5"   — comma-separated list
//   "all"     — every host in the table
//
// After target selection the user is optionally asked for a per-host
// bandwidth limit (in kbps).  Entering nothing / 0 means unlimited.
//
// The gateway is automatically excluded regardless of input.

use crate::cli::color::Color;
use crate::host::table::{HostId, HostTable};
use crate::paint;
use std::io::{self, Write};
use std::net::Ipv4Addr;

const COLOR_PROMPT: Color = Color::from_hex(b"#C792EA");
const COLOR_WARN: Color = Color::from_hex(b"#FFB347");
const COLOR_OK: Color = Color::from_hex(b"#50C878");
const COLOR_DIM: Color = Color::from_hex(b"#888888");

// ─────────────────────────────────────────────────────────────────────────────

pub struct SelectionResult {
    /// Host IDs chosen by the user (gateway never included).
    pub host_ids: Vec<HostId>,
    /// Optional shared bandwidth cap applied to every selected host (kbps).
    /// None = unlimited.
    pub bandwidth_kbps: Option<u64>,
}

// ─────────────────────────────────────────────────────────────────────────────

pub struct TargetSelector;

impl TargetSelector {
    /// Entry point.  Displays the host list, collects input, returns the
    /// parsed selection or `None` if the user quits / input is invalid.
    pub fn select(table: &HostTable, gateway_ip: Ipv4Addr) -> Option<SelectionResult> {
        let gateway_id = table.get_by_ip(gateway_ip).map(|e| e.id);

        // Build sorted list of selectable IDs (gateway excluded).
        let mut available: Vec<HostId> = table
            .iter()
            .filter(|e| Some(e.id) != gateway_id)
            .map(|e| e.id)
            .collect();
        available.sort_unstable();

        if available.is_empty() {
            eprintln!("No targets available — only the gateway was discovered.");
            return None;
        }

        // ── Print table ──────────────────────────────────────────────────────
        println!("\n{}", "=".repeat(62));
        println!("{:^62}", "ARP Spoof — Target Selection");
        println!("{}", "=".repeat(62));

        println!(
            "{:<5} {:<16} {:<18} {:<12} {:<24}",
            "ID", "IP", "MAC", "Status", "Vendor"
        );
        println!("{}", "-".repeat(62));

        // Sorted by ID (= sorted by IP after reindex_by_ip)
        let mut entries: Vec<_> = table.iter().filter(|e| Some(e.id) != gateway_id).collect();
        entries.sort_by_key(|e| e.id);

        for entry in &entries {
            let vendor = entry.host.vendor.as_deref().unwrap_or("Unknown");
            println!(
                "{:<5} {:<16} {:<18} {:<12} {}",
                format!("[{}]", entry.id),
                entry.host.ip,
                entry.host.mac,
                format!("{:?}", entry.state),
                if vendor.len() > 22 {
                    format!("{:.21}…", vendor)
                } else {
                    vendor.to_string()
                },
            );
        }

        println!("{}", "-".repeat(62));

        if let Some(gw_id) = gateway_id {
            if let Some(gw) = table.get_by_id(gw_id) {
                println!(
                    "{}",
                    paint!(
                        &COLOR_WARN,
                        "  Gateway [{}] {} is excluded from selection.",
                        gw_id,
                        gw.host.ip
                    )
                );
            }
        }

        println!(
            "\n{}",
            paint!(&COLOR_DIM, r#"  Formats:  "3"   "1-5"   "1,3,5"   "all""#)
        );

        // ── Prompt ───────────────────────────────────────────────────────────
        print!(
            "\n{}",
            paint!(
                &COLOR_PROMPT,
                "Select target(s) [1-{}] or 'q' to quit: ",
                available.iter().copied().max().unwrap_or(0)
            )
        );
        io::stdout().flush().unwrap();

        let raw = read_line()?;
        if raw.eq_ignore_ascii_case("q") || raw.eq_ignore_ascii_case("quit") {
            return None;
        }

        let host_ids = Self::parse_selection(&raw, &available)?;

        if host_ids.is_empty() {
            eprintln!("No valid hosts matched your input.");
            return None;
        }

        // ── Confirm selection ────────────────────────────────────────────────
        println!(
            "\n{}",
            paint!(&COLOR_OK, "  {} host(s) selected:", host_ids.len())
        );
        for id in &host_ids {
            if let Some(entry) = table.get_by_id(*id) {
                println!("    [{}] {}  {}", id, entry.host.ip, entry.host.mac);
            }
        }

        // ── Bandwidth cap ────────────────────────────────────────────────────
        let bandwidth_kbps = Self::prompt_bandwidth();

        Some(SelectionResult {
            host_ids,
            bandwidth_kbps,
        })
    }

    // ── Input parsing ────────────────────────────────────────────────────────

    /// Parses a user-supplied selection string into a deduplicated, sorted list
    /// of host IDs.  Returns `None` on any parse error so the caller can bail.
    fn parse_selection(raw: &str, available: &[HostId]) -> Option<Vec<HostId>> {
        let max_id = available.iter().copied().max().unwrap_or(0);

        if raw.eq_ignore_ascii_case("all") {
            return Some(available.to_vec());
        }

        let mut ids: Vec<HostId> = Vec::new();

        for token in raw.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }

            if let Some((lo, hi)) = token.split_once('-') {
                // ── Range ────────────────────────────────────────────────────
                let lo: HostId = match lo.trim().parse::<usize>() {
                    Ok(v) if v >= 1 => v,
                    _ => {
                        eprintln!("Invalid range start in '{}'.", token);
                        return None;
                    }
                };
                let hi: HostId = match hi.trim().parse::<usize>() {
                    Ok(v) if v <= max_id => v,
                    _ => {
                        eprintln!("Invalid range end in '{}' (max is {}).", token, max_id);
                        return None;
                    }
                };

                if lo > hi {
                    eprintln!("Invalid range {}-{}: start must be ≤ end.", lo, hi);
                    return None;
                }

                for id in lo..=hi {
                    // IDs not in `available` (e.g. the gateway) are silently skipped.
                    if available.contains(&id) {
                        ids.push(id);
                    }
                }
            } else {
                // ── Single ID ────────────────────────────────────────────────
                let id: HostId = match token.parse() {
                    Ok(v) => v,
                    Err(_) => {
                        eprintln!("'{}' is not a valid number.", token);
                        return None;
                    }
                };

                if !available.contains(&id) {
                    eprintln!(
                        "ID {} is not selectable (does not exist or is the gateway).",
                        id
                    );
                    return None;
                }

                ids.push(id);
            }
        }

        // Deduplicate while preserving ascending order.
        ids.sort_unstable();
        ids.dedup();

        // An empty result means the input was all empty tokens or all
        // unavailable IDs — treat it the same as invalid input.
        if ids.is_empty() {
            return None;
        }

        Some(ids)
    }

    // ── Bandwidth prompt ─────────────────────────────────────────────────────

    /// Pure logic for parsing a bandwidth input string.
    /// Extracted so it can be unit-tested without stdin.
    pub(crate) fn parse_bandwidth(raw: &str) -> Option<u64> {
        if raw.is_empty() || raw == "0" {
            return None;
        }
        match raw.parse::<u64>() {
            Ok(kbps) if kbps > 0 => Some(kbps),
            _ => None,
        }
    }

    fn prompt_bandwidth() -> Option<u64> {
        print!(
            "\n{}",
            paint!(
                &COLOR_PROMPT,
                "Bandwidth cap in kbps per host (leave blank = unlimited): "
            )
        );
        io::stdout().flush().unwrap();
        let raw = read_line()?;
        let result = Self::parse_bandwidth(&raw);
        // print feedback
        match result {
            Some(kbps) => println!(
                "{}",
                paint!(&COLOR_OK, "  Bandwidth limit: {} kbps per host", kbps)
            ),
            None => println!("{}", paint!(&COLOR_DIM, "  No bandwidth limit.")),
        }
        result
    }

    // fn prompt_bandwidth() -> Option<u64> {
    //     print!(
    //         "\n{}",
    //         paint!(
    //             &COLOR_PROMPT,
    //             "Bandwidth cap in kbps per host (leave blank = unlimited): "
    //         )
    //     );
    //     io::stdout().flush().unwrap();

    //     let raw = read_line()?;

    //     if raw.is_empty() || raw == "0" {
    //         println!("{}", paint!(&COLOR_DIM, "  No bandwidth limit."));
    //         return None;
    //     }

    //     match raw.parse::<u64>() {
    //         Ok(kbps) if kbps > 0 => {
    //             println!(
    //                 "{}",
    //                 paint!(&COLOR_OK, "  Bandwidth limit: {} kbps per host", kbps)
    //             );
    //             Some(kbps)
    //         }
    //         _ => {
    //             eprintln!("  Invalid value — no limit set.");
    //             None
    //         }
    //     }
    // }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Reads a trimmed line from stdin.  Returns `None` on EOF or I/O error.
fn read_line() -> Option<String> {
    let mut buf = String::new();
    match io::stdin().read_line(&mut buf) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(buf.trim().to_owned()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ONE LINE CHANGE REQUIRED before pasting this block:
//
//   fn parse_selection(...)   →   pub(crate) fn parse_selection(...)
//
// That's the only edit needed outside this test block.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Fixtures ──────────────────────────────────────────────────────────────

    /// Standard available set: IDs 1–5, contiguous.
    fn avail_1_to_5() -> Vec<HostId> {
        vec![1, 2, 3, 4, 5]
    }

    /// Sparse available set: IDs 1, 3, 5 (gateway or removed hosts left gaps).
    fn avail_sparse() -> Vec<HostId> {
        vec![1, 3, 5]
    }

    /// Single-element available set.
    fn avail_single() -> Vec<HostId> {
        vec![1]
    }

    // ── "all" keyword ─────────────────────────────────────────────────────────

    #[test]
    fn test_all_returns_every_available_id() {
        assert_eq!(
            TargetSelector::parse_selection("all", &avail_1_to_5()),
            Some(vec![1, 2, 3, 4, 5])
        );
    }

    /// "all" is case-insensitive.
    #[test]
    fn test_all_is_case_insensitive() {
        for variant in ["ALL", "All", "aLl"] {
            assert_eq!(
                TargetSelector::parse_selection(variant, &avail_1_to_5()),
                Some(vec![1, 2, 3, 4, 5]),
                "'{variant}' should be treated as 'all'"
            );
        }
    }

    /// "all" on a sparse available set returns only the available IDs,
    /// not a filled-in contiguous range.
    #[test]
    fn test_all_on_sparse_set_returns_sparse_ids() {
        assert_eq!(
            TargetSelector::parse_selection("all", &avail_sparse()),
            Some(vec![1, 3, 5])
        );
    }

    // ── Single ID ─────────────────────────────────────────────────────────────

    #[test]
    fn test_single_first_id() {
        assert_eq!(
            TargetSelector::parse_selection("1", &avail_1_to_5()),
            Some(vec![1])
        );
    }

    #[test]
    fn test_single_last_id() {
        assert_eq!(
            TargetSelector::parse_selection("5", &avail_1_to_5()),
            Some(vec![5])
        );
    }

    #[test]
    fn test_single_middle_id() {
        assert_eq!(
            TargetSelector::parse_selection("3", &avail_1_to_5()),
            Some(vec![3])
        );
    }

    #[test]
    fn test_single_id_on_single_element_list() {
        assert_eq!(
            TargetSelector::parse_selection("1", &avail_single()),
            Some(vec![1])
        );
    }

    // ── Range ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_full_range() {
        assert_eq!(
            TargetSelector::parse_selection("1-5", &avail_1_to_5()),
            Some(vec![1, 2, 3, 4, 5])
        );
    }

    #[test]
    fn test_partial_range_low() {
        assert_eq!(
            TargetSelector::parse_selection("1-3", &avail_1_to_5()),
            Some(vec![1, 2, 3])
        );
    }

    #[test]
    fn test_partial_range_high() {
        assert_eq!(
            TargetSelector::parse_selection("3-5", &avail_1_to_5()),
            Some(vec![3, 4, 5])
        );
    }

    /// A unit range (lo == hi) returns a single-element vec.
    #[test]
    fn test_unit_range_lo_equals_hi() {
        assert_eq!(
            TargetSelector::parse_selection("3-3", &avail_1_to_5()),
            Some(vec![3])
        );
    }

    /// A range that spans IDs not in the available set silently skips them.
    /// IDs 2 and 4 are absent from avail_sparse(); the range 1-5 yields
    /// only [1, 3, 5].
    #[test]
    fn test_range_skips_unavailable_ids() {
        assert_eq!(
            TargetSelector::parse_selection("1-5", &avail_sparse()),
            Some(vec![1, 3, 5])
        );
    }

    // ── Comma-separated list ──────────────────────────────────────────────────

    #[test]
    fn test_comma_list_two_items() {
        assert_eq!(
            TargetSelector::parse_selection("1,3", &avail_1_to_5()),
            Some(vec![1, 3])
        );
    }

    #[test]
    fn test_comma_list_three_items() {
        assert_eq!(
            TargetSelector::parse_selection("1,3,5", &avail_1_to_5()),
            Some(vec![1, 3, 5])
        );
    }

    /// Commas with surrounding whitespace: "1, 3, 5" — trim() is applied per token.
    #[test]
    fn test_comma_list_with_spaces() {
        assert_eq!(
            TargetSelector::parse_selection("1, 3, 5", &avail_1_to_5()),
            Some(vec![1, 3, 5])
        );
    }

    /// Duplicates in a comma list must be deduplicated in the output.
    #[test]
    fn test_comma_list_deduplication() {
        assert_eq!(
            TargetSelector::parse_selection("1,1,2", &avail_1_to_5()),
            Some(vec![1, 2])
        );
    }

    /// Output is sorted ascending regardless of input order.
    #[test]
    fn test_comma_list_output_is_sorted() {
        assert_eq!(
            TargetSelector::parse_selection("5,1,3", &avail_1_to_5()),
            Some(vec![1, 3, 5])
        );
    }

    // ── Mixed: commas and ranges ──────────────────────────────────────────────

    /// Comma-separated tokens where some tokens are ranges.
    #[test]
    fn test_mixed_range_and_single() {
        // "1-3,5" → [1, 2, 3, 5]
        assert_eq!(
            TargetSelector::parse_selection("1-3,5", &avail_1_to_5()),
            Some(vec![1, 2, 3, 5])
        );
    }

    #[test]
    fn test_mixed_single_and_range() {
        // "1,3-5" → [1, 3, 4, 5]
        assert_eq!(
            TargetSelector::parse_selection("1,3-5", &avail_1_to_5()),
            Some(vec![1, 3, 4, 5])
        );
    }

    /// Overlap between a range and a single ID is deduplicated.
    #[test]
    fn test_mixed_overlap_is_deduplicated() {
        // "1-3,2" → [1, 2, 3]  (2 appears in both the range and the extra token)
        assert_eq!(
            TargetSelector::parse_selection("1-3,2", &avail_1_to_5()),
            Some(vec![1, 2, 3])
        );
    }

    // ── Error: reversed range ─────────────────────────────────────────────────

    /// lo > hi must return None.
    #[test]
    fn test_reversed_range_returns_none() {
        assert!(TargetSelector::parse_selection("5-1", &avail_1_to_5()).is_none());
    }

    #[test]
    fn test_reversed_range_adjacent_returns_none() {
        assert!(TargetSelector::parse_selection("3-2", &avail_1_to_5()).is_none());
    }

    // ── Error: out-of-range IDs ───────────────────────────────────────────────

    /// A single ID that isn't in the available set must return None.
    #[test]
    fn test_single_id_not_in_available_returns_none() {
        assert!(TargetSelector::parse_selection("6", &avail_1_to_5()).is_none());
    }

    /// ID 0 is never valid (IDs start at 1).
    #[test]
    fn test_id_zero_returns_none() {
        assert!(TargetSelector::parse_selection("0", &avail_1_to_5()).is_none());
    }

    /// Range end exceeding max_id returns None.
    #[test]
    fn test_range_end_above_max_returns_none() {
        assert!(TargetSelector::parse_selection("1-99", &avail_1_to_5()).is_none());
    }

    // ── Error: non-numeric / malformed input ──────────────────────────────────

    #[test]
    fn test_empty_string_returns_none() {
        assert!(TargetSelector::parse_selection("", &avail_1_to_5()).is_none());
    }

    #[test]
    fn test_word_returns_none() {
        assert!(TargetSelector::parse_selection("abc", &avail_1_to_5()).is_none());
    }

    #[test]
    fn test_float_returns_none() {
        assert!(TargetSelector::parse_selection("1.5", &avail_1_to_5()).is_none());
    }

    #[test]
    fn test_negative_number_returns_none() {
        assert!(TargetSelector::parse_selection("-1", &avail_1_to_5()).is_none());
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    /// An empty token from a leading/trailing comma is silently skipped,
    /// not treated as an error, so a valid ID alongside it still works.
    /// e.g. "1," → token "" is empty → skipped → result [1]
    #[test]
    fn test_trailing_comma_empty_token_skipped() {
        // The implementation skips empty tokens via `if token.is_empty() { continue }`
        assert_eq!(
            TargetSelector::parse_selection("1,", &avail_1_to_5()),
            Some(vec![1])
        );
    }

    /// A comma-only string produces no IDs — Some(vec![]) would be filtered
    /// by the caller, but parse_selection itself must not panic.
    /// The actual return (None or Some([])) documents the current contract.
    #[test]
    fn test_comma_only_does_not_panic() {
        // We don't assert a specific value — just that it returns without panic.
        let _ = TargetSelector::parse_selection(",", &avail_1_to_5());
    }

    /// parse_selection on a completely empty available set:
    /// even "all" returns Some([]) since there is nothing to select.
    #[test]
    fn test_all_on_empty_available_returns_empty_vec() {
        assert_eq!(TargetSelector::parse_selection("all", &[]), Some(vec![]));
    }

    // ── parse_bandwidth() ─────────────────────────────────────────────────────

    #[test]
    fn test_bandwidth_empty_returns_none() {
        assert!(TargetSelector::parse_bandwidth("").is_none());
    }

    #[test]
    fn test_bandwidth_zero_string_returns_none() {
        assert!(TargetSelector::parse_bandwidth("0").is_none());
    }

    #[test]
    fn test_bandwidth_valid_value_returns_some() {
        assert_eq!(TargetSelector::parse_bandwidth("1000"), Some(1000));
        assert_eq!(TargetSelector::parse_bandwidth("512"), Some(512));
    }

    #[test]
    fn test_bandwidth_minimum_valid_value() {
        assert_eq!(TargetSelector::parse_bandwidth("1"), Some(1));
    }

    #[test]
    fn test_bandwidth_large_value() {
        assert_eq!(TargetSelector::parse_bandwidth("1000000"), Some(1_000_000));
    }

    #[test]
    fn test_bandwidth_non_numeric_returns_none() {
        assert!(TargetSelector::parse_bandwidth("abc").is_none());
        assert!(TargetSelector::parse_bandwidth("1.5").is_none());
    }

    #[test]
    fn test_bandwidth_negative_returns_none() {
        assert!(TargetSelector::parse_bandwidth("-100").is_none());
    }
}
