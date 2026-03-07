// src/cli/selector.rs
use crate::cli::color::*;
use crate::paint;

use crate::utils::check_interfaces::scan;
use crate::utils::logger::*;

use std::io::{self, Write};

const COLOR_MESSAGE: Color = Color::from_hex(b"#C792EA"); // purple

pub struct InterfaceSelector;

impl InterfaceSelector {
    pub fn select(only_wlan_eth: bool) -> Option<String> {
        let mut logger = Logger::new();

        let interfaces = scan(only_wlan_eth);

        if interfaces.is_empty() {
            logger.fatal_fmt(format_args!(
                "No network interfaces found! Make sure you have an active connection"
            ));
            return None;
        }

        println!("\n{}", "=".repeat(52));
        println!("{:^52}", "Available Network Interfaces");
        println!("{}", "=".repeat(52));
        println!();
        println!(
            "{:<4} {:<12} {:<10} {:<6} {}",
            "ID", "NAME", "TYPE", "UP", "MAC"
        );
        println!("{}", "-".repeat(52));

        for (idx, iface) in interfaces.iter().enumerate() {
            println!(
                "{:<4} {:<12} {:<10} {:<6} {}",
                format!("[{}]", idx + 1),
                iface.name,
                format!("{:?}", iface.kind),
                if iface.is_up { "yes" } else { "no" },
                iface.mac.as_deref().unwrap_or("unknown"),
            );
        }

        println!("{}", "-".repeat(52));

        print!(
            "{}",
            paint!(
                &COLOR_MESSAGE,
                "Select interface [1-{}] (or 'q' to quit): ",
                interfaces.len()
            )
        );

        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            return None;
        }

        // Delegate to pure parsing logic so it can be unit-tested.
        Self::parse_input(input.trim(), interfaces.len()).map(|idx| interfaces[idx].name.clone())
    }

    /// Pure function: maps a trimmed user input string and the number of
    /// available interfaces to a zero-based index into the interface list.
    ///
    /// Returns:
    ///   `Some(index)` — valid 1-based numeric selection, converted to 0-based
    ///   `None`        — quit command ("q" / "quit") or invalid input
    ///
    /// Kept `pub(crate)` so the test module below can call it directly.
    pub(crate) fn parse_input(input: &str, count: usize) -> Option<usize> {
        if input.eq_ignore_ascii_case("q") || input.eq_ignore_ascii_case("quit") {
            return None;
        }

        match input.parse::<usize>() {
            Ok(num) if num >= 1 && num <= count => Some(num - 1),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Quit commands ─────────────────────────────────────────────────────────

    /// "q" must always return None regardless of how many interfaces exist.
    #[test]
    fn test_q_returns_none() {
        assert!(InterfaceSelector::parse_input("q", 5).is_none());
    }

    /// "quit" is an accepted alias for quit.
    #[test]
    fn test_quit_returns_none() {
        assert!(InterfaceSelector::parse_input("quit", 5).is_none());
    }

    /// Quit commands are case-insensitive: "Q", "Quit", "QUIT" all quit.
    #[test]
    fn test_quit_is_case_insensitive() {
        for variant in ["Q", "Quit", "QUIT", "qUiT"] {
            assert!(
                InterfaceSelector::parse_input(variant, 5).is_none(),
                "'{variant}' should be treated as quit"
            );
        }
    }

    // ── Valid selections ──────────────────────────────────────────────────────

    /// Selecting "1" with any non-zero count returns index 0.
    #[test]
    fn test_select_first_returns_index_0() {
        assert_eq!(InterfaceSelector::parse_input("1", 3), Some(0));
    }

    /// Selecting the last item returns the last valid index.
    #[test]
    fn test_select_last_returns_last_index() {
        assert_eq!(InterfaceSelector::parse_input("3", 3), Some(2));
    }

    /// Selecting "2" out of 5 returns index 1.
    #[test]
    fn test_select_middle_item() {
        assert_eq!(InterfaceSelector::parse_input("2", 5), Some(1));
    }

    /// With a single interface, "1" is the only valid selection.
    #[test]
    fn test_single_interface_valid_selection() {
        assert_eq!(InterfaceSelector::parse_input("1", 1), Some(0));
    }

    /// The returned index is always exactly (input_number - 1).
    #[test]
    fn test_returned_index_is_one_based_converted() {
        for n in 1usize..=10 {
            assert_eq!(
                InterfaceSelector::parse_input(&n.to_string(), 10),
                Some(n - 1),
                "input '{n}' should map to index {}",
                n - 1
            );
        }
    }

    // ── Boundary: zero ────────────────────────────────────────────────────────

    /// "0" is not a valid 1-based index and must return None.
    #[test]
    fn test_zero_returns_none() {
        assert!(InterfaceSelector::parse_input("0", 5).is_none());
    }

    // ── Out-of-range ──────────────────────────────────────────────────────────

    /// One above the count must be rejected.
    #[test]
    fn test_one_above_count_returns_none() {
        assert!(InterfaceSelector::parse_input("4", 3).is_none());
    }

    /// A large number well above the count must be rejected.
    #[test]
    fn test_large_number_returns_none() {
        assert!(InterfaceSelector::parse_input("9999", 3).is_none());
    }

    /// With count == 0 (no interfaces), every numeric input must be rejected.
    #[test]
    fn test_any_number_with_zero_count_returns_none() {
        assert!(InterfaceSelector::parse_input("1", 0).is_none());
        assert!(InterfaceSelector::parse_input("0", 0).is_none());
    }

    // ── Non-numeric input ─────────────────────────────────────────────────────

    /// A plain word that isn't "q"/"quit" returns None.
    #[test]
    fn test_arbitrary_word_returns_none() {
        assert!(InterfaceSelector::parse_input("eth0", 5).is_none());
        assert!(InterfaceSelector::parse_input("hello", 5).is_none());
    }

    /// An empty string returns None.
    #[test]
    fn test_empty_string_returns_none() {
        assert!(InterfaceSelector::parse_input("", 5).is_none());
    }

    /// Whitespace-only input returns None.
    /// (select() trims before calling parse_input, but the function itself
    /// must also handle it defensively.)
    #[test]
    fn test_whitespace_returns_none() {
        assert!(InterfaceSelector::parse_input("   ", 5).is_none());
    }

    /// A float like "1.0" is not an integer and must return None.
    #[test]
    fn test_float_string_returns_none() {
        assert!(InterfaceSelector::parse_input("1.0", 5).is_none());
    }

    /// A negative number string "-1" must return None.
    #[test]
    fn test_negative_number_returns_none() {
        assert!(InterfaceSelector::parse_input("-1", 5).is_none());
    }

    /// A number with surrounding whitespace — select() trims, but verify
    /// the raw untrimmed form is rejected (so trim responsibility stays clear).
    #[test]
    fn test_number_with_whitespace_returns_none() {
        assert!(InterfaceSelector::parse_input(" 1 ", 5).is_none());
    }

    /// A number followed by non-digit characters is not a valid integer.
    #[test]
    fn test_number_with_trailing_chars_returns_none() {
        assert!(InterfaceSelector::parse_input("1x", 5).is_none());
        assert!(InterfaceSelector::parse_input("2 ", 5).is_none());
    }
}
