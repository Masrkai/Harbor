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

        let input = input.trim();

        if input.eq_ignore_ascii_case("q") || input.eq_ignore_ascii_case("quit") {
            return None;
        }

        match input.parse::<usize>() {
            Ok(num) if num > 0 && num <= interfaces.len() => {
                let selected = &interfaces[num - 1];
                Some(selected.name.clone())
            }
            _ => {
                logger.fatal_fmt(format_args!("Invalid selection."));
                None
            }
        }
    }
}
