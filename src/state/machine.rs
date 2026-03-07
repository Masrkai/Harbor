// src/state/machine.rs
use crate::host::table::{HostEntry, HostState};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    Scan,    // Discovered -> Discovered (refresh)
    Poison,  // Discovered -> Poisoning
    Limit,   // Poisoning -> Limited
    Block,   // Poisoning -> Blocked
    Free,    // Limited/Blocked -> Poisoning (stop limiting but keep MITM)
    Stop,    // Poisoning/Limited/Blocked -> Discovered (stop MITM)
    Error,   // Any -> Error
    Recover, // Error -> Discovered
}

#[derive(Debug)]
pub struct StateMachine;

impl StateMachine {
    pub fn can_transition(from: HostState, transition: Transition) -> bool {
        use HostState::{Blocked, Discovered, Error as StateError, Limited, Poisoning};
        use Transition::{Block, Error as TransError, Free, Limit, Poison, Recover, Scan, Stop};

        match (from, transition) {
            // From Discovered
            (Discovered, Scan) => true,
            (Discovered, Poison) => true,
            (Discovered, TransError) => true,

            // From Poisoning
            (Poisoning, Limit) => true,
            (Poisoning, Block) => true,
            (Poisoning, Stop) => true,
            (Poisoning, TransError) => true,

            // From Limited
            (Limited, Block) => true, // Increase restriction
            (Limited, Free) => true,  // Remove limit but keep MITM
            (Limited, Stop) => true,  // Stop everything
            (Limited, TransError) => true,

            // From Blocked
            (Blocked, Limit) => true, // Reduce restriction
            (Blocked, Free) => true,  // Remove block but keep MITM
            (Blocked, Stop) => true,  // Stop everything
            (Blocked, TransError) => true,

            // From Error
            (StateError, Recover) => true,
            (StateError, Stop) => true,

            _ => false,
        }
    }

    pub fn next_state(from: HostState, transition: Transition) -> Option<HostState> {
        if !Self::can_transition(from, transition) {
            return None;
        }

        use HostState::{Blocked, Discovered, Error as StateError, Limited, Poisoning};
        use Transition::{Block, Error as TransError, Free, Limit, Poison, Recover, Scan, Stop};

        Some(match (from, transition) {
            (Discovered, Scan) => Discovered,
            (Discovered, Poison) => Poisoning,
            (Discovered, TransError) => StateError,

            (Poisoning, Limit) => Limited,
            (Poisoning, Block) => Blocked,
            (Poisoning, Stop) => Discovered,
            (Poisoning, TransError) => StateError,

            (Limited, Block) => Blocked,
            (Limited, Free) => Poisoning,
            (Limited, Stop) => Discovered,
            (Limited, TransError) => StateError,

            (Blocked, Limit) => Limited,
            (Blocked, Free) => Poisoning,
            (Blocked, Stop) => Discovered,
            (Blocked, TransError) => StateError,

            (StateError, Recover) => Discovered,
            (StateError, Stop) => Discovered,

            _ => return None,
        })
    }

    pub fn describe_transition(from: HostState, to: HostState) -> String {
        use HostState::*;

        match (from, to) {
            (Discovered, Poisoning) => "Started ARP poisoning".to_string(),
            (Poisoning, Limited) => "Applied bandwidth limit".to_string(),
            (Poisoning, Blocked) => "Blocked all traffic".to_string(),
            (Limited, Blocked) => "Increased restriction to block".to_string(),
            (Blocked, Limited) => "Reduced restriction to limit".to_string(),
            (Limited, Poisoning) => "Removed bandwidth limit".to_string(),
            (Blocked, Poisoning) => "Unblocked traffic".to_string(),
            (Poisoning, Discovered) => "Stopped ARP poisoning".to_string(),
            (Limited, Discovered) => "Stopped all interference".to_string(),
            (Blocked, Discovered) => "Stopped all interference".to_string(),
            (Error, Discovered) => "Recovered from error".to_string(),
            (from, to) if from == to => "Refreshed".to_string(),
            _ => format!("{:?} -> {:?}", from, to),
        }
    }
}
