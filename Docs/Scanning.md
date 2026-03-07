# ARP Scanning: Real Limitations, Root Causes, and Building a Reliable Scanner

## How ARP Scanning Works (and Why It's Supposed to Be Perfect)

The Address Resolution Protocol (ARP) operates at OSI Layer 2, the Data Link layer. Its sole job is to map an IPv4 address to a MAC (hardware) address on the local network segment.

An ARP scan works by broadcasting an ARP request to every IP address in a target range. The request essentially asks: *"Who has IP address X? Tell me your MAC."* A device assigned to that IP is obligated by the protocol to reply with its MAC address. Since ARP is non-routable and operates below the IP layer, it cannot be blocked by host-based firewalls that operate at Layer 3 or above. A device cannot "silently drop" an ARP request the way it can drop a ping or a TCP SYN — doing so would mean it can no longer participate in any IP communication at all.

This is what gives ARP scanning its theoretical superiority over ICMP ping or TCP-based host discovery. In practice, this reasoning holds well for always-on, wired devices. For modern wireless networks filled with power-managed mobile devices, it breaks down.

---

## Why Devices Go Missing — Root Cause Analysis

### 802.11 WiFi Power Save Mode

This is the primary cause of missed devices in modern environments.

The IEEE 802.11 standard has included Power Save Mode (PSM) since its original 1997 release. PSM allows a wireless client (a phone, tablet, laptop, IoT sensor, etc.) to turn off its radio receiver — not just reduce activity, but **completely power it down** — between beacon intervals. The device negotiates a "Listen Interval" with the access point, specifying how many beacon frames it will skip before waking up to check for buffered traffic.

The sequence works like this:

1. A device signals to the AP that it is entering sleep (`PS-Poll` or `WMM Power Save` / `U-APSD`).
2. The AP acknowledges this and begins **buffering** any unicast frames destined for that device.
3. **Broadcast and multicast traffic** — which ARP requests are — is handled differently. The AP is expected to buffer group-addressed traffic and transmit it only at the DTIM (Delivery Traffic Indication Map) beacon interval.
4. The sleeping client wakes up at each DTIM beacon, checks if group traffic is buffered, receives it if so, and then goes back to sleep.

The problem for ARP scanning is multi-layered:

- If an ARP request (a broadcast frame) arrives while a device is asleep **and the AP does not correctly buffer and retransmit it at the next DTIM**, the device simply never receives the request.
- Many consumer and prosumer APs have buggy or aggressive implementations of this buffering. Field evidence from MikroTik, OpenWrt, and other platforms confirms that broadcast ARP packets are frequently **not retransmitted** to sleeping clients after they wake up — the AP drops them from the buffer.
- Smartphones are extremely aggressive with power saving. An iPhone can stop responding to all network traffic within approximately 30 seconds of its screen turning off. Android varies by vendor but follows similar patterns.
- IoT devices (ESP8266, ESP32, Arduino WiFi shields) with custom firmware often implement non-standard PSM behavior that makes their ARP response timing unpredictable.

The net result: an ARP scan executed while a phone or tablet is sleeping will receive no reply, even though the device is fully connected to the network and would respond immediately if the screen were on.

### AP Broadcast Handling and Proxy ARP

Modern enterprise wireless infrastructure adds another layer of complexity: **Proxy ARP**.

When Proxy ARP is enabled on a wireless controller or AP (as it is by default on Cisco Catalyst 9800, Ubiquiti UniFi, and others), the AP maintains a mapping table of IP-to-MAC associations for all associated clients. When an ARP request arrives on the wired side asking for a wireless client's MAC address:

1. The controller intercepts the broadcast ARP request.
2. It checks its internal association database.
3. If the IP is in the table, it **responds on behalf of the client** — impersonating the device.
4. The actual wireless client never sees the ARP request at all.

From the scanner's perspective this looks like a success — it gets a reply. But the scanner is talking to the AP's proxy, not the device itself. This is not necessarily a problem for basic host discovery, but it can mask devices that have become unresponsive or disconnected but whose IP-to-MAC mapping is still cached by the AP. Conversely, if the AP's mapping is stale or incomplete, some legitimate devices will go unanswered.

An additional complication comes from **multicast-to-unicast conversion**. Some APs convert broadcast frames (like ARP requests) into individual unicast frames sent directly to each associated client. While this improves efficiency and battery life, it means a scanner may not "see" ARP requests from other devices on the network in promiscuous mode, as the broadcasts are no longer being broadcast.

### AP Client Isolation

Many residential and enterprise access points have **client isolation** enabled by default — especially on guest networks. When client isolation is active, wireless clients cannot send Layer 2 frames to each other. ARP requests from one WiFi client are suppressed before they reach other WiFi clients on the same SSID.

A scanner running on a wireless interface may be able to reach wired devices just fine, while completely blind to other wireless clients due to this AP policy. This is entirely transparent at the scanning level — the ARP requests are sent, they just never arrive.

### ARP Cache Timing and Expiry

Even on wired networks, ARP cache entries have a finite TTL. Linux typically expires them after 30 seconds of inactivity (with a stale window); Windows uses a 2-minute reachable timeout with a configurable max of 10 minutes. Embedded devices and printers can have highly variable implementations.

A device that has been idle — no outgoing traffic — for longer than its ARP cache timeout on the gateway or scanner will have no active ARP entry. If the scanner queries it and the device is in a deep power state (for example, a network printer in sleep mode), it may not respond to the ARP request even over a wired connection. The SNBForums thread reporting this exact behavior with Brother laser printers over wired Ethernet confirms that **power-saving behavior is not exclusively a wireless problem**.

### Non-Standard or Buggy Network Stacks

Some devices have intentionally or accidentally non-conformant ARP implementations:

- **Security appliances** (Cisco ASA, Check Point firewalls, F5 BIG-IP, Palo Alto) are designed to be silent and may not respond to ARP from unrecognized sources or on interfaces where they are not the active gateway.
- **Virtual machine hypervisors** (VMware, Hyper-V, KVM) can create ARP asymmetries where VMs respond but the host itself doesn't, or where promiscuous mode settings affect visibility.
- **Some IoT firmware** has been observed to respond to unicast ARP requests but not broadcast ones, inverted from standard behavior.

The GitHub issue tracker for `royhills/arp-scan` documents a confirmed case of a device that was pingable but returned zero ARP responses even when targeted directly — the device's network stack had a legitimate bug.

### OS-Level ARP Suppression

Modern Android and iOS implement network-level optimizations that can delay or entirely suppress ARP responses from the device's perspective:

- iOS uses a technique where the WiFi chip continues to handle beacon monitoring in a low-power state while the application processor is fully suspended. ARP handling during this state is inconsistent — the WiFi chip may "wake on" certain unicast traffic but not on broadcast frames.
- Android's "WiFi doze" and Doze Mode (introduced in Android 6.0 Marshmallow) progressively suspends network interfaces based on inactivity. During deep Doze, the device will not respond to any unsolicited network traffic, including ARP.

---

## The Divide and Conquer Problem

Divide-and-conquer ARP scanning refers to splitting a large address range into smaller chunks and scanning them concurrently across multiple threads or async tasks — e.g., splitting a /16 into 256 concurrent /24 scans. The approach is correct in concept and can deliver enormous speed improvements. However, several subtle failure modes can cause hosts to be silently missed.

### The Race Condition at the Core

The most fundamental problem is the **timing gap between the last ARP packet sent and the end of the receive window**.

In a naive implementation, each scanning thread or task:

1. Sends ARP packets for its assigned range.
2. Waits for a fixed timeout (say, 500ms).
3. Closes its receive socket and reports results.

The issue is that network devices have variable ARP response latency. A device on a congested wireless network may take 200–400ms to respond. If a thread finishes sending its last packet and immediately starts a 500ms receive timer, responses from earlier packets in the same chunk that took a long time may overlap with the tail end of that timer — and if the timer fires too early due to async scheduling jitter, those responses are lost.

This is not theoretical. The Metasploit framework's `ipv6_neighbor` module had a confirmed race condition where scanning short address ranges would silently miss alive hosts because the adaptive timeout floor was too low. The fix was to enforce a minimum receive window that didn't scale to zero for small ranges.

### The Send/Receive Phase Coupling Problem

Many implementations tightly couple the send and receive phases, processing responses as packets are sent. This creates a structural problem when parallelizing:

- Thread A is actively sending ARP requests for 192.168.1.0–127.
- Thread B is actively sending ARP requests for 192.168.1.128–255.
- Thread A finishes sending at T=100ms and starts a 500ms receive window, expiring at T=600ms.
- A response for a host in Thread A's range arrives at T=650ms.

The response is missed. Thread B might still be running, but its receive socket is only listening for responses to **its** range (by design), so it won't capture Thread A's late response either.

The correct approach requires **a single, shared receive socket** that runs for the duration of the entire scan plus a trailing receive window — not a per-thread window.

### Thread Contention on Shared Sockets

The opposite architectural mistake — sharing a single raw socket between all worker threads for both sending and receiving — introduces contention bugs. Raw sockets at the OS level are not inherently thread-safe. Without careful locking:

- Two threads can attempt to write to the TX socket simultaneously, causing mangled or dropped packets.
- A thread may read a response from the RX socket that belongs to another thread's range and process it incorrectly (or discard it as unexpected).
- Platform differences between Linux, macOS, and BSD mean that raw socket behavior under concurrent writes is not consistent.

### Kernel TX Buffer Saturation

Sending ARP packets at high speed across many threads can saturate the kernel's network TX buffer (`sk_buff` on Linux). When this happens, `sendto()` or `pcap_inject()` returns `ENOBUFS` or `No buffer space available`. Naively retrying immediately makes this worse. Without backpressure-aware sending:

- Packets are silently dropped by the kernel without the application knowing.
- The retry logic may resend at the same rate, continuously filling the buffer.
- Some implementation bugs cause the error to be swallowed entirely.

This is explicitly documented in the `arp-scan` man page: *"setting the bandwidth too high can send packets faster than the network interface can transmit them, which will eventually fill the kernel's transmit buffer."*

### Adaptive Timeout Failures

Some implementations use adaptive timeouts: a shorter window for small ranges (fewer hosts to wait for), a longer one for large ranges. The logic is sound in principle but breaks in practice because **the number of hosts in a range does not predict how many will respond or how long they will take**. A range of 10 addresses where 9 are sleeping wireless devices will require far longer to collect all responses than a range of 256 always-on servers, despite being 25x smaller.

Basing the receive window on the count of target IPs rather than the observed response distribution is a systematic source of missed hosts.

---

## Building a Reliable ARP Scanner — The Ideal Design

### Decouple Send and Receive Phases

The single most impactful architectural decision is to **completely decouple the packet-sending logic from the packet-receiving logic**. The correct model is:

1. A **sender** component that works through the target IP list, sending raw ARP request frames at a controlled rate.
2. A **receiver** component running concurrently in its own thread/goroutine/task, listening on a raw or pcap socket, collecting every ARP reply frame from the wire regardless of which sender chunk triggered it.
3. A **global receive window** that starts when the first packet is sent and ends `max_response_latency` milliseconds after the **last** packet is sent — not after each chunk.

This design eliminates the race condition at the chunk boundary entirely. It also means that late responders — devices that take 400ms or more — are captured as long as the trailing window is generous enough.

### Multi-Pass Scanning with Retries

No single ARP sweep should be trusted as complete. A robust scanner should:

- Run at least 2–3 full passes over the target range.
- On each subsequent pass, only re-query addresses that did not respond in the previous pass.
- Space passes far enough apart (5–10 seconds minimum) that power-saving devices have a plausible wake window between passes.

The `arp-scan` tool exposes a `--retry` flag for this purpose. The default retry count is 2; increasing it to 3–4 on WiFi-heavy environments meaningfully reduces misses. The bandwidth/timing parameters should be adjusted per pass — a slower, lower-rate first pass followed by a targeted retry pass at normal speed often outperforms a single fast pass.

### Rate Limiting and Bandwidth Control

ARP flooding a network is counterproductive. Sending requests faster than devices can process them causes:

- Dropped replies from busy embedded devices (cheap IoT gear has small network buffers).
- ARP cache pollution and brief instability on some consumer routers.
- TX buffer saturation on the scanner itself, causing the scanner to silently drop its own outgoing packets.

A bandwidth-aware sender that models the wire rate and stays under a configurable threshold (the `arp-scan` default of 256 Kbps is reasonable for a /24; it should scale down for larger ranges) prevents these failure modes.

### Pre-Wake Strategy for Power-Saving Devices

Because sleeping wireless devices are the dominant cause of missed hosts, a pre-wake strategy can dramatically improve recall:

1. Send a unicast ICMP echo request (ping) to each IP in the range before the ARP sweep begins.
2. Wait 100–200ms for devices to process the ping and potentially wake their network stack.
3. Then perform the ARP sweep.

The ping itself may not get a response (firewalls, iOS deep sleep), but the act of receiving an ICMP frame can be enough to bring a device's WiFi stack out of its deepest sleep state before the ARP request arrives. Some implementations also send a UDP probe to a high-numbered port to generate the same wake effect without relying on ICMP.

Alternatively, a **targeted unicast ARP** (sending ARP requests to the device's known MAC address as the destination, rather than `ff:ff:ff:ff:ff:ff`) can bypass AP broadcast suppression issues, since unicast frames are forwarded to a specific client rather than being subject to broadcast buffering rules.

### Hybrid Discovery Pipeline

No single probe technique discovers all devices. A production-quality network scanner should chain multiple techniques, with each subsequent layer catching what the previous missed:

| Phase | Technique | Catches |
|-------|-----------|---------|
| 1 | ARP broadcast scan (multi-pass) | Most wired and idle wireless devices |
| 2 | Unicast ARP to known MACs | Devices behind AP broadcast suppression |
| 3 | ICMP ping sweep | Devices with broken ARP stacks that respond to ICMP |
| 4 | TCP/UDP probe to common ports | Firewalled hosts that still have open services |
| 5 | Passive ARP sniffing | Devices that initiate their own ARP requests |
| 6 | DHCP lease table query | Dynamically assigned devices, even sleeping ones |
| 7 | Router ARP cache (SNMP) | Ground truth from the gateway's own ARP table |

Each layer has different characteristics. ARP is fast and infrastructure-transparent. Passive sniffing has zero network impact but requires time (you wait for devices to generate traffic). The router's ARP cache is authoritative for any device that has communicated recently, regardless of whether it responds to active probes.

### Passive Sniffing as a Supplement

Passive ARP sniffing — placing the network interface in promiscuous mode and recording every ARP frame seen on the segment, whether request or reply — costs nothing in terms of network impact and accumulates a highly accurate host list over time.

Gratuitous ARP (GARP) frames, which devices send on their own initiative when they acquire or renew an IP address, reveal devices that never respond to probes. DHCP discovery messages are similarly valuable. A scanner that passively observes the network for 30–60 seconds before and after the active scan phase will capture late-waking devices with zero additional network load.

### DHCP and Router Cache as Ground Truth

The network's DHCP server knows every IP it has leased and to which MAC address. The gateway router's ARP cache reflects every device that has communicated through it recently. Both of these data sources are far more reliable than active probing for environments with many power-saving wireless clients.

Querying the router via SNMP (`ipNetToMediaTable`, OID `1.3.6.1.2.1.4.22`) or via its management API provides the ARP cache contents without requiring the scanner to successfully probe each individual device. For a scanner that has privileged access to the network infrastructure, this should be treated as the primary data source, with active probing used only to supplement and update it.

---

## Summary

The following table condenses the failure modes and their mitigations:

| Failure Mode | Root Cause | Mitigation |
|---|---|---|
| Sleeping mobile devices miss ARP | 802.11 PSM, WiFi radio powered down | Multi-pass scan, pre-wake ping, unicast ARP |
| AP intercepts/drops broadcast ARP | Proxy ARP, broadcast suppression, DTIM buffering issues | Unicast ARP, SNMP/DHCP query of infrastructure |
| Client isolation blocks inter-client ARP | AP policy | Scan from wired interface or gateway vantage |
| Hosts missed in concurrent scanning | Race condition on per-chunk receive windows | Single global RX socket, trailing receive window |
| TX buffer overflow drops outgoing packets | Sending faster than kernel can flush | Bandwidth-controlled sender with backpressure |
| Adaptive timeout too short for sparse ranges | Timeout based on host count, not response latency | Fixed minimum window + generous trailing window |
| Power-saving wired devices (printers, IoT) | Embedded devices enter deep sleep, stop responding | Static ARP entries, DHCP lease correlation |
| Stale AP Proxy ARP responds for offline device | AP mapping table not expired | Cross-validate with direct probing, lease TTLs |

**The key insight is this:** ARP scanning is the best active probe technique for local subnet host discovery. But "best" does not mean "complete." A scanner that treats a single ARP sweep as authoritative will consistently miss 10–30% of devices in environments with significant wireless client populations. A well-engineered implementation treats ARP as the primary layer of a multi-technique pipeline, decouples its send and receive phases, applies intelligent retries with appropriate timing, and supplements active probing with passive observation and infrastructure data queries.
