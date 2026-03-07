# nftables, QoS & Bandwidth Management: A Deep-Dive Reference

> **Scope:** nftables fundamentals, bandwidth-limiting case study (1 Mbit/s per client),
> Evillimiter's ARP-spoof + `tc` approach, and the current state of these utilities on NixOS.

---

## 1. What is nftables?

**nftables** is the modern Linux packet-classification framework that replaced `iptables`, `ip6tables`, `arptables`, and `ebtables` with a single unified tool. It ships inside the kernel's `nf_tables` subsystem and is controlled from userspace by the `nft` binary.

Key facts:

- **Introduced:** Linux 3.13 (2014); declared stable ~4.x; default in most distros by 2020-2022.
- **Userspace tool:** `/usr/sbin/nft` (package `nftables` on most distros).
- **Kernel modules:** `nf_tables`, plus family-specific helpers (`nft_chain_nat`, `nft_limit`, `nft_conntrack`, etc.).
- **Syntax:** a single clean DSL replaces four separate tools and their arcane flag syntax.
- **Atomic rule replacement:** an entire ruleset can be replaced in one kernel syscall, eliminating the partial-state windows that `iptables-restore` suffers from.

---

## 2. Architecture: Tables, Chains, Rules, Sets & Maps

```
┌─────────────────────────────────────────────┐
│  TABLE  (family: ip | ip6 | inet | arp |    │
│          bridge | netdev)                   │
│                                             │
│  ┌────────────────┐  ┌────────────────────┐ │
│  │ CHAIN (base)   │  │ CHAIN (regular)    │ │
│  │ hook + priority│  │ called by jump/goto│ │
│  │                │  │                    │ │
│  │  RULE          │  │  RULE              │ │
│  │  RULE          │  │  RULE              │ │
│  └────────────────┘  └────────────────────┘ │
│                                             │
│  SET  { 10.0.0.1, 10.0.0.2 }              │
│  MAP  { 10.0.0.1 : 1000kbps }             │
└─────────────────────────────────────────────┘
```

### Tables

A **table** is a namespace. You choose the address family it applies to:

| Family   | Handles                                |
|----------|----------------------------------------|
| `ip`     | IPv4 only                              |
| `ip6`    | IPv6 only                              |
| `inet`   | Both IPv4 and IPv6 (most common today) |
| `arp`    | ARP frames                             |
| `bridge` | Bridged Ethernet frames                |
| `netdev` | Device-level ingress/egress (XDP-like) |

### Chains

A **base chain** attaches to a **hook** in the kernel's netfilter path. A **regular chain** is only used when explicitly called via `jump` or `goto`.

Base-chain hooks (for `inet`/`ip`/`ip6`):

```
NIC ─── prerouting ─── routing decision ─── input ─── local process
                    └── forward ──────────── postrouting ─── NIC out
```

Plus the `netdev` family's `ingress` and `egress` hooks (kernel ≥ 5.16 for egress).

Every base chain has a **priority** (integer; lower fires first) and a **default policy** (`accept` or `drop`).

### Rules

Rules match packets with **expressions** and take a **verdict**:

```nft
# Drop TCP traffic to port 22 from 10.0.0.5
table inet filter {
  chain input {
    type filter hook input priority 0; policy accept;
    ip saddr 10.0.0.5 tcp dport 22 drop
  }
}
```

Common match expressions: `ip saddr/daddr`, `tcp/udp dport/sport`, `meta iif/oif`, `ct state`, `ip protocol`, `ether saddr/daddr`, `mark`, `limit`, `quota`.

### Sets and Maps

**Sets** are collections you can match against efficiently (kernel uses hash or rbtree):

```nft
set blocked_hosts {
  type ipv4_addr
  flags interval
  elements = { 10.0.0.1, 10.0.0.5-10.0.0.10 }
}

chain forward {
  ip saddr @blocked_hosts drop
}
```

**Maps** (verdict maps, type maps) associate a key with a value — extremely useful for QoS:

```nft
map rate_limits {
  type ipv4_addr : mark
  elements = {
    10.0.0.10 : 100,   # client A → fwmark 100
    10.0.0.11 : 200    # client B → fwmark 200
  }
}

chain postrouting {
  meta mark set ip saddr map @rate_limits
}
```

---

## 3. nftables vs iptables — Key Differences

| Feature | iptables | nftables |
|---------|----------|----------|
| Protocol coverage | Separate tools: iptables, ip6tables, arptables, ebtables | Single `nft` tool, multiple families |
| Syntax | Per-tool flags (`-j`, `-A`, `-m`) | Unified DSL with readable syntax |
| Atomic updates | No — rule-by-rule, racy | Yes — entire ruleset loaded atomically |
| Sets / dictionaries | ipset (separate kernel module) | Built-in sets and maps |
| Rate limiting | `xt_limit`, `xt_hashlimit` modules | Native `limit` expression |
| Performance | Linear rule scan by default | Hash/rbtree sets for O(1) lookup |
| Traffic shaping (QoS) | Cannot shape; must use `tc` | Cannot shape; must use `tc` |
| Userspace API | Separate `libiptc` | Netlink via `libnftables` |
| Scripting | Shell with iptables calls | Native `nft -f ruleset.nft` |

---

## 4. The Linux Traffic-Control Stack (tc / iproute2)

`tc` (traffic control) is part of `iproute2` and operates at the **network driver queue** level — below netfilter. It handles actual **packet scheduling and shaping**.

The hierarchy:

```
Network Interface
└── qdisc (queuing discipline)   ← root scheduling algorithm
    └── class                    ← sub-queue (in classful qdiscs)
        └── qdisc (leaf)         ← per-class scheduler
            └── filter           ← classifier: which packet → which class
```

### Important qdiscs

| qdisc | Type | Use |
|-------|------|-----|
| `pfifo_fast` | Classless | Kernel default; 3-band priority FIFO |
| `fq_codel` | Classless | Modern default; fair queue + CoDel AQM; great for home use |
| `htb` | Classful | **Hierarchical Token Bucket** — the standard for bandwidth limiting |
| `tbf` | Classless | Token Bucket Filter — simple single-rate limiter |
| `ingress` | Special | Allows attaching filters to *incoming* traffic; used with IFB for ingress shaping |
| `cake` | Classless | Modern all-in-one; excellent for ISP edge shaping |

### HTB (Hierarchical Token Bucket)

HTB is the workhorse for "give client X exactly Y kbit/s":

```
root qdisc (htb)
├── class 1:1  rate 100mbit (total)
│   ├── class 1:10  rate 1000kbit  ceil 1000kbit  ← client A, hard cap
│   ├── class 1:20  rate 1000kbit  ceil 1000kbit  ← client B, hard cap
│   └── class 1:30  rate 1000kbit  ceil 5000kbit  ← client C, burstable
```

- **rate** = guaranteed minimum bandwidth
- **ceil** = maximum bandwidth (hard cap when `ceil == rate`)
- Unused bandwidth from one class can be lent to another (up to `ceil`)

---

## 5. Why nftables Alone Cannot Shape Traffic

This is a critical and commonly misunderstood distinction.

**nftables (netfilter) is a packet *classifier* and *filter*.** It can:
- Accept or drop packets
- Modify packet headers (NAT, DSCP marking, fwmark)
- Count bytes and packets
- Rate-limit (token bucket policing — drops excess, does NOT buffer it)

**nftables cannot:**
- Buffer packets and release them at a controlled rate
- Create per-flow queues
- Implement HTB, TBF, CAKE, or any queuing discipline

The `limit` expression in nftables does **policing** (drops over-limit packets immediately), not **shaping** (buffering them and releasing at the desired rate). Policing causes TCP retransmissions and poor application experience. Shaping is kinder — it delays packets instead.

> **Rule of thumb:**
> Use **nftables** to *classify* and *mark* packets.
> Use **tc** to *shape* and *schedule* them.

The two tools are complementary. The common pattern is:
1. nftables sets `meta mark` (fwmark) on packets belonging to a client.
2. tc `filter` matches on that fwmark and assigns the packet to an HTB class.
3. HTB enforces the rate.

---

## 6. Case Study: 1000 kbit/s Per-Client QoS

### 6.1 Topology & Goal

```
Internet
    │
[Router / Linux box]  ← you control this
    │  eth0 (WAN)     ← upstream
    │  eth1 (LAN)     ← downstream to clients
    │
[Client 10.0.0.10]  ← limit to 1000kbit/s in BOTH directions
[Client 10.0.0.11]  ← no limit (or a different limit)
```

**Goal:** Hard-cap 10.0.0.10 at 1000 kbit/s upload AND 1000 kbit/s download.

- **Upload** (client → internet): traffic egresses `eth0` → shape on `eth0` egress.
- **Download** (internet → client): traffic ingresses `eth0` → shape on `eth0` ingress.

Shaping ingress is the tricky part because the kernel does not buffer incoming traffic at the NIC level. The standard solution is the **IFB (Intermediate Functional Block)** trick: redirect ingress to a virtual IFB device, then apply HTB on the IFB's egress.

---

### 6.2 Download (Ingress) Limiting with IFB + HTB

```bash
# 1. Load IFB module and bring up the virtual device
modprobe ifb
ip link add ifb0 type ifb
ip link set ifb0 up

# 2. Redirect ALL ingress traffic from eth0 → ifb0
tc qdisc add dev eth0 handle ffff: ingress
tc filter add dev eth0 parent ffff: protocol ip u32 match u32 0 0 \
    action mirred egress redirect dev ifb0

# 3. Build HTB on ifb0 (this shapes what appears as ifb0 egress = eth0 ingress)
tc qdisc add dev ifb0 root handle 1: htb default 999

# Root class — ceiling matches your WAN download speed (e.g. 100mbit)
tc class add dev ifb0 parent 1:  classid 1:1   htb rate 100mbit ceil 100mbit

# Limited client class — exactly 1000kbit/s, no borrowing
tc class add dev ifb0 parent 1:1 classid 1:10  htb rate 1000kbit ceil 1000kbit burst 15k

# Default class — full speed for everyone else
tc class add dev ifb0 parent 1:1 classid 1:999 htb rate 99mbit  ceil 100mbit

# Add fq_codel inside each class to prevent bufferbloat
tc qdisc add dev ifb0 parent 1:10  handle 10:  fq_codel
tc qdisc add dev ifb0 parent 1:999 handle 999: fq_codel

# 4. Filter: packets destined to 10.0.0.10 → class 1:10
tc filter add dev ifb0 parent 1: protocol ip prio 1 u32 \
    match ip dst 10.0.0.10/32 flowid 1:10
```

---

### 6.3 Upload (Egress) Limiting with HTB

```bash
# 1. Replace default qdisc on eth0 with HTB
tc qdisc add dev eth0 root handle 1: htb default 999

# Root class — ceiling matches your WAN upload speed (e.g. 50mbit)
tc class add dev eth0 parent 1:  classid 1:1   htb rate 50mbit ceil 50mbit

# Limited client class
tc class add dev eth0 parent 1:1 classid 1:10  htb rate 1000kbit ceil 1000kbit burst 15k

# Default (unlimited) class
tc class add dev eth0 parent 1:1 classid 1:999 htb rate 49mbit ceil 50mbit

# fq_codel in each leaf class
tc qdisc add dev eth0 parent 1:10  handle 10:  fq_codel
tc qdisc add dev eth0 parent 1:999 handle 999: fq_codel

# 2. Filter: packets sourced from 10.0.0.10 → class 1:10
tc filter add dev eth0 parent 1: protocol ip prio 1 u32 \
    match ip src 10.0.0.10/32 flowid 1:10
```

---

### 6.4 Marking Packets with nftables, Shaping with tc

For more complex scenarios — multiple clients, dynamic rules, or matching on ports — use nftables to **mark** packets, then tc **filters on fwmark**:

```nft
# /etc/nftables.conf

table inet qos_marks {

  # Map: client IP → fwmark value
  map client_marks {
    type ipv4_addr : mark
    elements = {
      10.0.0.10 : 0x10,   # decimal 16  → HTB class 1:16
      10.0.0.11 : 0x11,   # decimal 17  → HTB class 1:17
    }
  }

  chain postrouting {
    type route hook postrouting priority mangle; policy accept;
    # Mark egress packets by source IP
    meta mark set ip saddr map @client_marks
  }

  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    # Mark ingress packets by destination IP (for IFB-based ingress shaping)
    meta mark set ip daddr map @client_marks
  }
}
```

Then in tc, match on the fwmark instead of IP:

```bash
# Upload: match fwmark 0x10 → class 1:16
tc filter add dev eth0 parent 1: protocol ip prio 1 handle 0x10 fw flowid 1:16

# Download (via ifb0): match fwmark 0x10 → class 1:16
tc filter add dev ifb0 parent 1: protocol ip prio 1 handle 0x10 fw flowid 1:16
```

This is far more maintainable: to add a new client, add one line to the nftables map and one pair of tc classes/filters.

---

### 6.5 A Full Working Script

```bash
#!/usr/bin/env bash
# qos-limit.sh — limit a single client to 1000kbit/s up and down
# Usage: ./qos-limit.sh <LAN_IFACE> <WAN_IFACE> <CLIENT_IP>
#   e.g: ./qos-limit.sh eth1 eth0 10.0.0.10

set -euo pipefail

LAN="${1}"
WAN="${2}"
CLIENT="${3}"
LIMIT="1000kbit"
WAN_UP="50mbit"    # your actual WAN upload capacity
WAN_DOWN="100mbit" # your actual WAN download capacity

# ── Helper: flush tc on a device ──────────────────────────────────────────────
flush_tc() {
  tc qdisc del dev "$1" root    2>/dev/null || true
  tc qdisc del dev "$1" ingress 2>/dev/null || true
}

# ── 1. IFB for ingress shaping ─────────────────────────────────────────────────
modprobe ifb numifbs=1
ip link add ifb0 type ifb 2>/dev/null || true
ip link set ifb0 up

flush_tc "$WAN"
flush_tc ifb0

# Redirect WAN ingress → ifb0
tc qdisc add dev "$WAN" handle ffff: ingress
tc filter add dev "$WAN" parent ffff: protocol ip u32 match u32 0 0 \
    action mirred egress redirect dev ifb0

# ── 2. Egress (upload) HTB on WAN ─────────────────────────────────────────────
tc qdisc  add dev "$WAN" root       handle 1:   htb default 999
tc class  add dev "$WAN" parent 1:  classid 1:1 htb rate "$WAN_UP" ceil "$WAN_UP"
tc class  add dev "$WAN" parent 1:1 classid 1:10 htb rate "$LIMIT" ceil "$LIMIT" burst 15k
tc class  add dev "$WAN" parent 1:1 classid 1:999 htb rate "$WAN_UP" ceil "$WAN_UP"
tc qdisc  add dev "$WAN" parent 1:10  handle 10:  fq_codel
tc qdisc  add dev "$WAN" parent 1:999 handle 999: fq_codel
tc filter add dev "$WAN" parent 1: protocol ip prio 1 u32 \
    match ip src "${CLIENT}/32" flowid 1:10

# ── 3. Ingress (download) HTB on ifb0 ─────────────────────────────────────────
tc qdisc  add dev ifb0 root       handle 1:   htb default 999
tc class  add dev ifb0 parent 1:  classid 1:1 htb rate "$WAN_DOWN" ceil "$WAN_DOWN"
tc class  add dev ifb0 parent 1:1 classid 1:10 htb rate "$LIMIT" ceil "$LIMIT" burst 15k
tc class  add dev ifb0 parent 1:1 classid 1:999 htb rate "$WAN_DOWN" ceil "$WAN_DOWN"
tc qdisc  add dev ifb0 parent 1:10  handle 10:  fq_codel
tc qdisc  add dev ifb0 parent 1:999 handle 999: fq_codel
tc filter add dev ifb0 parent 1: protocol ip prio 1 u32 \
    match ip dst "${CLIENT}/32" flowid 1:10

echo "✓ ${CLIENT} limited to ${LIMIT} up/down on ${WAN}"
```

To remove the limits:

```bash
tc qdisc del dev eth0 root
tc qdisc del dev eth0 ingress
tc qdisc del dev ifb0 root
ip link del ifb0
```

---

## 7. How Evillimiter Works

Evillimiter is a Python tool that limits the bandwidth of *other* devices on the same LAN — **without having router/switch access**. It achieves this through a combination of ARP spoofing and `tc` traffic shaping.

### 7.1 Step 1 — ARP Spoofing (Scapy)

The fundamental trick: **convince the target device that your machine is the gateway, and convince the gateway that your machine is the target**.

```
Normal:
  Target  ─── ARP: "gateway is AA:BB:CC:DD:EE:FF" ──► Router
  Target sends packets to router's MAC directly.

After ARP spoof:
  Target  ◄── ARP reply: "gateway is YOUR:MAC:HERE" ── Evillimiter
  Router  ◄── ARP reply: "target is YOUR:MAC:HERE"  ── Evillimiter
  Target sends packets to YOUR MAC.
  YOU forward them (or shape them before forwarding).
```

Evillimiter uses **Scapy** to continuously send crafted ARP reply packets (ARP gratuitous/reply) to both the target and the gateway at a regular interval. The interval needs to be short enough that the target's ARP cache does not expire and re-resolve the real MAC.

```python
# Simplified pseudocode of what Evillimiter does under the hood
from scapy.all import ARP, Ether, sendp

def spoof(target_ip, target_mac, gateway_ip, our_mac, iface):
    # Tell the target: "I am the gateway"
    pkt_target = Ether(dst=target_mac) / ARP(
        op=2,                    # ARP reply
        pdst=target_ip,
        hwdst=target_mac,
        psrc=gateway_ip,
        hwsrc=our_mac            # lie: our MAC as gateway MAC
    )
    # Tell the gateway: "I am the target"
    pkt_gateway = Ether(dst=gateway_mac) / ARP(
        op=2,
        pdst=gateway_ip,
        hwdst=gateway_mac,
        psrc=target_ip,
        hwsrc=our_mac
    )
    sendp([pkt_target, pkt_gateway], iface=iface, verbose=False)
```

### 7.2 Step 2 — IP Forwarding

Since traffic from the target now passes through the attacker's machine, the attacker must enable kernel IP forwarding or all packets would be dropped:

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

Evillimiter enables this automatically. Without it, spoofing the target just causes a denial of service (all traffic dropped), which is the `block` command mode.

### 7.3 Step 3 — Traffic Shaping via tc

Once packets are flowing through the attacker's machine, `tc` is used to shape the *forwarded* traffic. Evillimiter shells out to `tc` via Python's `subprocess`:

```bash
# Create root HTB qdisc
tc qdisc add dev eth0 root handle 1: htb

# Per-host class — rate 1000kbit (both rate and ceil for hard cap)
tc class add dev eth0 parent 1: classid 1:<ID> htb rate 1000kbit burst 15k ceil 1000kbit

# Netem for blocking (sets rate to effectively 0)
tc qdisc add dev eth0 parent 1:<ID> handle <ID>: netem

# u32 filter: match traffic FROM this host → this class
tc filter add dev eth0 parent 1:0 protocol ip prio <PRIO> u32 \
    match ip src <HOST_IP>/32 flowid 1:<ID>
```

Each limited host gets its own HTB class ID. The `burst` parameter controls how many bytes can be sent instantaneously before the rate kicks in.

For **download** limiting, the Masrkai fork added nftables-based marking in addition to `tc`, but the core mechanism remains the `tc htb` approach applied to forwarded packets.

### 7.4 The nftables Migration in the Masrkai Fork

The Masrkai fork explicitly migrated from the original's `iptables` flushing to `nftables`. The `-f` / `--flush` flag in the Masrkai version runs:

```bash
nft flush ruleset     # replaces: iptables -F
```

And the fork uses nftables chains for packet marking alongside `tc` for the actual rate enforcement — reflecting the correct division of labor described in §5.

---

## 8. Evillimiter: Evaluation

### 8.1 What the Approach Does Well

**Requires no router access.** This is the core value proposition. You can rate-limit a device on a network you do not administratively control, from any machine on the same LAN segment. Useful for a sysadmin who has physical access but not router credentials.

**Works without kernel modules or router firmware changes.** The entire approach runs in userspace (Scapy) plus standard `tc` commands available on any Linux system.

**Real-time monitoring.** Because all target traffic passes through the attacker's machine, Evillimiter can measure actual bandwidth consumption (using `tc -s class show dev eth0`) and display it in real time.

**Per-host granularity.** Each host gets its own HTB class, so limits are applied individually and independently.

**Automatic discovery.** It scans the LAN with ARP requests and builds a host table automatically.

---

### 8.2 Fundamental Problems

#### Security and Ethics
ARP spoofing is a **man-in-the-middle attack**. Running this tool on a network you do not own or have explicit permission to manage is illegal in most jurisdictions (Computer Fraud and Abuse Act in the US, Computer Misuse Act in the UK, etc.). The tool's own README warns of this.

#### IPv4 Only — A Hard Architectural Limit
ARP is an IPv4 protocol. IPv6 uses **NDP (Neighbor Discovery Protocol)**, which is over ICMPv6 and has different security properties. Evillimiter explicitly documents this limitation: it cannot affect IPv6 traffic at all. A savvy client can simply use an IPv6-only connection to bypass the limit entirely.

#### Bypassed by Static ARP
Any device that has its ARP cache populated with a static, pinned entry for the gateway MAC cannot be spoofed. Most operating systems allow `arp -s <gateway_ip> <real_gateway_mac>` to set a permanent entry.

#### Bypassed by VPN
If the target uses a VPN (WireGuard, OpenVPN, etc.), all traffic is encrypted and destined for the VPN endpoint IP, not the gateway. The traffic still flows through the attacker's machine, but it is indistinguishable from any other encrypted UDP/TCP stream. The **destination IP is the VPN server**, not anything identifying the application traffic, so tc filters still work — but the user experience is that their VPN tunnel itself gets throttled, while any VPN-bypass path is unaffected.

#### Traffic Volume on the Attacker's Machine
Every byte the target sends or receives must pass through the attacker's NIC. If you are limiting ten clients each to 10 Mbit/s, you need 100 Mbit/s of spare NIC capacity on your machine just to carry their traffic. On a gigabit LAN with many clients, this can saturate the attacker's interface and cause packet loss.

#### ARP Spoofing Is Detectable
Many managed switches support **Dynamic ARP Inspection (DAI)** which validates ARP packets against a DHCP snooping table. If the switch has DAI enabled, ARP spoof packets are silently dropped and the attack fails. Intrusion detection systems also commonly alert on ARP spoofing.

#### No IPv6 Rate Limiting
Not just a capability limitation — if the target has both IPv4 and IPv6, traffic may naturally prefer IPv6 (HTTPS, streaming services, etc.), and Evillimiter has zero effect on that traffic.

#### Fragile State Management
If the attacker's machine crashes or the tool exits abnormally without the cleanup routine running, the gateway and target may have stale ARP entries pointing to the attacker's (now non-forwarding) MAC for up to several minutes. This causes a denial of service for the target until ARP caches expire.

#### `tc` Shell Invocations Are Fragile
Evillimiter builds `tc` command strings in Python and calls them via `subprocess.check_call`. If the `tc` binary is not in PATH, if class IDs collide, or if there is an existing qdisc on the interface, the tool fails with cryptic errors (the `qdisc root handle could not be created` issue seen in many GitHub issues).

---

### 8.3 How It Can Be Improved

#### Replace ARP Spoofing with Proper Router Integration
The correct solution for bandwidth management is to run `tc` rules **on the router itself** (or on a dedicated Linux-based gateway). This requires router access but eliminates every problem with ARP spoofing — it works for IPv6, is not detectable, cannot be bypassed by static ARP, and does not burden the attacker's NIC.

```bash
# On the actual router — limit 10.0.0.10 to 1000kbit/s
# No ARP spoofing needed. Works for both IPv4 and IPv6.
tc class add dev eth0 parent 1:1 classid 1:10 htb rate 1000kbit ceil 1000kbit
tc filter add dev eth0 parent 1: protocol ip prio 1 u32 \
    match ip src 10.0.0.10/32 flowid 1:10
```

#### Add IPv6 NDP Spoofing Support
If ARP spoofing must remain the method, the tool should also implement **NDP spoofing** (ICMPv6 Neighbor Advertisement forgery) to intercept IPv6 traffic. Libraries like Scapy support ICMPv6 fully:

```python
from scapy.all import IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, sendp

pkt = Ether(dst=target_mac) / IPv6(dst=target_ipv6) / \
      ICMPv6ND_NA(tgt=gateway_ipv6, R=1, S=1, O=1) / \
      ICMPv6NDOptDstLLAddr(lladdr=our_mac)
```

#### Use netlink Instead of subprocess for tc
Instead of calling the `tc` binary, use Python's `pyroute2` library which speaks netlink natively:

```python
from pyroute2 import IPRoute
ip = IPRoute()
ip.tc("add", "htb", index, 0x10000, default=0x200000)
ip.tc("add-class", "htb", index, 0x10000,
      classid=0x10010, rate=1_000_000, ceil=1_000_000)  # 1000kbit in bit/s
```

This is faster, more reliable, and does not depend on PATH or binary availability.

#### Graceful Cleanup with Signal Handlers and Systemd
Ensure that ARP entries are restored to their correct values even on `SIGKILL` via a watchdog process, not just `SIGTERM`. Alternatively, use a `systemd` service with `ExecStop` that runs the ARP restoration script.

#### Use nftables `limit` for Policing, tc for Shaping
For light-touch rate enforcement where shaping is not required (e.g., blocking a flooding device), nftables policing is simpler and does not require managing qdisc trees:

```nft
chain forward {
  type filter hook forward priority 0; policy accept;
  ip saddr 10.0.0.10 limit rate over 1000 kbytes/second drop
}
```

Note: this **drops** excess packets rather than buffering them (policing, not shaping). For applications where TCP throughput under the limit matters more than perfect rate enforcement, use `tc htb` shaping.

#### Replace `u32` Filters with nftables fwmark + fw Classifier
`u32` filters are brittle and hard to debug. A better architecture:

1. Use nftables to stamp packets with `meta mark` based on source/destination IP (or any complex match).
2. Use `tc filter ... handle <mark> fw` to steer marked packets into HTB classes.
3. This separates classification policy (nftables, expressive) from scheduling mechanism (tc, efficient).

---

## 9. NixOS: Current State of These Utilities

### 9.1 nftables on NixOS

**Status: Fully supported and actively maintained.**

NixOS has had a native `networking.nftables` module since around NixOS 21.05, and as of NixOS 21.11, the default `networking.firewall` module **switched its backend to `nft` (via `iptables-nft`)** even when you have not explicitly enabled nftables. This means that even if you are using `networking.firewall.enable = true` with no nftables options set, the underlying implementation uses `nf_tables` in the kernel.

To use native `nft` syntax (and disable `iptables` shims entirely):

```nix
networking.nftables.enable = true;
```

This:
- Loads `nf_tables` kernel module
- Starts `nftables.service` which loads `/etc/nftables.conf`
- Makes `nft` available in PATH via `pkgs.nftables`
- Disables the `iptables` service

To write custom rules:

```nix
networking.nftables = {
  enable = true;
  ruleset = ''
    table inet filter {
      chain input {
        type filter hook input priority 0; policy drop;
        iif lo accept
        ct state established,related accept
        tcp dport 22 accept
      }
      chain forward {
        type filter hook forward priority 0; policy drop;
      }
      chain output {
        type filter hook output priority 0; policy accept;
      }
    }
  '';
};
```

Or load a file:

```nix
networking.nftables = {
  enable = true;
  rulesetFile = ./nftables.conf;
};
```

**Key behavior:** NixOS's `networking.firewall` and `networking.nftables` coexist. If `networking.nftables.enable = true`, the NixOS-generated firewall rules are written in nft syntax. If only `networking.firewall.enable = true` (the default), NixOS internally uses `iptables-nft` commands that translate to `nf_tables`.

The `nftables` package in nixpkgs is `pkgs.nftables` and is kept reasonably up to date (1.0.x series as of early 2026).

---

### 9.2 iptables / iptables-nft Interop

Since NixOS 21.11, the `iptables` package in nixpkgs is **`iptables-nft`** — the compatibility shim that translates `iptables` commands into `nf_tables` operations. This means:

- `iptables -L` and `nft list ruleset` both show the same underlying rules.
- You **cannot** load both the legacy `ip_tables` kernel module and `nf_tables` simultaneously on the same table. If you try to use the legacy `iptables` binary (compiled against `libiptc`, not `libnftables`) while nftables is active, you get: `Unload ip_tables before using nftables!`

To check which backend is in use:

```bash
iptables --version
# Output like: iptables v1.8.9 (nf_tables)  ← nft backend
# Output like: iptables v1.8.9 (legacy)     ← legacy backend
```

If you need the legacy backend for something (rare), you can add `iptables-legacy` to your environment, but this conflicts with `networking.nftables.enable = true`.

---

### 9.3 iproute2 / tc on NixOS

**Status: Fully functional. No NixOS-specific quirks for normal use.**

`tc` is part of `pkgs.iproute2`, which is available in any NixOS system. Install it in your environment or system packages:

```nix
environment.systemPackages = with pkgs; [ iproute2 ];
```

`tc` commands work identically on NixOS as on any other Linux distribution. The kernel modules for `htb`, `fq_codel`, `netem`, `ingress`, etc. are all compiled in or available as modules in the NixOS kernel configuration.

**IFB module:** Available but must be loaded explicitly:

```nix
boot.kernelModules = [ "ifb" ];
```

Or at runtime: `modprobe ifb numifbs=1`.

To make `tc` rules persistent across reboots, use a `systemd.services` entry:

```nix
systemd.services.tc-qos = {
  description = "Per-client QoS traffic shaping";
  after = [ "network.target" ];
  wantedBy = [ "multi-user.target" ];
  serviceConfig = {
    Type = "oneshot";
    RemainAfterExit = true;
    ExecStart = pkgs.writeShellScript "tc-qos-start" ''
      ${pkgs.iproute2}/bin/tc qdisc add dev eth0 root handle 1: htb default 999
      ${pkgs.iproute2}/bin/tc class add dev eth0 parent 1: classid 1:1 \
          htb rate 50mbit ceil 50mbit
      ${pkgs.iproute2}/bin/tc class add dev eth0 parent 1:1 classid 1:10 \
          htb rate 1000kbit ceil 1000kbit burst 15k
      ${pkgs.iproute2}/bin/tc filter add dev eth0 parent 1: protocol ip prio 1 u32 \
          match ip src 10.0.0.10/32 flowid 1:10
    '';
    ExecStop = pkgs.writeShellScript "tc-qos-stop" ''
      ${pkgs.iproute2}/bin/tc qdisc del dev eth0 root || true
    '';
  };
};
```

---

### 9.4 Running Evillimiter on NixOS

The Masrkai fork provides a `shell.nix` and an `evillimiter.nix` derivation in his NixOS configuration repository. Since it is not in nixpkgs, you use it as a local package or flake input.

**Dependencies (all available in nixpkgs):**
- `python3`
- `python3Packages.scapy`
- `python3Packages.netifaces`
- `python3Packages.netaddr`
- `iproute2` (for `tc`)
- `nftables` (for `nft flush`)

**Practical shell.nix approach:**

```nix
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    python3
    python3Packages.scapy
    python3Packages.netifaces
    python3Packages.netaddr
    iproute2
    nftables
  ];
}
```

Then:

```bash
nix-shell
sudo python3 bin/evillimiter
```

`sudo` (or root) is required because:
1. Scapy needs raw socket access (`CAP_NET_RAW`).
2. `tc` requires `CAP_NET_ADMIN`.
3. `/proc/sys/net/ipv4/ip_forward` write needs elevated privilege.

You can use `security.wrappers` in NixOS to grant specific capabilities rather than running as root if desired.

---

### 9.5 Caveats Specific to NixOS

**`/proc/sys/net/ipv4/ip_forward` may be managed by NixOS:**

NixOS controls IP forwarding through `boot.kernel.sysctl`. If the system is configured as a router/gateway, this is likely already enabled. If not, Evillimiter's attempt to write to `/proc/sys/net/ipv4/ip_forward` still works at runtime even though NixOS does not persistently set it this way.

To set it persistently in NixOS:

```nix
boot.kernel.sysctl."net.ipv4.ip_forward" = 1;
```

**nftables service conflict:**

If `networking.nftables.enable = true` is set and `networking.nftables.rulesetFile` is configured, the `nftables.service` will overwrite `nft flush ruleset` on every restart. Evillimiter's dynamically added nftables rules would be wiped on `systemctl restart nftables`. Keep this in mind if using both.

**Mutable network state vs NixOS immutability:**

NixOS's network configuration is declarative and applied by systemd at boot. `tc` qdisc states are **not preserved across reboots** by any NixOS module (as of early 2026). You must manage persistence yourself via a `systemd.services` entry as shown in §9.3.

Similarly, `ip link` changes (adding `ifb0`) are not persistent unless done in a systemd service or via a NixOS module.

**NetworkManager vs systemd-networkd:**

NixOS supports both. Neither interferes with `tc` rules you apply manually. However, if NetworkManager resets an interface (e.g., on reconnect), the qdisc on that interface may be reset to `pfifo_fast`. Use the `systemd.services` approach with `BindsTo = "network-addresses-eth0.service"` or similar to re-apply rules after network events.

---

## 10. Quick Reference Cheatsheet

### nftables

```bash
# List all rules
nft list ruleset

# Load a ruleset file
nft -f /etc/nftables.conf

# Flush all rules
nft flush ruleset

# Add a rate-limit rule (policing — drops excess)
nft add rule inet filter forward \
    ip saddr 10.0.0.10 limit rate over 1000 kbytes/second drop

# Add a fwmark to packets from a specific host
nft add rule inet mangle postrouting \
    ip saddr 10.0.0.10 meta mark set 0x10

# Monitor events in real time
nft monitor
```

### tc

```bash
# Show qdiscs on an interface
tc qdisc show dev eth0

# Show HTB classes
tc class show dev eth0

# Show filters
tc filter show dev eth0

# Show stats (byte/packet counters per class)
tc -s class show dev eth0

# Delete the root qdisc (removes all children too)
tc qdisc del dev eth0 root

# Add HTB root
tc qdisc add dev eth0 root handle 1: htb default 999

# Add an HTB class at 1000kbit/s hard cap
tc class add dev eth0 parent 1:1 classid 1:10 \
    htb rate 1000kbit ceil 1000kbit burst 15k

# Add a u32 filter matching source IP
tc filter add dev eth0 parent 1: protocol ip prio 1 u32 \
    match ip src 10.0.0.10/32 flowid 1:10

# Add a filter matching fwmark (set by nftables)
tc filter add dev eth0 parent 1: protocol ip prio 1 \
    handle 0x10 fw flowid 1:10
```

### NixOS Quick Options

```nix
# Enable nftables
networking.nftables.enable = true;

# Load iproute2 (tc)
environment.systemPackages = with pkgs; [ iproute2 ];

# Enable IP forwarding
boot.kernel.sysctl."net.ipv4.ip_forward" = 1;

# Load IFB kernel module
boot.kernelModules = [ "ifb" ];
```

---

## Summary

| Tool | Role | NixOS Status |
|------|------|-------------|
| **nftables** | Packet filtering, marking, NAT, policing | Native module, `networking.nftables.enable` |
| **iptables** | Legacy; maps to nf_tables via `iptables-nft` | Available; backend is nft since NixOS 21.11 |
| **tc / iproute2** | Traffic shaping (HTB, CAKE, fq_codel) | Fully functional via `pkgs.iproute2` |
| **IFB** | Ingress shaping trick | Available, needs `boot.kernelModules = ["ifb"]` |
| **Evillimiter** | ARP-spoof + tc; LAN-level limiter | Not in nixpkgs; manual or flake install |

**The correct architecture for production QoS** is always:
1. **Mark** packets with nftables (`meta mark set`)
2. **Shape** them with `tc htb` on the router's interfaces
3. Persist rules via `systemd.services` on NixOS
4. Avoid ARP spoofing approaches for anything you control at the infrastructure level

ARP spoofing tools like Evillimiter remain useful for **diagnostic and auditing purposes on networks you own**, but they are fundamentally limited to IPv4, detectable, and fragile compared to running QoS at the actual gateway.