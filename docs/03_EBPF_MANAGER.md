# eBPF/XDP Manager — Kernel-Level Packet Filtering

**File:** `core/ebpf_manager.py` (390 lines)

## Overview

The eBPF Manager provides **line-rate packet filtering** using Linux eBPF/XDP (Express Data Path) technology. XDP programs run at the earliest point in the network stack — before the kernel allocates socket buffers — enabling millions of packets per second to be dropped with minimal CPU overhead.

If eBPF is unavailable (missing BCC library or kernel support), it automatically falls back to iptables.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                       EbpfManager                             │
│                                                               │
│  ┌─────────────────────┐    ┌─────────────────────────────┐  │
│  │    XDPProgram        │    │   Fallback: FirewallManager │  │
│  │                      │    │   (iptables)                │  │
│  │  XDP_CODE (C/BPF)   │    │                             │  │
│  │  load()             │    │  Used when:                 │  │
│  │  unload()           │    │  - BCC library missing      │  │
│  │  block_ip()         │    │  - XDP program fails to load│  │
│  │  unblock_ip()       │    │  - Interface not specified  │  │
│  │  get_stats()        │    │                             │  │
│  └─────────────────────┘    └─────────────────────────────┘  │
│                                                               │
│  State:                                                       │
│  ├── xdp_program: XDPProgram or None                          │
│  ├── use_iptables_fallback: bool                              │
│  ├── _blocked_ips: Dict[ip → {reason, timestamp}]             │
│  ├── _stats: {packets_dropped, bytes_dropped,                 │
│  │            blocks_added, blocks_removed}                   │
│  └── _whitelist: Set[ip] (localhost + local IPs)              │
└──────────────────────────────────────────────────────────────┘
```

## XDP Program (C/BPF Code)

The embedded XDP program is written in C and compiled by BCC at runtime:

```c
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>

// BPF maps (hash tables shared between kernel and user space)
BPF_HASH(blocked_ipv4, u32, u8);        // IPv4 → blocked flag
BPF_HASH(blocked_ipv6, struct in6_addr, u8);  // IPv6 → blocked flag
BPF_HASH(stats, u32, u64);              // Drop counter

int xdp_drop_blocked(struct xdp_md *ctx) {
    // Parse Ethernet header
    struct ethhdr *eth = data;

    // IPv4 path
    if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *iph = data + sizeof(*eth);
        u32 src_ip = iph->saddr;
        if (is_blocked_ipv4(src_ip)) {
            increment_drop_stats();
            return XDP_DROP;  // Drop at NIC level
        }
    }

    // IPv6 path
    if (eth->h_proto == htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = data + sizeof(*eth);
        if (is_blocked_ipv6(&src_ip6)) {
            increment_drop_stats();
            return XDP_DROP;
        }
    }

    return XDP_PASS;  // Allow all other traffic
}
```

### XDP Return Values

| Value | Behavior |
|-------|----------|
| `XDP_DROP` | Packet is dropped immediately at NIC level (fastest) |
| `XDP_PASS` | Packet continues through normal kernel network stack |

## Initialization Flow

```
EbpfManager.initialize()
│
├── if use_xdp AND BCC_AVAILABLE:
│   ├── xdp_program = XDPProgram(interface)
│   ├── xdp_program.load()
│   │   ├── BPF(text=XDP_CODE)  # Compile C to BPF bytecode
│   │   ├── load_func("xdp_drop_blocked", BPF.XDP)
│   │   └── attach_xdp(interface, fn, 0)  # Attach to NIC
│   ├── _restore_blocks()  # Re-apply saved blocks
│   └── return True
│
├── if fallback_to_iptables:
│   ├── use_iptables_fallback = True
│   ├── FirewallManager.init_firewall()
│   ├── _restore_blocks()
│   └── return True
│
└── return False  # No filtering method available
```

## Block/Unblock Flow

```
block_ip(ip, reason)
│
├── Check whitelist → return False if whitelisted
│
├── Try XDP first (if attached):
│   └── xdp_program.block_ip(ip)
│       ├── IPv4: blocked_ipv4[ip_int] = 1
│       └── IPv6: blocked_ipv6[ip_bytes] = 1
│
├── If XDP fails → try iptables fallback:
│   └── FirewallManager.block_ip(ip)
│
├── Record in _blocked_ips[ip] = {reason, timestamp}
├── Increment stats.blocks_added
├── _save_blocks() → data/ebpf_blocked_ips.json
│
└── return True/False
```

## Statistics

```python
get_stats() → {
    "packets_dropped": int,        # Total from XDP map
    "bytes_dropped": int,          # Approximate (packets × 1500 MTU)
    "blocks_added": int,           # Lifetime blocks added
    "blocks_removed": int,         # Lifetime blocks removed
    "xdp_packets_dropped": int,    # From XDP stats map
    "xdp_bytes_dropped": int,
    "use_xdp": bool,               # Is XDP active?
    "use_iptables_fallback": bool, # Using iptables fallback?
    "interface": str,              # Network interface name
    "bcc_available": bool,         # Is BCC library available?
}
```

## Dependencies

| Dependency | Required For | Fallback |
|-----------|-------------|----------|
| `bcc` Python library | XDP program loading | iptables |
| `pyroute2` | Advanced XDP management | Not used (optional) |
| Root privileges | XDP attachment | iptables (also needs root) |
| Kernel ≥ 4.8 | XDP support | iptables |

## Shutdown

```
shutdown()
│
├── if xdp_program:
│   └── xdp_program.unload()
│       └── bpf.remove_xdp(interface, 0)  # Detach from NIC
│
└── Log "eBPF/XDP manager shut down"
```

## Key Advantages of XDP

1. **Line-Rate**: Drops packets at the NIC driver level, before kernel networking overhead
2. **Zero Socket Allocation**: No socket buffer allocation for dropped packets
3. **Low Latency**: Sub-microsecond decision time per packet
4. **CPU Efficient**: Can handle millions of packets per second on a single core
5. **eBPF Safety**: Verified by kernel eBPF verifier (no crashes possible)
