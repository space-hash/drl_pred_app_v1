# Mitigation Agent — Rate-Based & ML-Based IP Blocking

**File:** `core/mitigation_agent.py` (504 lines)

## Overview

The Mitigation Agent provides three layers of IP blocking:
1. **Rate-based auto-blocking**: Blocks IPs exceeding N packets per minute
2. **ML-based auto-blocking**: Blocks IPs after N DDoS detections with high confidence
3. **Multi-vector DDoS detection**: Detects SYN/UDP/ICMP/HTTP flood attacks

All blocking is enforced via iptables for actual packet dropping at the OS level.

## Class Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MitigationAgent                           │
│                                                              │
│  ┌──────────────────┐  ┌──────────────────┐                 │
│  │ FirewallManager  │  │MultiVectorDetector│                 │
│  │ (static methods) │  │                  │                 │
│  │                  │  │ SYN flood        │                 │
│  │ block_ip()       │  │ UDP flood        │                 │
│  │ unblock_ip()     │  │ ICMP flood       │                 │
│  │ init_firewall()  │  │ HTTP flood       │                 │
│  │ flush_rules()    │  │                  │                 │
│  └──────────────────┘  └──────────────────┘                 │
│                                                              │
│  Configuration:                                              │
│  ├── auto_block: bool                                        │
│  ├── rate_limit_enabled: bool                                │
│  ├── rate_limit_ppm: int (default 100)                       │
│  ├── ml_auto_block: bool                                     │
│  ├── confidence_threshold: float (default 0.8)              │
│  ├── detection_count: int (default 3)                        │
│  ├── block_duration: timedelta (default 60 min)              │
│  └── use_iptables: bool                                      │
│                                                              │
│  State:                                                      │
│  ├── _blocked_ips: Dict[ip → {expiry, reason, timestamp}]    │
│  ├── _whitelist: Set[ip]                                     │
│  ├── _blacklist: Set[ip]                                     │
│  ├── _detection_counts: Dict[ip → count]                     │
│  ├── _packet_counts: Dict[ip → List[datetime]]               │
│  └── _log: List[Dict]                                        │
└─────────────────────────────────────────────────────────────┘
```

## FirewallManager

Static utility class for iptables/ip6tables rule management:

```python
class FirewallManager:
    @staticmethod
    def _is_ipv6(ip: str) -> bool
        # Returns True for IPv6 addresses

    @staticmethod
    def block_ip(ip: str, chain: str = "DDOS_BLOCK") -> bool
        # Adds iptables DROP rule: iptables -A DDOS_BLOCK -s <ip> -j DROP
        # Checks if rule already exists before adding (-C check)
        # Handles both IPv4 (iptables) and IPv6 (ip6tables)

    @staticmethod
    def unblock_ip(ip: str, chain: str = "DDOS_BLOCK") -> bool
        # Removes iptables DROP rule: iptables -D DDOS_BLOCK -s <ip> -j DROP

    @staticmethod
    def init_firewall() -> bool
        # Creates custom chain: iptables -N DDOS_BLOCK
        # Links to INPUT: iptables -I INPUT -j DDOS_BLOCK
        # Does the same for ip6tables

    @staticmethod
    def flush_rules() -> bool
        # Flushes all rules in DDOS_BLOCK chain
```

## MultiVectorDetector

Real-time DDoS attack vector detection:

```python
class MultiVectorDetector:
    # Thresholds (per minute):
    syn_threshold = 100      # SYN packets without ACK
    udp_threshold = 200      # UDP packets
    icmp_threshold = 50      # ICMP packets
    http_threshold = 300     # HTTP requests (port 80/443/8080)

    def on_packet(src_ip, protocol, dst_port=0, flags=0) -> Optional[str]:
        """
        Analyzes each packet and returns attack type if threshold exceeded.

        Detection logic:
        ├── SYN flood: protocol==6 (TCP) AND SYN flag set AND no ACK flag
        ├── UDP flood: protocol==17 (UDP)
        ├── ICMP flood: protocol==1 (ICMP)
        └── HTTP flood: protocol==6 (TCP) AND dst_port in (80, 443, 8080)

        Counters reset every 60 seconds.
        Returns: "SYN flood (N SYN/min)" or None
        """
```

## MitigationAgent — Core Logic

### Packet Processing Flow

```
on_packet(src_ip)  # Called for EVERY captured packet
│
├── Check: auto_block AND rate_limit_enabled?
├── Check: src_ip not in whitelist?
├── Check: src_ip not already blocked?
├── Check: src_ip in blacklist? → _do_block() immediately
│
├── Update sliding window:
│   └── Remove timestamps older than 1 minute
│   └── Add current timestamp
│
├── Check: len(timestamps) > rate_limit_ppm?
│   └── YES → _do_block(src_ip, "Rate limit: N packets/min")
│
└── Return: blocked IP or None
```

### ML Detection Processing Flow

```
on_detection(detection)  # Called after PPO inference
│
├── Extract: src_ip, status, confidence
├── Check: not in whitelist, not already blocked
├── Check: in blacklist? → _do_block() immediately
│
├── If ml_auto_block enabled:
│   └── Increment detection counter for src_ip
│   └── Check: count >= detection_count AND confidence >= threshold?
│       └── YES → _do_block(src_ip, "ML auto-block: DDoS (conf=X.XX)")
│
└── Return: blocked IP or None
```

### Vector Analysis Flow

```
on_packet_vector(src_ip, protocol, dst_port, flags)
│
├── Forward to MultiVectorDetector.on_packet()
├── If attack type detected:
│   └── _do_block(src_ip, "Multi-vector: SYN flood (N SYN/min)")
│
└── Return: attack type string or None
```

### Blocking Action

```
_do_block(ip, reason)
│
├── Calculate expiry = now + block_duration
├── Store in _blocked_ips[ip] = {expiry, reason, timestamp}
├── Append to _log
├── Log warning
│
├── If use_iptables:
│   └── FirewallManager.block_ip(ip)  # Actual kernel-level drop
│
└── _save_blocks()  # Persist to data/blocked_ips.json (batched, 5s delay)
```

### Persistence

- **Save**: Batched with 5-second debounce timer to avoid excessive disk I/O
- **Restore**: On startup, reads `data/blocked_ips.json`, re-applies iptables rules for non-expired entries
- **Cleanup**: `cleanup_expired()` removes expired blocks from memory and iptables

### Whitelist & Blacklist

| List | Behavior |
|------|----------|
| **Whitelist** | IPs that are NEVER blocked. Auto-populated with localhost (127.0.0.1, ::1) and local machine IPs |
| **Blacklist** | IPs that are ALWAYS blocked immediately on any detection |

### Configuration API

| Method | Effect |
|--------|--------|
| `set_enabled(bool)` | Toggles all blocking modes |
| `set_auto_block(bool)` | Toggles rate-based blocking |
| `set_ml_auto_block(bool)` | Toggles ML-based blocking |
| `set_rate_limit_ppm(int)` | Sets packets/minute threshold (min: 10) |
| `set_confidence(float)` | Sets ML confidence threshold (0.0-1.0) |
| `set_detection_count(int)` | Sets required detections before block (min: 1) |
| `set_block_duration(int)` | Sets block duration in minutes (min: 1) |
| `clear_detection_counts()` | Resets all per-IP detection counters |

### Status Output

```python
get_status() → {
    "enabled": bool,
    "auto_block": bool,
    "rate_limit_enabled": bool,
    "rate_limit_ppm": int,
    "ml_auto_block": bool,
    "confidence_threshold": float,
    "detection_count": int,
    "block_duration_min": int,
    "blocked_ips": [{"ip": str, "reason": str, "remaining_min": int}],
    "total_blocked": int,
    "whitelist": [str],
    "blacklist": [str],
    "detection_counts": {ip: count},
    "packet_rates": {ip: ppm},
    "vector_stats": {
        "syn_flood_ips": int,
        "udp_flood_ips": int,
        "icmp_flood_ips": int,
        "http_flood_ips": int,
    },
    "log": [last 50 entries],
    "use_iptables": bool,
}
```
