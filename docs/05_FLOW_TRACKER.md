# Flow Tracker — Real-Time CICFlowMeter Feature Extraction

**File:** `core/flow_tracker.py` (538 lines)

## Overview

The Flow Tracker is the bridge between raw network packets and the DRL model. It tracks active bidirectional network flows in real-time and computes incremental 81-dimensional CICFlowMeter-style feature vectors that match the trained DRL model's expected input format.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                       FlowTracker                             │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                    _flows: Dict                          │ │
│  │  flow_key → FlowRecord                                   │ │
│  │  (src_ip, dst_ip, src_port, dst_port, protocol)          │ │
│  │                                                          │ │
│  │  Max flows: 10,000                                       │ │
│  │  Timeout: 120 seconds                                    │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
│  update() → flow_key or None                                  │
│  get_features(flow_key) → List[float] (81 dims)               │
│  cleanup_expired() → int                                      │
│  get_active_flows() → int                                     │
│  get_stats() → Dict                                           │
└──────────────────────────────────────────────────────────────┘
```

## FlowRecord — Per-Flow State

Each `FlowRecord` tracks a single bidirectional network flow:

```python
class FlowRecord:
    # Flow identification
    src_ip, dst_ip, src_port, dst_port, protocol

    # Timing
    start_time, last_seen, duration

    # Packet counts (forward = src→dst, backward = dst→src)
    fwd_packets, bwd_packets

    # Byte counts
    fwd_bytes, bwd_bytes

    # Packet lengths (all packets + per direction)
    packet_lengths: List[int]
    fwd_packet_lengths: List[int]
    bwd_packet_lengths: List[int]

    # Inter-arrival times (IAT) in seconds
    flow_iats: List[float]     # All packets
    fwd_iats: List[float]      # Forward direction only
    bwd_iats: List[float]      # Backward direction only

    # TCP flags (8 flag types)
    fin_count, syn_count, rst_count, psh_count,
    ack_count, urg_count, cwe_count, ece_count

    # TCP header info
    fwd_header_length, bwd_header_length
    fwd_init_win, bwd_init_win, fwd_min_seg_size

    # Active/Idle tracking
    active_periods: List[float]
    idle_periods: List[float]

    # Subflow tracking (5-second windows)
    subflow_fwd_packets, subflow_fwd_bytes
    subflow_bwd_packets, subflow_bwd_bytes

    # Bulk transfer tracking
    fwd_bulk_packets, fwd_bulk_bytes
    bwd_bulk_packets, bwd_bulk_bytes

    # PSH/URG per direction
    fwd_psh_flags, bwd_psh_flags
    fwd_urg_flags, bwd_urg_flags

    # Inference tracking
    inference_count: int
```

## Update Flow

```
update(src_ip, dst_ip, src_port, dst_port, protocol,
       packet_length, timestamp, tcp_flags, ...)
│
├── Create flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
│
├── If flow_key not in _flows:
│   ├── If len(_flows) >= max_flows (10,000):
│   │   ├── _evict_expired()  # Remove timed-out flows
│   │   └── If still full → evict oldest flow (by last_seen)
│   │
│   └── Create new FlowRecord
│
├── flow.update(packet_length, is_forward, timestamp, ...)
│   ├── Update packet/byte counts
│   ├── Update packet length lists
│   ├── Update IAT lists
│   ├── Update TCP flag counters
│   ├── Update subflow counters (5-second windows)
│   └── Update active/idle periods (1-second threshold)
│
├── if flow.should_trigger_inference():
│   ├── total_packets >= MIN_PACKETS_FOR_INFERENCE (3)
│   └── total_packets % INFERENCE_INTERVAL (5) == 0
│   │
│   ├── flow.mark_inference()
│   ├── stats.inferences_triggered += 1
│   └── return flow_key  # Signal to call DRL inference
│
└── return None  # No inference needed yet
```

## 81-Dimensional Feature Vector

The `_compute_features()` method produces exactly 81 features:

| Index Range | Feature Category | Count |
|------------|-----------------|-------|
| 1-5 | Flow identifiers (src_ip, src_port, dst_ip, dst_port, protocol) | 5 |
| 6 | Flow Duration (microseconds) | 1 |
| 7-8 | Total Fwd/Bwd Packets | 2 |
| 9-10 | Total Fwd/Bwd Bytes | 2 |
| 11-14 | Fwd Packet Length (max, min, mean, std) | 4 |
| 15-18 | Bwd Packet Length (max, min, mean, std) | 4 |
| 19-20 | Flow Bytes/s, Flow Packets/s | 2 |
| 21-24 | Flow IAT (mean, std, max, min) | 4 |
| 25-29 | Fwd IAT (total, mean, std, max, min) | 5 |
| 30-34 | Bwd IAT (total, mean, std, max, min) | 5 |
| 35-38 | PSH/URG flags (fwd_psh, bwd_psh, fwd_urg, bwd_urg) | 4 |
| 39-40 | Header lengths (fwd, bwd) | 2 |
| 41-42 | Directional rates (fwd_pkts/s, bwd_pkts/s) | 2 |
| 43-47 | Overall packet length (min, max, mean, std, variance) | 5 |
| 48-55 | Flag counts (FIN, SYN, RST, PSH, ACK, URG, CWE, ECE) | 8 |
| 56 | Down/Up Ratio | 1 |
| 57-59 | Average sizes (overall, fwd, bwd) | 3 |
| 60-65 | Bulk transfer stats (avg bytes/packets/rate × 2 directions) | 6 |
| 66-69 | Subflow stats (fwd/bwd packets/bytes) | 4 |
| 70-73 | TCP window/segment (fwd_init_win, bwd_init_win, act_data_pkt_fwd, min_seg_size) | 4 |
| 74-81 | Active/Idle stats (mean, std, max, min × 2) | 8 |
| **Total** | | **81** |

## Memory Management

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `FLOW_TIMEOUT_SECONDS` | 120 | Expire flows after 2 minutes of inactivity |
| `MAX_FLOWS` | 10,000 | Maximum concurrent flows tracked |
| `MIN_PACKETS_FOR_INFERENCE` | 3 | Minimum packets before first inference |
| `INFERENCE_INTERVAL` | 5 | Trigger inference every 5 packets per flow |

### Eviction Strategy

```
_evict_expired()
│
├── Find all flows where (now - last_seen) > FLOW_TIMEOUT_SECONDS
├── Delete expired flows from _flows dict
├── Increment stats.expired_flows
│
└── If still over MAX_FLOWS after expiry:
    └── Evict oldest flow (minimum last_seen timestamp)
```

## Flow Direction Detection

The FlowTracker uses a `_seen_flows` set in the `PacketCapturer` to determine packet direction:

```python
flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
is_forward = flow_key not in self._seen_flows

if is_forward:
    self._seen_flows.add(flow_key)
    # Also add reverse key to avoid duplicate tracking
    self._seen_flows.add((dst_ip, src_ip, dst_port, src_port, protocol))
```

This ensures that the first packet of a flow is always treated as "forward" and subsequent packets in either direction are correctly classified.

## Statistics

```python
get_stats() → {
    "total_flows_seen": int,      # Lifetime flow count
    "active_flows": int,          # Currently tracked flows
    "expired_flows": int,         # Flows removed due to timeout
    "evicted_flows": int,         # Flows removed due to memory limit
    "inferences_triggered": int,  # Total DRL inference calls
}
```

## Helper Methods

| Method | Purpose |
|--------|---------|
| `_ip_to_int(ip)` | Convert IPv4 to integer (IPv6 uses hash) |
| `_mean(values)` | Calculate mean (returns 0.0 for empty) |
| `_std(values)` | Calculate sample standard deviation |
| `_variance(values)` | Calculate sample variance |
