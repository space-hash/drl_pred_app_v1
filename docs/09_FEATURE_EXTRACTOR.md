# CIC Feature Extractor — PCAP to Feature CSV

**File:** `capapp/processing/feature_extractor/cic_extractor.py` (430 lines)

## Overview

The CIC Feature Extractor reads `.pcap` files and extracts 84 CICFlowMeter-style features per network flow, outputting CSV files compatible with the DRL prediction pipeline.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                   CICFeatureExtractor                         │
│                                                               │
│  FEATURE_NAMES: List[str]  # 84 feature column names          │
│  executor: ThreadPoolExecutor  # Parallel PCAP processing     │
│                                                               │
│  process_pcap(pcap_path) → (bool, Path)                       │
│  ├── _process_pcap_task(pcap_path) → List[Dict]               │
│  │   ├── rdpcap(pcap_path)  # Load all packets                │
│  │   ├── For each packet:                                     │
│  │   │   ├── _get_flow_key(packet) → canonical tuple          │
│  │   │   ├── Check flow expiry (120s inactive / 120s total)   │
│  │   │   ├── If expired → move to completed_flows             │
│  │   │   └── Add packet to active_flows[flow_key]             │
│  │   └── Return [flow.get_features(FEATURE_NAMES) for flow]   │
│  │                                                            │
│  └── Write CSV with DictWriter                                  │
│      └── Output: processed_features/B_..._features.csv         │
└──────────────────────────────────────────────────────────────┘
```

## Flow Tracking (_Flow class)

Internal class that tracks a single bidirectional flow:

```python
class _Flow:
    # Flow identification (canonical ordering)
    src_ip, dst_ip, src_port, dst_port, proto
    is_ipv6: bool

    # Timing (nanosecond precision)
    start_time_ns, last_seen_ns

    # Directional packet storage
    fwd_packets: List[Packet]  # src→dst
    bwd_packets: List[Packet]  # dst→src

    # Directional flag counters
    fwd_flags: defaultdict(int)  # FIN, SYN, RST, PSH, ACK, URG, ECE, CWR
    bwd_flags: defaultdict(int)

    # Bulk transfer tracking
    fwd_bulk_size, fwd_bulk_packets  # PSH-flagged packets
    bwd_bulk_size, bwd_bulk_packets

    # TCP state
    fwd_init_win, bwd_init_win  # SYN packet window sizes
    min_fwd_seg_size: float

    add_packet(packet, packet_time_ns)
    # Determines direction by matching (src_ip, src_port)
    # Updates appropriate directional counters
```

### Direction Determination

```python
def add_packet(packet, packet_time_ns):
    current_sport = packet.sport if TCP/UDP else 0
    is_forward = (
        packet.src_ip == self.src_ip
        and current_sport == self.src_port
    )
    # First packet defines the flow direction
    # Subsequent packets matched against it
```

## Feature Extraction (84 Features)

The `get_features()` method extracts these features per flow:

| # | Feature Name | Calculation |
|---|-------------|-------------|
| 1 | Flow ID | `src_ip:src_port-dst_ip:dst_port` |
| 2 | Src IP | Source IP address |
| 3 | Src Port | Source port number |
| 4 | Dst IP | Destination IP address |
| 5 | Dst Port | Destination port number |
| 6 | Protocol | IP protocol number (6=TCP, 17=UDP, 1=ICMP) |
| 7 | Timestamp | ISO format of flow start time |
| 8 | Flow Duration | `(last_seen - start_time) / 1000` (microseconds) |
| 9 | Total Fwd Packets | `len(fwd_packets)` |
| 10 | Total Bwd Packets | `len(bwd_packets)` |
| 11 | Total Length of Fwd Packets | `sum(len(p) for p in fwd_packets)` |
| 12 | Total Length of Bwd Packets | `sum(len(p) for p in bwd_packets)` |
| 13-16 | Fwd Packet Length Max/Min/Mean/Std | Statistics of fwd packet sizes |
| 17-20 | Bwd Packet Length Max/Min/Mean/Std | Statistics of bwd packet sizes |
| 21 | Flow Bytes/s | `total_bytes / (duration_us / 1e6)` |
| 22 | Flow Packets/s | `total_packets / (duration_us / 1e6)` |
| 23-26 | Flow IAT Mean/Std/Max/Min | Inter-arrival time stats (all packets) |
| 27-31 | Fwd IAT Total/Mean/Std/Max/Min | Forward IAT stats |
| 32-36 | Bwd IAT Total/Mean/Std/Max/Min | Backward IAT stats |
| 37 | Fwd PSH Flags | Count of PSH flags in forward direction |
| 38 | Bwd PSH Flags | Count of PSH flags in backward direction |
| 39 | Fwd URG Flags | Count of URG flags in forward direction |
| 40 | Bwd URG Flags | Count of URG flags in backward direction |
| 41 | Fwd Header Length | Sum of IP header lengths (forward) |
| 42 | Bwd Header Length | Sum of IP header lengths (backward) |
| 43 | Fwd Packets/s | `fwd_packets / (duration_us / 1e6)` |
| 44 | Bwd Packets/s | `bwd_packets / (duration_us / 1e6)` |
| 45-49 | Min/Max/Mean/Std/Variance Packet Length | Overall packet size stats |
| 50-57 | FIN/SYN/RST/PSH/ACK/URG/CWE/ECE Flag Count | Total flag counts (both directions) |
| 58 | Down/Up Ratio | `bwd_packets / fwd_packets` |
| 59 | Average Packet Size | Mean of all packet lengths |
| 60 | Avg Fwd Segment Size | Mean of forward packet lengths |
| 61 | Avg Bwd Segment Size | Mean of backward packet lengths |
| 62 | Fwd Header Length.1 | Duplicate of Fwd Header Length |
| 63 | Fwd Avg Bytes/Bulk | `fwd_bulk_size / fwd_bulk_packets` |
| 64 | Fwd Avg Packets/Bulk | `fwd_bulk_packets / fwd_packets` |
| 65 | Fwd Avg Bulk Rate | `fwd_bulk_size / duration_sec` |
| 66 | Bwd Avg Bytes/Bulk | `bwd_bulk_size / bwd_bulk_packets` |
| 67 | Bwd Avg Packets/Bulk | `bwd_bulk_packets / bwd_packets` |
| 68 | Bwd Avg Bulk Rate | `bwd_bulk_size / duration_sec` |
| 69 | Subflow Fwd Packets | Forward packets in current subflow |
| 70 | Subflow Fwd Bytes | Forward bytes in current subflow |
| 71 | Subflow Bwd Packets | Backward packets in current subflow |
| 72 | Subflow Bwd Bytes | Backward bytes in current subflow |
| 73 | Init_Win_bytes_forward | Forward SYN window size |
| 74 | Init_Win_bytes_backward | Backward SYN window size |
| 75 | act_data_pkt_fwd | Forward packets with TCP payload |
| 76 | min_seg_size_forward | Minimum forward segment size |
| 77-80 | Active Mean/Std/Max/Min | Active period stats (IAT < 1s) |
| 81-84 | Idle Mean/Std/Max/Min | Idle period stats (IAT >= 1s) |

## Flow Expiry

Two timeout thresholds control flow lifecycle:

| Timeout | Value | Purpose |
|---------|-------|---------|
| `INACTIVE_TIMEOUT` | 5 seconds | Flow expires if no packets for 5s |
| `ACTIVE_TIMEOUT` | 120 seconds | Flow expires after 120s total duration |

During packet processing, expired flows are moved to `completed_flows`:

```python
expired_keys = [
    key for key, flow in active_flows.items()
    if (packet_time_ns - flow.last_seen_ns > INACTIVE_TIMEOUT
        or packet_time_ns - flow.start_time_ns > ACTIVE_TIMEOUT)
]
for key in expired_keys:
    completed_flows.append(active_flows.pop(key))
```

## Canonical Flow Key

Flow keys use canonical ordering to ensure bidirectional packets map to the same flow:

```python
def _get_flow_key(packet):
    # (src_ip, sport, dst_ip, dport, proto)
    if (src_ip, sport) > (dst_ip, dport):
        return (dst_ip, dport, src_ip, sport, proto)  # Swap
    return (src_ip, sport, dst_ip, dport, proto)
```

## Output Format

CSV files are written to `features_output/` with the naming convention:

```
B_20260519_143025_123456_features.csv
```

Each row represents one network flow with all 84 feature columns.

## Threading

Feature extraction runs in a `ThreadPoolExecutor` with configurable workers:

```python
executor = ThreadPoolExecutor(
    max_workers=config.MAX_PROCESSING_WORKERS,  # Default: CPU count
    thread_name_prefix="CICExtractorWorker"
)

future = executor.submit(self._process_pcap_task, pcap_path)
flow_features = future.result(timeout=config.PROCESSING_TIMEOUT_SECONDS)  # 300s
```
