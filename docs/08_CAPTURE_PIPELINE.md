# Capture Pipeline — Packet Capture & PCAP Rotation

**Files:**
- `capapp/orchestration/pipeline.py` (54 lines)
- `capapp/capture/packet_capture.py` (265 lines)
- `capapp/processing/dispatcher.py` (81 lines)
- `capapp/storage/file_manager.py` (43 lines)
- `capapp/utils/logger.py` (36 lines)
- `capapp/main.py` (34 lines)

## Overview

The capture application (`capapp`) is a disk-based pipeline that captures live network traffic, rotates it into `.pcap` files, and dispatches them for feature extraction. It can run standalone (`capapp/main.py`) or as part of the full Flask-controlled pipeline.

## Pipeline Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      DDoSPipeline                             │
│                     (orchestration/pipeline.py)                │
│                                                               │
│  Components:                                                  │
│  ├── PacketCapturer (capture/packet_capture.py)               │
│  └── FileDispatcher (processing/dispatcher.py)                │
│                                                               │
│  Lifecycle:                                                   │
│  ├── start() → component.start() for each                     │
│  ├── run() → start() + while not shutdown: sleep(1)           │
│  └── stop() → component.stop() in reverse order               │
└──────────────────────────────────────────────────────────────┘
```

## PacketCapturer

### Thread Architecture

```
PacketCapturer.start()
│
├── Thread 1: "RotationManager"
│   └── _rotation_manager()
│       ├── Every 1 second: check rotation conditions
│       ├── Time-based: elapsed >= ROTATE_INTERVAL_SECONDS (5s)
│       ├── Size-based: total_bytes >= ROTATE_MAX_SIZE_MB (50MB)
│       └── When triggered:
│           ├── Copy packets list
│           ├── Clear packets list
│           ├── Generate new filepath
│           └── Submit _write_file() to ThreadPoolExecutor
│
├── Thread 2: "PacketSniffer"
│   └── _run_sniffer()
│       └── Loop: sniff(iface, prn=_packet_handler, timeout=5)
│           └── Restarts sniffer on timeout (graceful shutdown check)
│
└── ThreadPoolExecutor: "PCAPWriter" (max 2 workers)
    └── _write_file(packets, filepath)
        ├── Write to .pcap.tmp (atomic write)
        └── Rename .pcap.tmp → .pcap (atomic rename)
```

### Packet Handler

```
_packet_handler(packet)  # Called by Scapy for each captured packet
│
├── Append to in-memory packets list (max 100,000)
│   └── Ring buffer: pop(0) if full, then append
│
├── Extract packet metadata:
│   ├── IP layer: src_ip, dst_ip, protocol
│   ├── IPv6 layer: src_ip, dst_ip, nh (next header)
│   ├── TCP layer: sport, dport, flags, header_len, window
│   └── UDP layer: sport, dport
│
├── Feed to FlowTracker (if available):
│   ├── Determine flow direction (first-seen tracking)
│   ├── flow_tracker.update(...) → triggered_key or None
│   └── If triggered: drl_mitigation.on_flow(triggered_key)
│
├── Feed to MitigationAgent (if available):
│   ├── Rate-based: mitigation_agent.on_packet(src_ip)
│   └── Vector-based: mitigation_agent.on_packet_vector(...)
│
└── Track blocked IPs in _blocked_ips set
```

### Interface Validation

```
_validate_interface() → str
│
├── Get available interfaces: scapy.get_if_list()
├── Check configured interface (from .env)
│   └── If found → return it
│
├── Auto-detect: first non-loopback interface
│   └── Filter out "lo" interfaces
│
└── If none found → SystemExit("Fatal: No interface")
```

### File Naming

PCAP files are named with microsecond-precision timestamps:

```
B_20260519_143025_123456.pcap
│ │        │      │
│ │        │      └── Microseconds
│ │        └── HHMMSS
│ └── YYYYMMDD
└── "B" prefix (batch)
```

## FileDispatcher

Continuously scans the capture directory for completed `.pcap` files:

```
_dispatch_loop()
│
├── While not shutdown:
│   ├── _find_oldest_file()
│   │   ├── Scan CAPTURE_DIR for *.pcap files
│   │   ├── Exclude .tmp files (still being written)
│   │   ├── Check settling time (10 seconds since last modification)
│   │   └── Return oldest file by mtime
│   │
│   ├── If no file found → sleep(DISPATCHER_POLL_INTERVAL_SECONDS)
│   │
│   ├── Move to in_progress:
│   │   └── FileManager.move_to_in_progress(pcap_path)
│   │
│   ├── Process:
│   │   └── feature_extractor.process_pcap(in_progress_path)
│   │       ├── Returns (success, output_csv_path)
│   │
│   ├── If success → FileManager.move_to_processed() (deletes file)
│   └── If failure → FileManager.move_to_error()
```

## FileManager

Static utility for file lifecycle management:

```python
class FileManager:
    @staticmethod
    move_to_in_progress(pcap_path) → Path
    # shutil.move(capture_dir/file.pcap → in_progress/file.pcap)

    @staticmethod
    move_to_processed(pcap_path)
    # pcap_path.unlink()  # Delete from in_progress

    @staticmethod
    move_to_error(pcap_path)
    # shutil.move(in_progress/file.pcap → error/file.pcap)
```

## Logger

Centralized logging with console + rotating file output:

```python
logger = logging.getLogger("DDoSPipeline")
# Format: "asctime - threadName - levelname - message"
# Console: stdout
# File: logs/pipeline_YYYYMMDD.log (10MB max, 5 backups)
```

## Standalone Entry Point

```python
# capapp/main.py
def main():
    config.setup_directories()
    pipeline = DDoSPipeline()  # No mitigation/flow_tracker
    pipeline.run()
```

This runs the capture + dispatch pipeline without the DRL detection or mitigation components — useful for data collection only.

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `CAPTURE_INTERFACE` | "enp0s3" | Network interface to capture on |
| `CAPTURE_FILTER` | "" | BPF filter string (e.g., "tcp port 80") |
| `ROTATE_INTERVAL_SECONDS` | 5 | Time-based rotation interval |
| `ROTATE_MAX_SIZE_MB` | 50 | Size-based rotation threshold |
| `DISPATCHER_POLL_INTERVAL_SECONDS` | 5 | How often to scan for new files |
| `MAX_PROCESSING_WORKERS` | CPU count | Thread pool size for feature extraction |
| `PROCESSING_TIMEOUT_SECONDS` | 300 | Max time to process a single PCAP |
