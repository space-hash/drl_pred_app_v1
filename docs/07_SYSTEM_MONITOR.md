# System Monitor — Hardware & Application Metrics

**File:** `core/system_monitor.py` (182 lines)

## Overview

The System Monitor collects hardware, application, and security metrics using `psutil`. It provides a unified metrics API for the Flask dashboard's real-time monitoring panels.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     SystemMonitor                             │
│                                                               │
│  get_all_metrics(controller) → Dict                           │
│  ├── hardware: Dict                                           │
│  │   ├── cpu_percent, cpu_count, cpu_freq                     │
│  │   ├── memory_total_gb, memory_used_gb, memory_percent      │
│  │   ├── disk_total_gb, disk_used_gb, disk_percent            │
│  │   ├── net_rx_mbps, net_tx_mbps, net_rx_pps, net_tx_pps     │
│  │   └── disk_read_mbps, disk_write_mbps                      │
│  │                                                            │
│  ├── application: Dict                                        │
│  │   ├── pipeline_running, queue_size                         │
│  │   ├── processed_files, failed_files                        │
│  │   ├── detections_per_min, model_loaded, uptime_hours       │
│  │                                                            │
│  └── security: Dict                                           │
│      ├── active_blocks, total_blocked_today                   │
│      ├── firewall_enabled, ebpf_enabled, alerts_triggered     │
│                                                                
│  All methods use try/except — failures return 0/False         │
└──────────────────────────────────────────────────────────────┘
```

## Metric Categories

### Hardware Metrics

| Metric | Source | Unit |
|--------|--------|------|
| `cpu_percent` | `psutil.cpu_percent(interval=0.1)` | % |
| `cpu_count` | `psutil.cpu_count(logical=True)` | cores |
| `cpu_freq` | `psutil.cpu_freq().current` | MHz |
| `memory_total_gb` | `psutil.virtual_memory().total` | GB |
| `memory_used_gb` | `psutil.virtual_memory().used` | GB |
| `memory_percent` | `psutil.virtual_memory().percent` | % |
| `disk_total_gb` | `psutil.disk_usage('/').total` | GB |
| `disk_used_gb` | `psutil.disk_usage('/').used` | GB |
| `disk_percent` | `psutil.disk_usage('/').percent` | % |
| `net_rx_mbps` | Delta of `net_io_counters().bytes_recv` | Mbps |
| `net_tx_mbps` | Delta of `net_io_counters().bytes_sent` | Mbps |
| `net_rx_pps` | Delta of `net_io_counters().packets_recv` | packets/s |
| `net_tx_pps` | Delta of `net_io_counters().packets_sent` | packets/s |
| `disk_read_mbps` | Delta of `disk_io_counters().read_bytes` | MB/s |
| `disk_write_mbps` | Delta of `disk_io_counters().write_bytes` | MB/s |

### Application Metrics

| Metric | Source | Description |
|--------|--------|-------------|
| `pipeline_running` | `controller.get_status()["running"]` | Is pipeline active? |
| `queue_size` | `controller.get_status()["queue_size"]` | Files waiting for processing |
| `processed_files` | `controller.get_status()["processed_files"]` | Total files processed |
| `failed_files` | `controller.get_status()["failed_files"]` | Total files failed |
| `model_loaded` | `controller.get_status()["model_loaded"]` | Is PPO model loaded? |
| `uptime_hours` | `controller.get_status()["uptime"] / 3600` | Pipeline uptime |
| `detections_per_min` | `(ddos + suspicious) / (uptime / 60)` | Detection rate |

### Security Metrics

| Metric | Source | Description |
|--------|--------|-------------|
| `active_blocks` | `mitigation_agent.get_status()["total_blocked"]` | Currently blocked IPs |
| `total_blocked_today` | Count of block actions in log | Blocks today |
| `firewall_enabled` | `mitigation_agent.get_status()["use_iptables"]` | iptables active? |
| `ebpf_enabled` | `ebpf_manager.get_stats()["use_xdp"]` | XDP active? |
| `alerts_triggered` | `alert_manager.get_stats()["total_alerts"]` | Total alerts sent |

## Design Principle: Fail-Safe

Every metric collection method is wrapped in `try/except`. If any metric fails to collect, it returns a safe default (0 or False) rather than crashing the application. This ensures the dashboard remains functional even when individual psutil calls fail.

```python
try:
    metrics["cpu_percent"] = psutil.cpu_percent(interval=0.1)
except Exception as e:
    logger.debug(f"Failed to get CPU metrics: {e}")
    metrics["cpu_percent"] = 0  # Safe default
```

## Rate Calculation

Network and disk I/O metrics are calculated as rates by comparing current counters with previously stored values:

```python
now = time.time()
dt = now - self._last_net_io_time
if dt > 0:
    metrics["net_rx_mbps"] = (current_bytes_recv - last_bytes_recv) * 8 / (1024**2) / dt
    metrics["net_tx_mbps"] = (current_bytes_sent - last_bytes_sent) * 8 / (1024**2) / dt
```
