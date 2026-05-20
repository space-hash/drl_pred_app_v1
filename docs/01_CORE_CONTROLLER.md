# Core Controller — Pipeline Orchestrator

**File:** `core/controller.py` (395 lines)

## Overview

The `PipelineController` is the central hub of the entire DDoS detection system. It initializes, manages, and coordinates all subsystems: the capture pipeline, detection pipeline, mitigation agents, alerting, and model updates.

## Class Diagram

```
PipelineController
├── pipeline_active: Event           # Thread-safe running flag
├── lock: RLock                      # Thread-safe state access
├── pipeline: DDoSPipeline           # Capture + dispatch pipeline
├── detect: LocalPredictionPipeline  # DRL inference pipeline
├── model_updater: ModelUpdater      # Remote model download
├── mitigation_agent: MitigationAgent # Rate + ML blocking
├── ebpf_manager: EbpfManager        # eBPF/XDP filtering
├── drl_mitigation: DRLMitigationAgent # DRL-based blocking
├── alert_manager: AlertManager      # Multi-channel alerts
├── flow_tracker: FlowTracker        # Real-time flow features
│
├── ddos_count: int                  # DDoS detection counter
├── normal_count: int                # Normal traffic counter
├── suspicious_count: int            # Suspicious traffic counter
├── recent_detections: List[Dict]    # Recent detection records
├── start_time: datetime             # Pipeline start timestamp
│
├── __init__()                       # Conditional module initialization
├── initialize_components()          # Create pipeline + detection instances
├── start_all() → bool               # Start all threads
├── stop_all() → bool                # Stop all threads + cleanup
├── is_running() → bool              # Check pipeline status
├── get_status() → Dict              # Comprehensive status report
├── get_recent_detections() → List   # Recent detections (filtered)
├── get_detection_details() → Dict   # Single detection details
├── record_detection()               # Process detection result
│
└── _reset_counters()                # Reset all counters
```

## Initialization Flow

```
PipelineController.__init__()
│
├── Create Event + RLock
├── Initialize all references to None
├── Reset counters (ddos=0, normal=0, suspicious=0)
│
├── if MITIGATION_ENABLED:
│   └── MitigationAgent(
│         auto_block, rate_limit_enabled, rate_limit_ppm,
│         ml_auto_block, confidence_threshold, detection_count,
│         block_duration_minutes, use_iptables
│       )
│
├── if EBPF_ENABLED:
│   └── EbpfManager(interface, use_xdp, fallback_to_iptables)
│       └── initialize() → True/False
│
├── if DRL_MITIGATION_ENABLED:
│   ├── FlowTracker()
│   └── DRLMitigationAgent(
│         model_path, confidence_threshold,
│         block_duration_minutes, enabled=True, flow_tracker
│       )
│
└── if ALERTING_ENABLED:
    └── create_alert_manager_from_config(config)
        └── load_history()
```

## Thread Architecture

When `start_all()` is called, two daemon threads are spawned:

```
start_all()
│
├── initialize_components()
│   ├── ModelUpdater(api_url, model_path, interval)
│   ├── DDoSPipeline(mitigation_agent, flow_tracker)
│   └── LocalPredictionPipeline(
│         model_path, processed_dir, output_dir,
│         queue_maxsize, force_cpu, model_updater,
│         detection_callback=self.record_detection
│       )
│
├── model_updater.start_periodic_update()
│
├── Thread 1: "DDoSPipelineThread"
│   └── target: self._run_pipeline()
│       └── pipeline.run()  # Blocks until stop signal
│
└── Thread 2: "DetectionThread"
    └── target: self._run_detection()
        └── detect.start()  # File discovery + processing workers
```

## Detection Recording Pipeline

The `record_detection()` method is the most complex method — it processes every prediction result:

```
record_detection(detection_data)
│
├── Parse prediction value → is_ddos (bool)
├── Extract src_ip, dst_ip (convert int IPs to string)
├── Parse protocol number → "TCP"/"UDP"/"ICMP"
├── Convert Flow Duration (microseconds → seconds)
│
├── Determine status & severity:
│   ├── is_ddos AND confidence < 0.6 → "Suspicious" / "warning"
│   ├── is_ddos AND confidence >= 0.6 → "DDoS" / "critical"
│   └── not is_ddos → "Normal" / "info"
│
├── Check if src_ip is blocked by any module:
│   ├── mitigation_agent.is_blocked(src_ip)
│   ├── drl_mitigation.is_blocked(src_ip)
│   └── ebpf_manager.is_blocked(src_ip)
│
├── Update counters (ddos_count / suspicious_count / normal_count)
│
├── If NOT blocked → add to recent_detections (max 200, trim to 100)
│   └── Detection record includes:
│       id, timestamp, src_ip, dst_ip, protocol, duration,
│       status, severity, confidence, flow_id, packets, bytes
│
├── If not blocked → route through mitigation_agent.on_detection()
│
└── Send alerts (outside lock to avoid blocking):
    ├── DDoS + confidence >= 0.8 → critical alert
    └── Suspicious → warning alert
```

## Status Reporting

The `get_status()` method returns a comprehensive dictionary:

```python
{
    "running": bool,
    "start_time": str (ISO),
    "uptime": float (seconds),
    "processed_files": int,
    "failed_files": int,
    "ddos_detections": int,
    "normal_detections": int,
    "suspicious_detections": int,
    "recent_detections_count": int,  # Filtered (excludes blocked IPs)
    "model_loaded": bool,
    "queue_size": int,
    "device": str,
    "ebpf_enabled": bool,
    "drl_mitigation_enabled": bool,
    "alerting_enabled": bool,
    "flow_tracker_active": int,
}
```

## Shutdown Sequence

```
stop_all()
│
├── pipeline.stop()              # Stop packet capture + dispatcher
├── detect.stop()                # Stop file discovery + processing
├── model_updater.stop_periodic_update()
├── ebpf_manager.shutdown()      # Unload XDP program
├── drl_mitigation.cleanup_expired()
│
├── Join pipeline threads (5s timeout)
├── Clear pipeline_active event
├── Set pipeline/detect/model_updater to None
│
└── Log "Pipeline stopped successfully"
```

## Module-Level Functions

The module exposes convenience functions that delegate to the singleton `controller`:

| Function | Delegates To |
|----------|-------------|
| `start_pipeline()` | `controller.start_all()` |
| `stop_pipeline()` | `controller.stop_all()` |
| `pipeline_status()` | `controller.get_status()` |
| `is_pipeline_running()` | `controller.is_running()` |
| `get_recent_detections(limit)` | `controller.get_recent_detections(limit)` |
| `get_detection_details(id)` | `controller.get_detection_details(id)` |

## Key Design Patterns

1. **Singleton Pattern**: A single `controller = PipelineController()` instance is created at module load time
2. **Conditional Initialization**: Modules are only created if their corresponding config flags are enabled
3. **Thread Safety**: All shared state access is protected by `RLock`
4. **Event-Based Lifecycle**: `threading.Event` controls the running/stopped state
5. **Detection Callback Pattern**: The prediction pipeline calls `record_detection()` via callback, decoupling inference from mitigation
