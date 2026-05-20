# DRL-Based DDoS Detection & Mitigation System — Architecture Overview

## System Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           FLASK WEB DASHBOARD (app.py)                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ Pipeline  │  │Detection │  │Mitigation│  │  eBPF/   │  │  System       │  │
│  │ Controls  │  │  APIs    │  │  APIs    │  │  XDP     │  │  Metrics      │  │
│  └─────┬────┘  └─────┬────┘  └─────┬────┘  └─────┬────┘  └───────┬───────┘  │
│        │              │              │              │              │          │
│        ▼              ▼              ▼              ▼              ▼          │
│  ┌─────────────────────────────────────────────────────────────────────────┐ │
│  │                     PipelineController (core/controller.py)              │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  │ │
│  │  │ DDoSPipeline │  │LocalPredict  │  │ModelUpdater  │  │AlertManager│  │ │
│  │  │ (capapp)     │  │Pipeline      │  │              │  │            │  │ │
│  │  └──────┬───────┘  └──────┬───────┘  └──────────────┘  └────────────┘  │ │
│  │         │                  │                                             │ │
│  │  ┌──────┴───────┐  ┌──────┴───────┐  ┌──────────────┐  ┌────────────┐  │ │
│  │  │MitigationAgent│ │FlowTracker   │  │DRLMitigation │  │SystemMonitor│ │ │
│  │  │              │ │              │  │Agent         │  │            │  │ │
│  │  └──────┬───────┘ └──────┬───────┘  └──────────────┘  └────────────┘  │ │
│  │         │                 │                                             │ │
│  │  ┌──────┴───────┐  ┌──────┴───────┐                                    │ │
│  │  │EbpfManager   │  │FirewallMgr   │                                    │ │
│  │  │(XDP/iptables)│  │(iptables)    │                                    │ │
│  │  └──────────────┘  └──────────────┘                                    │ │
│  └─────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘

┌───────────────────── DATA FLOW ─────────────────────────────────────────────┐
│                                                                             │
│  Network Interface (eth0/wlan0)                                             │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────┐                                                        │
│  │  PacketCapturer │ ◄── Scapy sniff() — captures raw packets in real-time  │
│  │  (capapp)       │     Rotates to timestamped .pcap files every 5s/50MB   │
│  └────┬────────────┘                                                        │
│       │                                                                     │
│       ├─────────────────────────────────────────┐                           │
│       ▼                                         ▼                           │
│  ┌─────────────────┐                    ┌─────────────────┐                 │
│  │  FlowTracker    │                    │  MitigationAgent│                 │
│  │  (core)         │                    │  (core)         │                 │
│  │  Real-time flow │                    │  Rate-based     │                 │
│  │  feature ext.   │                    │  auto-blocking  │                 │
│  └────┬────────────┘                    └─────────────────┘                 │
│       │                                                                     │
│       ▼ (triggers DRL inference every N packets)                            │
│  ┌─────────────────┐                                                        │
│  │ DRLMitigation   │ ◄── Uses trained PPO model on 81-dim CIC features      │
│  │ Agent (core)    │     Confidence-based blocking decisions                │
│  └─────────────────┘                                                        │
│                                                                             │
│  ┌─────────────────┐                                                        │
│  │  FileDispatcher │ ◄── Scans capture dir for completed .pcap files        │
│  │  (capapp)       │     Moves to in_progress/, dispatches to extractor     │
│  └────┬────────────┘                                                        │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────┐                                                        │
│  │ CICFeature      │ ◄── Extracts 84 CICFlowMeter features from .pcap       │
│  │ Extractor       │     Bidirectional flow tracking, IAT, TCP flags, etc.  │
│  │ (capapp)        │     Outputs CSV files to processed_features/           │
│  └────┬────────────┘                                                        │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─────────────────┐                                                        │
│  │ LocalPrediction │ ◄── File discovery worker + processing worker threads  │
│  │ Pipeline        │     Preprocesses CSV, runs PPO batch inference         │
│  │ (detection_mod) │     Saves prediction CSVs, calls detection callback    │
│  └────┬────────────┘                                                        │
│       │                                                                     │
│       ▼ (detection_callback)                                                │
│  ┌─────────────────┐                                                        │
│  │ PipelineCtrl    │ ◄── Records detections, updates counters               │
│  │ record_detection│     Routes through mitigation agents                   │
│  └────┬────────────┘                                                        │
│       │                                                                     │
│       ├──────────────────┬──────────────────┬──────────────────┐            │
│       ▼                  ▼                  ▼                  ▼            │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │
│  │Dashboard │  │Mitigation    │  │Alerting      │  │eBPF/XDP      │        │
│  │UI Update │  │Agent blocks  │  │(Email/Slack/ │  │kernel-level  │        │
│  │          │  │(iptables)    │  │ Webhook)     │  │XDP_DROP      │        │
│  └──────────┘  └──────────────┘  └──────────────┘  └──────────────┘        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
drl_pred_app_v1/
│
├── app.py                              # Flask web dashboard entry point
├── train.py                            # Model training script (PPO)
├── evaluate_model.py                   # Model evaluation & validation
├── compare_models.py                   # Model comparison utility
├── model_manager.py                    # Model lifecycle management CLI
├── generate_sample_data.py             # Synthetic CICFlowMeter data generator
├── add_model_metadata.py               # Add metadata to existing models
│
├── requirements.txt                    # Python dependencies
├── docker-compose.yml                  # Docker deployment configuration
├── setup.sh                            # Automated setup script
├── deploy.sh                           # One-click production deploy script
├── .env                                # Active environment configuration
├── .env.example                        # Environment configuration template
│
├── templates/
│   └── index.html                      # Cyberpunk-themed Flask dashboard UI
│
├── core/                               # Core mitigation & monitoring modules
│   ├── __init__.py
│   ├── controller.py                   # Pipeline orchestrator (central hub)
│   ├── mitigation_agent.py             # Rate-based + ML-based IP blocking + iptables
│   ├── ebpf_manager.py                 # eBPF/XDP kernel-level packet filtering
│   ├── drl_mitigation.py               # DRL model-based real-time mitigation
│   ├── flow_tracker.py                 # Real-time 81-dim CIC feature extraction
│   ├── alerting.py                     # Multi-channel alerting (Email/Slack/Discord)
│   └── system_monitor.py               # CPU/Memory/Disk/Network metrics via psutil
│
├── capapp/                             # Capture application (disk-based pipeline)
│   ├── __init__.py
│   ├── main.py                         # Standalone pipeline entry point
│   │
│   ├── capture/
│   │   ├── __init__.py
│   │   ├── packet_capture.py           # Scapy-based packet capture + PCAP rotation
│   │   └── file_writer.py              # (Unused) Queue-based PCAP writer
│   │
│   ├── config/
│   │   ├── __init__.py
│   │   └── settings.py                 # Centralized configuration (env-based)
│   │
│   ├── orchestration/
│   │   ├── __init__.py
│   │   └── pipeline.py                 # DDoSPipeline master orchestrator
│   │
│   ├── processing/
│   │   ├── __init__.py
│   │   ├── dispatcher.py               # PCAP file dispatcher to feature extractor
│   │   └── feature_extractor/
│   │       ├── __init__.py
│   │       └── cic_extractor.py        # CICFlowMeter feature extraction from PCAP
│   │
│   ├── storage/
│   │   ├── __init__.py
│   │   └── file_manager.py             # File lifecycle (in_progress/processed/error)
│   │
│   └── utils/
│       ├── __init__.py
│       └── logger.py                   # Centralized logging setup
│
├── detection_module/                   # DRL detection & inference
│   ├── __init__.py
│   ├── detection.py                    # PPO agent + DDoS environment (1377 lines)
│   ├── predict_pipeline.py             # Local prediction pipeline (file watcher)
│   └── model_update.py                 # Remote model download/update system
│
├── data/                               # Runtime data storage
│   ├── __init__.py
│   ├── blocked_ips.json                # Persisted blocked IPs
│   ├── alert_history.json              # Alert history
│   ├── ebpf_blocked_ips.json           # eBPF blocked IPs
│   └── predictions/                    # Prediction CSV output files
│
└── detection_module/trained_models/    # Trained .pt model files
```

## Architecture Layers

### Layer 1: Data Acquisition (capapp/capture)
- **PacketCapturer**: Uses Scapy's `sniff()` to capture live network traffic
- Rotates captured packets into timestamped `.pcap` files (time-based: 5s, size-based: 50MB)
- Feeds packets to FlowTracker and MitigationAgent in real-time
- Auto-detects network interface if configured one is unavailable

### Layer 2: Real-Time Processing (core)
- **FlowTracker**: Tracks bidirectional network flows, computes incremental 81-dimensional CICFlowMeter features
- **MitigationAgent**: Rate-based auto-blocking (packets/min threshold), ML-based auto-blocking, iptables enforcement
- **DRLMitigationAgent**: Uses trained PPO model for real-time blocking decisions based on flow features
- **EbpfManager**: Kernel-level XDP_DROP packet filtering with iptables fallback

### Layer 3: Batch Processing (capapp/processing)
- **FileDispatcher**: Scans capture directory for completed `.pcap` files, dispatches to feature extractor
- **CICFeatureExtractor**: Extracts 84 CICFlowMeter features from `.pcap` files using Scapy
- Outputs CSV files with flow features for the prediction pipeline

### Layer 4: DRL Inference (detection_module)
- **LocalPredictionPipeline**: File discovery + processing worker threads
- Preprocesses CSV data (IP conversion, scaling, NaN handling)
- Runs batch PPO inference, saves prediction CSVs
- **ModelUpdater**: Downloads models from remote API, validates, hot-swaps

### Layer 5: Mitigation & Alerting (core)
- **MitigationAgent**: Rate-based + ML-based IP blocking with iptables
- **EbpfManager**: eBPF/XDP kernel-level filtering (line-rate)
- **AlertManager**: Multi-channel alerting (Dashboard, Email, Slack, Discord, Webhooks)
- **SystemMonitor**: Hardware and application metrics collection

### Layer 6: Web Dashboard (app.py)
- Flask REST API for pipeline control, detection data, mitigation controls
- Cyberpunk-themed single-page UI with real-time updates
- System health monitoring, traffic charts, alert management

## Key Design Decisions

1. **Disk-Based Pipeline**: PCAP files are written to disk rather than processed purely in-memory, providing durability and decoupling capture from processing
2. **Three-Layer Mitigation**: Rate-based (fast), DRL model-based (intelligent), eBPF/XDP (kernel-level line-rate)
3. **CICFlowMeter Compatibility**: Features match the CICFlowMeter standard (84 features extracted, 81 used for DRL inference)
4. **PPO Reinforcement Learning**: Proximal Policy Optimization with GAE, early stopping, validation split, and adaptive thresholds
5. **Hot-Swap Model Updates**: Models can be downloaded from a remote API and swapped without restarting the pipeline
6. **Thread-Safe Design**: All shared state uses `threading.RLock` for thread safety
7. **Graceful Degradation**: eBPF falls back to iptables, CUDA falls back to CPU, missing scaler is handled

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Packet Capture | Scapy |
| ML Framework | PyTorch |
| Web Framework | Flask |
| Data Processing | Pandas, NumPy |
| Feature Scaling | scikit-learn (StandardScaler) |
| System Monitoring | psutil |
| Kernel Filtering | eBPF/XDP (BCC library) |
| Firewall | iptables/ip6tables |
| Visualization | Chart.js (frontend) |
| Deployment | Docker, systemd |

## Data Flow Summary

```
Raw Packets → [Scapy sniff] → .pcap Files → [CIC Extractor] → Feature CSVs
     ↓                                                      ↓
[FlowTracker] → 81-dim Features → [PPO Model] → DDoS/Normal
     ↓                                                      ↓
[Mitigation] → iptables/XDP DROP ← [Blocking Decision] ← [Confidence Check]
     ↓
[Alerting] → Dashboard / Email / Slack / Discord
```
