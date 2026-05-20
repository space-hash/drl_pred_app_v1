# DRL-Based DDoS Detection System — Documentation Index

## Complete Documentation Set

This directory contains comprehensive documentation for every module in the DRL-Based DDoS Detection & Mitigation System.

## Full File Index

| # | Document | Source File | Location |
|---|----------|-------------|----------|
| 00 | [Architecture Overview](00_ARCHITECTURE_OVERVIEW.md) | System diagram, project structure, architecture layers, data flow | `docs/00_ARCHITECTURE_OVERVIEW.md` |
| 01 | [Core Controller](01_CORE_CONTROLLER.md) | `core/controller.py` | `docs/01_CORE_CONTROLLER.md` |
| 02 | [Mitigation Agent](02_MITIGATION_AGENT.md) | `core/mitigation_agent.py` | `docs/02_MITIGATION_AGENT.md` |
| 03 | [eBPF Manager](03_EBPF_MANAGER.md) | `core/ebpf_manager.py` | `docs/03_EBPF_MANAGER.md` |
| 04 | [DRL Mitigation](04_DRL_MITIGATION.md) | `core/drl_mitigation.py` | `docs/04_DRL_MITIGATION.md` |
| 05 | [Flow Tracker](05_FLOW_TRACKER.md) | `core/flow_tracker.py` | `docs/05_FLOW_TRACKER.md` |
| 06 | [Alerting](06_ALERTING.md) | `core/alerting.py` | `docs/06_ALERTING.md` |
| 07 | [System Monitor](07_SYSTEM_MONITOR.md) | `core/system_monitor.py` | `docs/07_SYSTEM_MONITOR.md` |
| 08 | [Capture Pipeline](08_CAPTURE_PIPELINE.md) | `capapp/capture/`, `capapp/orchestration/`, `capapp/processing/` | `docs/08_CAPTURE_PIPELINE.md` |
| 09 | [Feature Extractor](09_FEATURE_EXTRACTOR.md) | `capapp/processing/feature_extractor/cic_extractor.py` | `docs/09_FEATURE_EXTRACTOR.md` |
| 10 | [Detection Module](10_DETECTION_MODULE.md) | `detection_module/detection.py` | `docs/10_DETECTION_MODULE.md` |
| 11 | [Prediction Pipeline](11_PREDICTION_PIPELINE.md) | `detection_module/predict_pipeline.py` | `docs/11_PREDICTION_PIPELINE.md` |
| 12 | [Model Update](12_MODEL_UPDATE.md) | `detection_module/model_update.py` | `docs/12_MODEL_UPDATE.md` |
| 13 | [Training](13_TRAINING.md) | `train.py` | `docs/13_TRAINING.md` |
| 14 | [Flask Dashboard](14_FLASK_DASHBOARD.md) | `app.py`, `templates/index.html` | `docs/14_FLASK_DASHBOARD.md` |
| 15 | [Configuration](15_CONFIGURATION.md) | `capapp/config/settings.py` | `docs/15_CONFIGURATION.md` |
| 16 | [Model Management](16_MODEL_MANAGEMENT.md) | `model_manager.py`, `evaluate_model.py`, `compare_models.py`, `generate_sample_data.py`, `add_model_metadata.py` | `docs/16_MODEL_MANAGEMENT.md` |
| 17 | [Deployment](17_DEPLOYMENT.md) | `setup.sh`, `deploy.sh`, `docker-compose.yml` | `docs/17_DEPLOYMENT.md` |
| 18 | [Sequence Diagrams](18_SEQUENCE_DIAGRAMS.md) | End-to-end flow diagrams for startup, detection, processing, updates, alerts, shutdown | `docs/18_SEQUENCE_DIAGRAMS.md` |

---

## System Summary

### Total Codebase

| Category | Files | Lines |
|----------|-------|-------|
| Python source | 37 | ~6,500 |
| HTML/CSS/JS | 1 | ~2,000+ |
| Shell scripts | 2 | 245 |
| Config files | 3 | 150 |
| Documentation | 19 | ~150,000+ words |

### Key Technologies

- **PyTorch** — PPO neural network training and inference
- **Scapy** — Packet capture and PCAP processing
- **Flask** — Web dashboard and REST API
- **eBPF/XDP** — Kernel-level packet filtering
- **iptables** — Firewall rule management
- **psutil** — System metrics collection
- **pandas/numpy** — Data processing
- **scikit-learn** — Feature scaling

### Three-Layer Mitigation

1. **Rate-based** — Simple packets-per-minute threshold (fastest, ~0ms)
2. **DRL model-based** — 81-feature neural network inference (~1-5ms)
3. **eBPF/XDP** — Kernel-level XDP_DROP at NIC driver (line-rate, millions pps)

### Data Pipeline

```
Raw Packets → Scapy sniff → .pcap files → CIC Feature Extractor → 84-feature CSVs
     ↓                                                                    ↓
[FlowTracker] → 81-dim features → PPO Model → DDoS/Normal ← Prediction Pipeline
     ↓                                                                    ↓
[Mitigation] → iptables/XDP DROP ← Blocking Decision ← Confidence Check
     ↓
[Alerting] → Dashboard / Email / Slack / Discord
```
