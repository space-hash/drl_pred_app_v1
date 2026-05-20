# Configuration System — Environment-Based Settings

**File:** `capapp/config/settings.py` (156 lines)

## Overview

All application configuration is centralized in a single `Config` class, loaded from environment variables or a `.env` file using `python-dotenv`. This provides a clean separation between code and configuration.

## Configuration Loading

```python
PROJECT_ROOT = Path(__file__).resolve().parents[2]  # drl_pred_app_v1/
CAPAPP_ROOT = Path(__file__).resolve().parents[1]   # drl_pred_app_v1/capapp/

# Load .env file from project root
load_dotenv(PROJECT_ROOT / ".env")

# Helper functions for type-safe env reading
def _get_bool(name, default) → bool
def _get_int(name, default) → int
def _get_path(name, default) → Path
```

## Directory Structure

```python
class Config:
    # Core directories
    CAPTURE_DIR = capapp/capture_output/
    IN_PROGRESS_DIR = capapp/capture_output/in_progress/
    FEATURES_DIR = capapp/features_output/
    ERROR_DIR = capapp/capture_output/error/
    LOG_DIR = capapp/logs/
    PREDICTIONS_DIR = data/predictions/
    MODEL_DIR = detection_module/trained_models/
```

### Directory Setup

```python
@classmethod
def setup_directories(cls):
    for directory in [
        cls.CAPTURE_DIR,
        cls.IN_PROGRESS_DIR,
        cls.FEATURES_DIR,
        cls.ERROR_DIR,
        cls.LOG_DIR,
        cls.PREDICTIONS_DIR,
        cls.MODEL_DIR,
        cls.PROCESSED_FEATURES_DIR,
        cls.PREDICTION_OUTPUT_DIR,
    ]:
        directory.mkdir(parents=True, exist_ok=True)
```

## All Configuration Variables

### Flask Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_HOST` | `0.0.0.0` | Bind address |
| `FLASK_PORT` | `5000` | Bind port |
| `FLASK_DEBUG` | `False` | Debug mode |
| `FLASK_APP_URL` | `http://127.0.0.1:5000` | App URL |

### Capture Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `CAPTURE_INTERFACE` | `enp0s3` | Network interface |
| `CAPTURE_FILTER` | `""` | BPF filter string |
| `ROTATE_INTERVAL_SECONDS` | `5` | PCAP rotation interval |
| `ROTATE_MAX_SIZE_MB` | `50` | PCAP max size before rotation |

### Processing Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `DISPATCHER_POLL_INTERVAL_SECONDS` | `5` | File scan interval |
| `MAX_PROCESSING_WORKERS` | `cpu_count` | Thread pool size |
| `PROCESSING_TIMEOUT_SECONDS` | `300` | Max processing time per PCAP |

### Flow Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `FLOW_TIMEOUT_NS` | `1,200,000,000` | Flow expiry (120s in ns) |
| `MAX_FLOW_DURATION_NS` | `120,000,000,000` | Max flow duration (120s in ns) |
| `ACTIVE_THRESHOLD_US` | `1,000,000` | Active/idle threshold (1s) |

### Model Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL_PATH` | `detection_module/trained_models/final_drl1.pt` | Active model |
| `PREDICTION_OUTPUT_DIR` | `data/predictions/` | Prediction output |
| `PROCESSED_FEATURES_DIR` | `capapp/features_output/` | Feature CSV output |
| `FORCE_CPU` | `True` | Force CPU inference |
| `QUEUE_MAXSIZE` | `10` | File queue max size |

### Model Updater Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `MODEL_API_URL` | `http://127.0.0.1:8000/api/pipeline/model/download` | Remote model URL |
| `MODEL_UPDATE_INTERVAL_HOURS` | `2` | Update check interval |

### Mitigation Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `MITIGATION_ENABLED` | `False` | Enable mitigation |
| `MITIGATION_AUTO_BLOCK` | `False` | Enable auto-blocking |
| `MITIGATION_RATE_LIMIT_ENABLED` | `True` | Enable rate limiting |
| `MITIGATION_RATE_LIMIT_PPM` | `1000` | Packets per minute limit |
| `MITIGATION_ML_AUTO_BLOCK` | `False` | Enable ML-based blocking |
| `MITIGATION_CONFIDENCE_THRESHOLD` | `0.8` | ML confidence threshold |
| `MITIGATION_DETECTION_COUNT` | `3` | Detections before block |
| `MITIGATION_BLOCK_DURATION_MINUTES` | `60` | Block duration |
| `MITIGATION_USE_IPTABLES` | `True` | Use iptables enforcement |

### eBPF/XDP Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `EBPF_ENABLED` | `False` | Enable eBPF/XDP |
| `EBPF_USE_XDP` | `True` | Use XDP mode |
| `EBPF_FALLBACK_TO_IPTABLES` | `True` | Fallback to iptables |

### DRL Mitigation Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `DRL_MITIGATION_ENABLED` | `False` | Enable DRL mitigation |
| `DRL_MITIGATION_MODEL_PATH` | `detection_module/trained_models/final_drl1.pt` | DRL model path |
| `DRL_MITIGATION_CONFIDENCE_THRESHOLD` | `0.7` | DRL confidence threshold |
| `DRL_MITIGATION_BLOCK_DURATION_MINUTES` | `30` | DRL block duration |
| `DRL_MITIGATION_FEATURE_WINDOW_SIZE` | `10` | Feature window size |

### Alerting Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `ALERTING_ENABLED` | `True` | Enable alerting |
| `ALERTING_RATE_LIMIT_SECONDS` | `60` | Alert rate limit |
| `ALERTING_DEDUP_WINDOW_SECONDS` | `300` | Dedup window (5 min) |

### Email Alerting

| Variable | Default | Description |
|----------|---------|-------------|
| `ALERTING_EMAIL_ENABLED` | `False` | Enable email alerts |
| `ALERTING_EMAIL_SMTP_HOST` | `smtp.gmail.com` | SMTP server |
| `ALERTING_EMAIL_SMTP_PORT` | `587` | SMTP port |
| `ALERTING_EMAIL_USERNAME` | `""` | SMTP username |
| `ALERTING_EMAIL_PASSWORD` | `""` | SMTP password |
| `ALERTING_EMAIL_FROM` | `""` | Sender email |
| `ALERTING_EMAIL_TO` | `[]` | Recipient emails (comma-separated) |

### Webhook Alerting

| Variable | Default | Description |
|----------|---------|-------------|
| `ALERTING_WEBHOOK_ENABLED` | `False` | Enable webhook alerts |
| `ALERTING_WEBHOOK_URL` | `""` | Webhook URL |
| `ALERTING_WEBHOOK_TYPE` | `generic` | Type: slack, discord, generic |

## .env File Format

```bash
# Flask
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
FLASK_DEBUG=false

# Capture
CAPTURE_INTERFACE=wlp0s20f3
ROTATE_INTERVAL_SECONDS=5
ROTATE_MAX_SIZE_MB=50

# Model
MODEL_PATH=detection_module/trained_models/final_drl1.pt
FORCE_CPU=true

# Mitigation
MITIGATION_ENABLED=true
MITIGATION_AUTO_BLOCK=true
MITIGATION_RATE_LIMIT_PPM=50
MITIGATION_USE_IPTABLES=true

# eBPF
EBPF_ENABLED=false

# DRL Mitigation
DRL_MITIGATION_ENABLED=true
DRL_MITIGATION_CONFIDENCE_THRESHOLD=0.7

# Alerting
ALERTING_ENABLED=true
```

## Singleton Instance

```python
config = Config()  # Created at module import time
```

All modules import and use this singleton:

```python
from capapp.config.settings import config
# config.CAPTURE_INTERFACE, config.MODEL_PATH, etc.
```
