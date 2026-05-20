# Flask Dashboard — Web UI & REST API

**File:** `app.py` (438 lines)
**Template:** `templates/index.html`

## Overview

The Flask application provides a cyberpunk-themed web dashboard with real-time monitoring, pipeline controls, mitigation management, and REST APIs for all system components.

## Application Structure

```python
app = Flask(__name__)
system_monitor = SystemMonitor()

# No-cache headers for all responses
@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response
```

## Routes

### Page Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Main dashboard (renders index.html) |

### Pipeline Control

| Route | Method | Description |
|-------|--------|-------------|
| `/start` | POST | Start the detection pipeline (requires privileges) |
| `/stop` | POST | Stop the detection pipeline |

### Detection Data

| Route | Method | Description |
|-------|--------|-------------|
| `/api/status` | GET | Pipeline status with detection stats |
| `/api/detections` | GET | Recent detections (paginated, limit/offset) |
| `/api/detections/<id>` | GET | Single detection details |
| `/api/stats` | GET | Detection statistics + throughput |
| `/api/data` | POST | Receive prediction data (debug endpoint) |
| `/raw_data` | POST | Receive raw data (debug endpoint) |

### Model Management

| Route | Method | Description |
|-------|--------|-------------|
| `/api/model_status` | GET | Model update status |
| `/api/update_model` | POST | Trigger manual model update |

### Mitigation Control

| Route | Method | Description |
|-------|--------|-------------|
| `/api/mitigation/status` | GET | Mitigation agent status |
| `/api/mitigation/block` | POST | Manually block an IP |
| `/api/mitigation/unblock` | POST | Unblock an IP |
| `/api/mitigation/toggle` | POST | Toggle all mitigation |
| `/api/mitigation/toggle_auto` | POST | Toggle rate-based auto-block |
| `/api/mitigation/toggle_ml_auto` | POST | Toggle ML-based auto-block |
| `/api/mitigation/settings` | POST | Update mitigation settings |
| `/api/mitigation/whitelist` | POST | Add IP to whitelist |
| `/api/mitigation/unwhitelist` | POST | Remove IP from whitelist |
| `/api/mitigation/blacklist` | POST | Add IP to blacklist |
| `/api/mitigation/unblacklist` | POST | Remove IP from blacklist |
| `/api/mitigation/clear_counts` | POST | Clear detection counters |

### eBPF/XDP Control

| Route | Method | Description |
|-------|--------|-------------|
| `/api/ebpf/status` | GET | eBPF/XDP status and statistics |
| `/api/ebpf/block` | POST | Block IP via eBPF/XDP |
| `/api/ebpf/unblock` | POST | Unblock IP via eBPF/XDP |

### DRL Mitigation Control

| Route | Method | Description |
|-------|--------|-------------|
| `/api/drl_mitigation/status` | GET | DRL mitigation status |
| `/api/drl_mitigation/toggle` | POST | Toggle DRL mitigation |
| `/api/drl_mitigation/settings` | POST | Update DRL settings |
| `/api/drl_mitigation/unblock` | POST | Unblock IP via DRL mitigation |

### Alerting

| Route | Method | Description |
|-------|--------|-------------|
| `/api/alerts` | GET | Recent alerts (filterable by severity) |
| `/api/alerts/stats` | GET | Alert statistics |
| `/api/alerts/acknowledge` | POST | Acknowledge an alert |
| `/api/alerts/clear` | POST | Clear all alerts |
| `/api/alerts/test` | POST | Send a test alert |

### System Metrics

| Route | Method | Description |
|-------|--------|-------------|
| `/api/system/metrics` | GET | Combined hardware + app + security metrics |

## Privilege Check

```python
def check_privileges() -> bool:
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        s.close()
        return True
    except PermissionError:
        return False
```

This checks if the process can create raw sockets, which is required for packet capture. The `/start` endpoint returns 403 if privileges are insufficient.

## Graceful Shutdown

```python
def graceful_shutdown(signum, frame):
    if is_pipeline_running():
        stop_pipeline()
    sys.exit(0)

signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)
```

## Dashboard UI (index.html)

The template is a cyberpunk-themed single-page application with:

- **Animated background** with particle effects
- **Sidebar navigation** with sections for each subsystem
- **Stats cards** showing real-time counters
- **Detection table** with live-updating rows
- **Traffic distribution chart** (Chart.js)
- **Mitigation control panel** with toggles and IP management
- **eBPF/XDP panel** with kernel-level controls
- **DRL mitigation panel** with model status
- **Alerts panel** with severity filtering
- **Pipeline controls** (start/stop buttons)
- **System health monitoring** with CPU/memory/disk gauges

### CSS Features

- CSS custom properties for theming
- Glassmorphism effects (backdrop-filter blur)
- Glitch text effects for headings
- Fade-in animations for content sections
- Responsive grid layouts

## Server Configuration

```python
if __name__ == "__main__":
    if not check_privileges():
        print("\nWARNING: Missing packet capture privileges.")
    app.run(
        host=config.FLASK_HOST,    # Default: 0.0.0.0
        port=config.FLASK_PORT,    # Default: 5000
        debug=config.FLASK_DEBUG   # Default: False
    )
```
