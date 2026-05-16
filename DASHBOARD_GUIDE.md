# DDoS Detection Dashboard - User Guide

## Overview

The DDoS Detection Dashboard is a web-based interface for real-time network traffic monitoring, DDoS attack detection using a Deep Reinforcement Learning (DRL) model, and automated/manual mitigation controls.

**Access:** Open `http://localhost:5000` in your browser (or `http://<server-ip>:5000` for remote access).

---

## Dashboard Sections

### 1. Pipeline Control

**Purpose:** Start, stop, and manage the detection pipeline.

| Element | Description | How to Use |
|---------|-------------|------------|
| **Start Detection** (green button) | Begins packet capture, feature extraction, and ML prediction | Click to start monitoring. Button disables while running. |
| **Stop Detection** (red button) | Stops all pipeline components gracefully | Click to stop. Button disables while stopped. |
| **Update Model Now** (blue button) | Downloads the latest DRL model from the model server | Click to manually trigger a model update. Shows spinner while updating. |
| **Status Indicator** | Shows current pipeline state (Running/Stopped) | Updates automatically every 5 seconds. |

---

### 2. Mitigation Control

**Purpose:** Configure automatic and manual IP blocking to mitigate detected DDoS attacks.

#### Toggles (All On/Off Switches)

| Toggle | Description | When to Enable |
|--------|-------------|----------------|
| **Mitigation** (Master) | Enables ALL mitigation features at once (rate blocking + ML blocking) | Turn ON to activate all protection. Turn OFF to disable everything. |
| **Rate-Based Auto-Block** | Automatically blocks IPs that send more packets per minute than the configured limit | Enable when you want automatic protection against volumetric floods (SYN flood, UDP flood, etc.). |
| **ML-Based Auto-Block** | Automatically blocks IPs after N DDoS detections by the ML model with confidence above the threshold | Enable when you want the AI model to trigger blocks based on attack pattern recognition. |

#### Configuration Inputs

| Input | Default | Description | How to Use |
|-------|---------|-------------|------------|
| **Rate Limit (packets/min)** | 100 | Maximum packets per IP per minute before auto-block | Lower = more aggressive (e.g., 50 blocks faster). Higher = more permissive (e.g., 500 allows more traffic). |
| **ML Confidence Threshold** | 0.8 | Minimum ML confidence (0.0-1.0) to trigger auto-block | Higher = only block when model is very sure. Lower = block more easily. |
| **ML Detection Count** | 3 | Number of DDoS detections from same IP before auto-block | Lower = block after fewer detections. Higher = require more evidence. |
| **Block Duration (minutes)** | 60 | How long blocked IPs stay blocked | Set how long an IP remains blocked before automatic unblock. |

#### Manual IP Controls

| Control | Description | How to Use |
|---------|-------------|------------|
| **Block IP** | Manually block any IP immediately | Type IP address → Click "Block". IP is blocked for the configured duration. |
| **Whitelist IP** | Never block this IP (even if rate exceeded or ML detects DDoS) | Type IP address → Click "Whitelist". Protected IP is removed from blocked list if already blocked. |
| **Blacklist IP** | Always block this IP immediately on any activity | Type IP address → Click "Blacklist". IP is blocked instantly and permanently until manually removed. |

#### Live Lists

| List | Description | Actions |
|------|-------------|---------|
| **Blocked IPs** | Shows all currently blocked IPs with reason and remaining time | Click "Unblock" to immediately remove a block. |
| **Whitelist** | Shows all whitelisted (protected) IPs | Click "Remove" to take an IP off the whitelist. |
| **Blacklist** | Shows all blacklisted (always-blocked) IPs | Click "Remove" to take an IP off the blacklist. |

#### Action Buttons

| Button | Description |
|--------|-------------|
| **Save Settings** | Saves all configuration values (rate limit, confidence, count, duration) |
| **Clear Counts** | Resets all detection counters for each IP (useful after changing thresholds) |

---

### 3. Statistics Cards

**Purpose:** Quick overview of pipeline performance and detection counts.

| Card | Description |
|------|-------------|
| **Processed Files** | Number of .pcap files successfully processed through the pipeline |
| **DDoS Detections** | Total number of flows classified as DDoS attacks by the ML model |
| **Normal Traffic** | Total number of flows classified as normal/legitimate traffic |
| **Failed Files** | Number of .pcap files that failed processing (moved to error directory) |

---

### 4. Recent Detections Table

**Purpose:** Real-time display of all classified network flows.

| Column | Description |
|--------|-------------|
| **Timestamp** | When the flow was classified (local time) |
| **Source IP** | Origin IP address of the flow |
| **Destination IP** | Target IP address of the flow |
| **Protocol** | Network protocol (TCP, UDP, ICMP, or Proto-X) |
| **Duration** | Flow duration in seconds |
| **Status** | Classification result with color-coded badge: |
| | 🔴 **DDoS** (red) — Confident ML prediction of attack |
| | 🟡 **Suspicious** (yellow) — Low-confidence DDoS prediction |
| | 🔵 **Normal** (blue) — Legitimate traffic |
| **Details** | Click "View" to see full flow details (Flow ID, packets, bytes, confidence, etc.) |

**Auto-refresh:** Updates every 5 seconds automatically.

---

### 5. Detection Statistics Chart

**Purpose:** Visual doughnut chart showing the distribution of traffic classifications.

- **Green** = Normal Traffic
- **Red** = DDoS Traffic
- **Yellow** = Suspicious

Updates automatically every 5 seconds.

---

### 6. System Status Panel

**Purpose:** Technical status of the detection system.

| Item | Description |
|------|-------------|
| **Model Status** | Whether the DRL model is loaded and ready |
| **Processing Device** | CPU or GPU used for ML inference |
| **Queue Size** | Number of feature files waiting to be processed |
| **Last Dashboard Update** | Timestamp of the last dashboard refresh |
| **Last Model Update** | Timestamp of the last model download from server |

---

## How It Works (Data Flow)

```
Network Traffic
    ↓
[Packet Capture] ───→ Rate tracking per IP (for rate-based blocking)
    ↓
.pcap files → rotated to disk every 30s or 50MB
    ↓
[File Dispatcher] ───→ moves files to in_progress/
    ↓
[Feature Extractor] ───→ extracts 81 CICFlowMeter features per flow
    ↓
Feature CSV files → saved to features_output/
    ↓
[Prediction Pipeline] ───→ DRL model classifies each flow
    ↓
Prediction results → saved to predictions/
    ↓
[Detection Callback] ───→ records detection, updates dashboard
    ↓
[Mitigation Agent] ───→ checks if IP should be auto-blocked
    ↓
Blocked IPs → enforced via mock backend (or iptables if enabled)
```

---

## Quick Start Guide

### Basic Monitoring (Detection Only)

1. Open `http://localhost:5000`
2. Click **Start Detection**
3. Watch **Recent Detections** table populate in real-time
4. Monitor **Statistics Cards** for counts
5. Click **Stop Detection** when done

### Enable Automatic Protection

1. Start the pipeline
2. In **Mitigation Control**:
   - Turn ON **Mitigation** (master toggle)
   - Turn ON **Rate-Based Auto-Block**
   - Set **Rate Limit** to `100` (packets/min)
3. IPs sending >100 packets/min are automatically blocked
4. View blocked IPs in the **Blocked IPs** list

### Enable ML-Based Protection

1. Start the pipeline
2. In **Mitigation Control**:
   - Turn ON **Mitigation** (master toggle)
   - Turn ON **ML-Based Auto-Block**
   - Set **ML Confidence Threshold** to `0.8`
   - Set **ML Detection Count** to `3`
3. IPs detected as DDoS 3+ times with ≥80% confidence are auto-blocked

### Manual Blocking

1. In **Mitigation Control**:
   - Type an IP in **Block IP** field → Click **Block**
   - Type an IP in **Whitelist IP** field → Click **Whitelist**
   - Type an IP in **Blacklist IP** field → Click **Blacklist**
2. Manage lists using the **Unblock** / **Remove** buttons

---

## Configuration (.env)

| Variable | Default | Description |
|----------|---------|-------------|
| `CAPTURE_INTERFACE` | `wlp0s20f3` | Network interface to capture on |
| `ROTATE_INTERVAL_SECONDS` | `30` | How often to rotate .pcap files |
| `MITIGATION_ENABLED` | `true` | Enable mitigation module |
| `MITIGATION_AUTO_BLOCK` | `false` | Enable rate-based auto-block at startup |
| `MITIGATION_RATE_LIMIT_ENABLED` | `true` | Enable rate limiting |
| `MITIGATION_RATE_LIMIT_PPM` | `100` | Packets per minute threshold |
| `MITIGATION_ML_AUTO_BLOCK` | `false` | Enable ML-based auto-block at startup |
| `MITIGATION_CONFIDENCE_THRESHOLD` | `0.8` | ML confidence threshold |
| `MITIGATION_DETECTION_COUNT` | `3` | Detections before auto-block |
| `MITIGATION_BLOCK_DURATION_MINUTES` | `60` | Block duration in minutes |

---

## Running the Application

```bash
# Start the application (requires sudo for packet capture)
cd /home/clg/rajesh/drl_pred_app_v1
sudo python3 app.py

# Or set capabilities instead of running as root
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))
python3 app.py
```

Dashboard available at: `http://localhost:5000`
