# DRL Mitigation Agent — AI-Powered Real-Time Blocking

**File:** `core/drl_mitigation.py` (258 lines)

## Overview

The DRL (Deep Reinforcement Learning) Mitigation Agent uses a trained PPO (Proximal Policy Optimization) neural network to make intelligent, real-time blocking decisions based on 81-dimensional CICFlowMeter flow features extracted from live network traffic.

Unlike the rate-based MitigationAgent (which uses simple thresholds), the DRL agent analyzes the full feature vector of each flow — including packet sizes, inter-arrival times, TCP flags, and flow duration — to make nuanced blocking decisions.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                   DRLMitigationAgent                          │
│                                                               │
│  ┌──────────────────┐    ┌──────────────────────────────┐    │
│  │  FlowTracker     │───▶│  DRL Model (PPO)             │    │
│  │  (core)          │    │                              │    │
│  │  81-dim features │    │  Input:  81 features         │    │
│  └──────────────────┘    │  Output: action + confidence │    │
│                          │                              │    │
│                          │  action=1 + ddos_prob≥thresh │    │
│                          │       → BLOCK IP             │    │
│                          └──────────────────────────────┘    │
│                                                               │
│  Configuration:                                               │
│  ├── model_path: str                                          │
│  ├── confidence_threshold: float (default 0.7)                │
│  ├── block_duration: timedelta (default 30 min)               │
│  ├── enabled: bool                                            │
│  └── flow_tracker: FlowTracker                                │
│                                                               │
│  State:                                                       │
│  ├── model: EnhancedPPOAgent (loaded .pt file)                │
│  ├── device: torch.device                                     │
│  ├── scaler: StandardScaler (optional)                        │
│  ├── _blocked_ips: Dict[ip → {expiry, reason, timestamp}]     │
│  ├── _decision_log: List[Dict]                                │
│  ├── _stats: {decisions_made, blocks_applied,                 │
│  │            false_positives, true_positives,                │
│  │            features_extracted}                             │
│  └── _whitelist: Set[ip]                                      │
└──────────────────────────────────────────────────────────────┘
```

## Model Loading

```python
_load_model()
│
├── EnhancedPPOAgent.load_model(model_path, map_location="cpu")
│   └── Loads PyTorch checkpoint with:
│       ├── policy.state_dict()  # Neural network weights
│       ├── optimizer.state_dict()
│       ├── scheduler.state_dict()
│       └── metadata  # Training info
│
├── Load scaler if available:
│   └── joblib.load(model_path.with_suffix('.scaler.pkl'))
│
└── self.device = torch.device("cpu")  # Always CPU for real-time
```

## Inference Flow

```
on_flow(flow_key)  # Called when FlowTracker triggers inference
│
├── Check: enabled AND model loaded AND flow_tracker available?
│
├── features = flow_tracker.get_features(flow_key)
│   └── Returns 81-dimensional list of floats
│
├── src_ip = flow_key[0]  # First element of flow tuple
├── Check: not in whitelist?
├── Check: not already blocked?
│
├── feature_array = np.array(features, dtype=np.float32)
│
├── if scaler available:
│   └── feature_array = scaler.transform(feature_array.reshape(1, -1)).flatten()
│
├── result = model.predict(feature_array, return_probs=True)
│   ├── action: 0 (Normal) or 1 (DDoS)
│   ├── confidence: max probability (0.0-1.0)
│   └── ddos_probability: probability of class 1
│
├── if action == 1 AND ddos_prob >= confidence_threshold:
│   ├── _do_block(src_ip, f"DRL block: DDoS prob=X.XXX, conf=X.XXX")
│   ├── stats.blocks_applied += 1
│   └── stats.true_positives += 1
│   └── return src_ip
│
├── elif action == 0:
│   └── stats.false_positives += 1
│
└── return None
```

## Integration with Packet Capture

The DRL agent is integrated into the packet capture pipeline through the `FlowTracker`:

```
PacketCapturer._packet_handler(packet)
│
├── Extract: src_ip, dst_ip, ports, protocol, flags, length
│
├── flow_tracker.update(...) → triggered_key or None
│   └── Triggers every INFERENCE_INTERVAL packets (default: 5)
│
├── if triggered_key:
│   └── drl_mitigation.on_flow(triggered_key)
│       └── Returns blocked IP or None
│
└── if blocked:
    └── Add to _blocked_ips set (future packets skipped)
```

## Decision Statistics

```python
get_status() → {
    "enabled": bool,
    "model_loaded": bool,
    "model_path": str,
    "confidence_threshold": float,
    "block_duration_min": int,
    "blocked_ips": [{"ip": str, "reason": str, "remaining_min": int}],
    "total_blocked": int,
    "stats": {
        "decisions_made": int,      # Total inference calls
        "blocks_applied": int,      # IPs actually blocked
        "false_positives": int,     # action=0 (normal predicted)
        "true_positives": int,      # action=1 (DDoS predicted + blocked)
        "features_extracted": int,  # Total feature vectors computed
    },
    "decision_log": [last 50 entries],
    "has_flow_tracker": bool,
}
```

## Configuration API

| Method | Effect |
|--------|--------|
| `set_enabled(bool)` | Enable/disable DRL mitigation |
| `set_confidence_threshold(float)` | Set blocking threshold (0.0-1.0) |
| `set_block_duration(int)` | Set block duration in minutes |
| `unblock_ip(ip)` | Manually unblock an IP |
| `cleanup_expired()` | Remove expired blocks |

## Key Differences from MitigationAgent

| Aspect | MitigationAgent | DRLMitigationAgent |
|--------|----------------|-------------------|
| **Decision Basis** | Simple thresholds (packets/min) | 81-dim neural network inference |
| **Speed** | Instant (counter check) | ~1-5ms (model inference) |
| **Accuracy** | Good for volumetric attacks | Better for sophisticated attacks |
| **Features Used** | Packet count only | Full CICFlowMeter feature set |
| **Adaptability** | Fixed thresholds | Learns from training data |
| **Blocking Trigger** | Every packet check | Every N packets per flow |
