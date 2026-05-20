# Alerting System — Multi-Channel Notification

**File:** `core/alerting.py` (462 lines)

## Overview

The Alerting System provides multi-channel notification for DDoS detection events. It supports dashboard alerts, email (SMTP), and webhooks (Slack, Discord, PagerDuty) with built-in rate limiting and deduplication.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      AlertManager                             │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │                    Channels                              │ │
│  │                                                          │ │
│  │  ┌──────────────┐ ┌────────────┐ ┌──────────────────┐  │ │
│  │  │ Dashboard    │ │  Email     │ │  Webhook         │  │ │
│  │  │ Channel      │ │  Channel   │ │  Channel         │  │ │
│  │  │              │ │  (SMTP)    │ │  (Slack/Discord/ │  │ │
│  │  │ In-memory    │ │  HTML      │ │   PagerDuty)     │  │ │
│  │  │ deque        │ │  email     │ │  JSON payload    │  │ │
│  │  └──────────────┘ └────────────┘ └──────────────────┘  │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
│  Configuration:                                               │
│  ├── enabled: bool                                            │
│  ├── rate_limit_seconds: int (default 60)                     │
│  ├── dedup_window_seconds: int (default 300)                  │
│  └── channels: Dict[name → AlertChannel]                      │
│                                                               │
│  State:                                                       │
│  ├── alert_history: deque (maxlen=1000)                       │
│  ├── _last_alert_times: Dict[type → datetime]                 │
│  ├── _alert_hashes: Dict[hash → datetime]                     │
│  └── _stats: {total_alerts, by_severity, by_type, failed}     │
└──────────────────────────────────────────────────────────────┘
```

## Alert Class

```python
class Alert:
    id: str           # Format: "YYYYMMDDHHMMSS_type_severity_uuid8"
    type: str         # "ddos_detection", "suspicious_detection", "test"
    severity: str     # "critical", "warning", "info"
    title: str        # Human-readable title
    message: str      # Detailed message
    metadata: Dict    # Additional context (src_ip, confidence, etc.)
    timestamp: datetime
    acknowledged: bool
    channels_sent: List[str]  # Which channels successfully received it
```

## Alert Channels

### DashboardChannel

In-memory notification channel for the web UI:

```python
class DashboardChannel(AlertChannel):
    alerts: deque(maxlen=100)  # Stores alert dicts

    send(alert) → True          # Appends to deque
    get_alerts(limit, severity) → List[Dict]  # Recent alerts, optionally filtered
    acknowledge(alert_id) → bool  # Mark as acknowledged
    clear_all()                 # Remove all alerts
```

### EmailChannel

SMTP-based email notifications:

```python
class EmailChannel(AlertChannel):
    smtp_host: str      # "smtp.gmail.com"
    smtp_port: int      # 587
    username: str       # Gmail address
    password: str       # App password
    from_email: str     # Sender address
    to_emails: List[str] # Recipients
    use_tls: bool       # True

    send(alert) → bool
    # Sends HTML email with:
    #   - Color-coded severity (red/orange/blue)
    #   - Alert title, type, time
    #   - Detailed message
    #   - Auto-DDoS Protection System footer
```

### WebhookChannel

HTTP webhook for Slack, Discord, and generic endpoints:

```python
class WebhookChannel(AlertChannel):
    webhook_url: str
    channel_type: str   # "slack", "discord", "generic"
    headers: Dict

    send(alert) → bool
    # Formats payload based on channel_type:

    Slack format:
    └── attachments: [{color, title, text, fields}]
        └── color: critical=#ff0000, warning=#ffaa00, info=#00aa00

    Discord format:
    └── embeds: [{title, description, color, fields}]
        └── color: critical=0xFF0000, warning=0xFFAA00, info=0x00AA00

    Generic format:
    └── alert.to_dict()  # Raw JSON
```

## Alert Flow

```
send_alert(alert_type, severity, title, message, metadata)
│
├── Create Alert object with unique ID
│
├── Rate Limiting Check:
│   └── if (now - last_alert_time[type]) < rate_limit_seconds:
│       └── Return None (skip)
│
├── Deduplication Check:
│   └── alert_hash = "{type}_{title}_{message[:50]}"
│   └── if (now - last_hash_time[hash]) < dedup_window_seconds:
│       └── Return None (skip)
│
├── Update Statistics:
│   ├── total_alerts += 1
│   ├── alerts_by_severity[severity] += 1
│   └── alerts_by_type[type] += 1
│
├── Send to Each Channel:
│   ├── For each channel_name in target_channels:
│   │   └── channel.send(alert)
│   │       ├── Success → append channel_name to alert.channels_sent
│   │       └── Failure → stats.channels_failed += 1
│
├── Store in History:
│   └── alert_history.append(alert.to_dict())
│
├── Update Tracking:
│   ├── _last_alert_times[type] = now
│   └── _alert_hashes[hash] = now
│
├── Persist to Disk:
│   └── _save_history() → data/alert_history.json
│
└── Return Alert object
```

## Alert Triggers (from Controller)

The `PipelineController.record_detection()` method triggers alerts:

| Condition | Alert Type | Severity |
|-----------|-----------|----------|
| DDoS + confidence ≥ 0.8 | `ddos_detection` | `critical` |
| Suspicious (DDoS + confidence < 0.6) | `suspicious_detection` | `warning` |

## Configuration

```python
create_alert_manager_from_config(config) → AlertManager
│
├── AlertManager(
│       enabled=ALERTING_ENABLED,
│       rate_limit_seconds=ALERTING_RATE_LIMIT_SECONDS,
│       dedup_window_seconds=ALERTING_DEDUP_WINDOW_SECONDS,
│   )
│
├── if ALERTING_EMAIL_ENABLED:
│   └── add_channel("email", EmailChannel(...))
│
├── if ALERTING_WEBHOOK_ENABLED:
│   └── add_channel("webhook", WebhookChannel(...))
│
└── Always adds DashboardChannel by default
```

## Statistics

```python
get_stats() → {
    "total_alerts": int,
    "alerts_by_severity": {"critical": int, "warning": int, "info": int},
    "alerts_by_type": {type: count},
    "channels_failed": int,
    "channels": [channel_names],
    "enabled": bool,
    "recent_alerts": int,
}
```

## Persistence

- **Save**: After each alert, writes full history to `data/alert_history.json`
- **Load**: On startup, reads history from disk into `alert_history` deque
- **Max History**: 1,000 alerts (deque maxlen)
