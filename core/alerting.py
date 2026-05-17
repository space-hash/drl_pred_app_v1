# core/alerting.py
"""
Alerting System for DDoS detection notifications.

Supports multiple notification channels:
- Dashboard notifications (in-app alerts)
- Email alerts
- Webhook notifications (Slack, Discord, PagerDuty, etc.)
- Log-based alerts

Features:
- Configurable alert thresholds
- Alert deduplication and rate limiting
- Multiple notification channels
- Alert history and statistics
- Custom alert templates
"""
import threading
import logging
import json
import smtplib
import requests
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import deque

logger = logging.getLogger("Alerting")

ALERTS_FILE = Path(__file__).parent.parent / "data" / "alert_history.json"


class Alert:
    """Represents a single alert notification."""

    def __init__(
        self,
        alert_type: str,
        severity: str,
        title: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.id = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{alert_type}_{severity}"
        self.type = alert_type
        self.severity = severity
        self.title = title
        self.message = message
        self.metadata = metadata or {}
        self.timestamp = datetime.now()
        self.acknowledged = False
        self.channels_sent: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
            "acknowledged": self.acknowledged,
            "channels_sent": self.channels_sent,
        }


class AlertChannel:
    """Base class for alert notification channels."""

    def send(self, alert: Alert) -> bool:
        raise NotImplementedError


class DashboardChannel(AlertChannel):
    """In-app dashboard notification channel."""

    def __init__(self, max_alerts: int = 100):
        self.alerts: deque = deque(maxlen=max_alerts)
        self._lock = threading.RLock()

    def send(self, alert: Alert) -> bool:
        with self._lock:
            self.alerts.append(alert.to_dict())
            return True

    def get_alerts(self, limit: int = 20, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            alerts = list(self.alerts)
            if severity:
                alerts = [a for a in alerts if a["severity"] == severity]
            return list(reversed(alerts[-limit:]))

    def acknowledge(self, alert_id: str) -> bool:
        with self._lock:
            for alert in self.alerts:
                if alert["id"] == alert_id:
                    alert["acknowledged"] = True
                    return True
            return False

    def clear_all(self):
        with self._lock:
            self.alerts.clear()


class EmailChannel(AlertChannel):
    """Email notification channel."""

    def __init__(
        self,
        smtp_host: str = "smtp.gmail.com",
        smtp_port: int = 587,
        username: str = "",
        password: str = "",
        from_email: str = "",
        to_emails: Optional[List[str]] = None,
        use_tls: bool = True,
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_email = from_email
        self.to_emails = to_emails or []
        self.use_tls = use_tls
        self.enabled = bool(username and password and from_email and self.to_emails)

    def send(self, alert: Alert) -> bool:
        if not self.enabled:
            return False

        try:
            msg = MIMEMultipart()
            msg["From"] = self.from_email
            msg["To"] = ", ".join(self.to_emails)
            msg["Subject"] = f"[DDoS Alert] [{alert.severity.upper()}] {alert.title}"

            body = f"""
            <html>
            <body>
                <h2 style="color: {'red' if alert.severity == 'critical' else 'orange' if alert.severity == 'warning' else 'blue'}">
                    {alert.title}
                </h2>
                <p><strong>Severity:</strong> {alert.severity.upper()}</p>
                <p><strong>Type:</strong> {alert.type}</p>
                <p><strong>Time:</strong> {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <hr>
                <p>{alert.message}</p>
                <hr>
                <p><small>This is an automated alert from the DDoS Protection System.</small></p>
            </body>
            </html>
            """
            msg.attach(MIMEText(body, "html"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.send_message(msg)

            logger.info(f"Email alert sent to {self.to_emails}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False


class WebhookChannel(AlertChannel):
    """Webhook notification channel (Slack, Discord, PagerDuty, etc.)."""

    def __init__(
        self,
        webhook_url: str = "",
        channel_type: str = "generic",
        headers: Optional[Dict[str, str]] = None,
    ):
        self.webhook_url = webhook_url
        self.channel_type = channel_type
        self.headers = headers or {}
        self.enabled = bool(webhook_url)

    def send(self, alert: Alert) -> bool:
        if not self.enabled:
            return False

        try:
            payload = self._format_payload(alert)
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers=self.headers,
                timeout=10,
            )
            response.raise_for_status()
            logger.info(f"Webhook alert sent to {self.channel_type}")
            return True
        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
            return False

    def _format_payload(self, alert: Alert) -> Dict[str, Any]:
        """Format alert payload for different webhook types."""
        if self.channel_type == "slack":
            color = {
                "critical": "#ff0000",
                "warning": "#ffaa00",
                "info": "#00aa00",
            }.get(alert.severity, "#000000")

            return {
                "attachments": [
                    {
                        "color": color,
                        "title": alert.title,
                        "text": alert.message,
                        "fields": [
                            {"title": "Severity", "value": alert.severity.upper(), "short": True},
                            {"title": "Type", "value": alert.type, "short": True},
                            {"title": "Time", "value": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "short": True},
                        ],
                    }
                ]
            }
        elif self.channel_type == "discord":
            color = {
                "critical": 0xFF0000,
                "warning": 0xFFAA00,
                "info": 0x00AA00,
            }.get(alert.severity, 0x000000)

            return {
                "embeds": [
                    {
                        "title": alert.title,
                        "description": alert.message,
                        "color": color,
                        "fields": [
                            {"name": "Severity", "value": alert.severity.upper(), "inline": True},
                            {"name": "Type", "value": alert.type, "inline": True},
                            {"name": "Time", "value": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S"), "inline": True},
                        ],
                    }
                ]
            }
        else:
            return alert.to_dict()


class AlertManager:
    """
    Central alert management system.

    Coordinates multiple notification channels and provides:
    - Alert creation and routing
    - Deduplication and rate limiting
    - Alert history and statistics
    - Channel configuration
    """

    def __init__(
        self,
        enabled: bool = True,
        rate_limit_seconds: int = 60,
        dedup_window_seconds: int = 300,
    ):
        self.enabled = enabled
        self.rate_limit_seconds = rate_limit_seconds
        self.dedup_window_seconds = dedup_window_seconds

        self._lock = threading.RLock()
        self.channels: Dict[str, AlertChannel] = {}
        self.alert_history: deque = deque(maxlen=1000)
        self._last_alert_times: Dict[str, datetime] = {}
        self._alert_hashes: Dict[str, datetime] = {}
        self._stats = {
            "total_alerts": 0,
            "alerts_by_severity": {"critical": 0, "warning": 0, "info": 0},
            "alerts_by_type": {},
            "channels_failed": 0,
        }

        # Add default dashboard channel
        self.add_channel("dashboard", DashboardChannel())

    def add_channel(self, name: str, channel: AlertChannel):
        """Add a notification channel."""
        with self._lock:
            self.channels[name] = channel
            logger.info(f"Alert channel added: {name}")

    def remove_channel(self, name: str):
        """Remove a notification channel."""
        with self._lock:
            if name in self.channels:
                del self.channels[name]
                logger.info(f"Alert channel removed: {name}")

    def send_alert(
        self,
        alert_type: str,
        severity: str,
        title: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
        channels: Optional[List[str]] = None,
    ) -> Optional[Alert]:
        """Create and send an alert through configured channels."""
        if not self.enabled:
            return None

        alert = Alert(alert_type, severity, title, message, metadata)

        with self._lock:
            # Check rate limiting
            if self._is_rate_limited(alert_type):
                logger.debug(f"Alert rate limited: {alert_type}")
                return None

            # Check deduplication
            alert_hash = f"{alert_type}_{title}_{message[:50]}"
            if self._is_duplicate(alert_hash):
                logger.debug(f"Alert deduplicated: {alert_hash}")
                return None

            # Update stats
            self._stats["total_alerts"] += 1
            self._stats["alerts_by_severity"][severity] = self._stats["alerts_by_severity"].get(severity, 0) + 1
            self._stats["alerts_by_type"][alert_type] = self._stats["alerts_by_type"].get(alert_type, 0) + 1

            # Send to channels
            target_channels = channels or list(self.channels.keys())
            for channel_name in target_channels:
                if channel_name in self.channels:
                    try:
                        success = self.channels[channel_name].send(alert)
                        if success:
                            alert.channels_sent.append(channel_name)
                        else:
                            self._stats["channels_failed"] += 1
                    except Exception as e:
                        logger.error(f"Failed to send alert to {channel_name}: {e}")
                        self._stats["channels_failed"] += 1

            # Store in history
            self.alert_history.append(alert.to_dict())
            self._last_alert_times[alert_type] = datetime.now()
            self._alert_hashes[alert_hash] = datetime.now()

            # Persist to disk
            self._save_history()

            logger.info(f"Alert sent: [{severity}] {title}")
            return alert

    def _is_rate_limited(self, alert_type: str) -> bool:
        """Check if alert type is rate limited."""
        if alert_type not in self._last_alert_times:
            return False
        elapsed = (datetime.now() - self._last_alert_times[alert_type]).total_seconds()
        return elapsed < self.rate_limit_seconds

    def _is_duplicate(self, alert_hash: str) -> bool:
        """Check if alert is a duplicate."""
        if alert_hash not in self._alert_hashes:
            return False
        elapsed = (datetime.now() - self._alert_hashes[alert_hash]).total_seconds()
        return elapsed < self.dedup_window_seconds

    def get_alerts(self, limit: int = 20, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get recent alerts."""
        with self._lock:
            alerts = list(self.alert_history)
            if severity:
                alerts = [a for a in alerts if a["severity"] == severity]
            return list(reversed(alerts[-limit:]))

    def get_stats(self) -> Dict[str, Any]:
        """Get alert statistics."""
        with self._lock:
            return {
                **self._stats,
                "channels": list(self.channels.keys()),
                "enabled": self.enabled,
                "recent_alerts": len(self.alert_history),
            }

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert."""
        with self._lock:
            for alert in self.alert_history:
                if alert["id"] == alert_id:
                    alert["acknowledged"] = True
                    return True
            return False

    def clear_alerts(self):
        """Clear all alerts."""
        with self._lock:
            self.alert_history.clear()
            if "dashboard" in self.channels:
                self.channels["dashboard"].clear_all()

    def _save_history(self):
        """Persist alert history to disk."""
        try:
            data = [alert for alert in self.alert_history]
            ALERTS_FILE.parent.mkdir(parents=True, exist_ok=True)
            ALERTS_FILE.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.error(f"Failed to save alert history: {e}")

    def load_history(self):
        """Load alert history from disk."""
        if not ALERTS_FILE.exists():
            return
        try:
            data = json.loads(ALERTS_FILE.read_text())
            self.alert_history = deque(data, maxlen=1000)
            logger.info(f"Loaded {len(self.alert_history)} alerts from history")
        except Exception as e:
            logger.error(f"Failed to load alert history: {e}")


def create_alert_manager_from_config(config: Any) -> AlertManager:
    """Create AlertManager from configuration object."""
    manager = AlertManager(
        enabled=getattr(config, "ALERTING_ENABLED", True),
        rate_limit_seconds=getattr(config, "ALERTING_RATE_LIMIT_SECONDS", 60),
        dedup_window_seconds=getattr(config, "ALERTING_DEDUP_WINDOW_SECONDS", 300),
    )

    # Email channel
    email_enabled = getattr(config, "ALERTING_EMAIL_ENABLED", False)
    if email_enabled:
        email_channel = EmailChannel(
            smtp_host=getattr(config, "ALERTING_EMAIL_SMTP_HOST", "smtp.gmail.com"),
            smtp_port=getattr(config, "ALERTING_EMAIL_SMTP_PORT", 587),
            username=getattr(config, "ALERTING_EMAIL_USERNAME", ""),
            password=getattr(config, "ALERTING_EMAIL_PASSWORD", ""),
            from_email=getattr(config, "ALERTING_EMAIL_FROM", ""),
            to_emails=getattr(config, "ALERTING_EMAIL_TO", []),
        )
        if email_channel.enabled:
            manager.add_channel("email", email_channel)

    # Webhook channel
    webhook_enabled = getattr(config, "ALERTING_WEBHOOK_ENABLED", False)
    if webhook_enabled:
        webhook_channel = WebhookChannel(
            webhook_url=getattr(config, "ALERTING_WEBHOOK_URL", ""),
            channel_type=getattr(config, "ALERTING_WEBHOOK_TYPE", "generic"),
        )
        if webhook_channel.enabled:
            manager.add_channel("webhook", webhook_channel)

    return manager
