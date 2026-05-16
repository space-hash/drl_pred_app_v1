# core/mitigation_agent.py
"""
MitigationAgent - Receives detection events and applies mitigation actions.

This module is designed for future integration. To enable:
1. Set MITIGATION_ENABLED=true in .env
2. Set MITIGATION_AUTO_BLOCK=true to enable automatic IP blocking
3. Implement a mitigation backend (iptables, firewall API, etc.)

Architecture:
  DetectionPipeline → controller.record_detection() → mitigation_agent.on_detection()
  mitigation_agent decides action → calls backend (block/rate-limit/alert)
"""
import threading
import logging
from typing import Dict, Any, Optional, Callable
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger("MitigationAgent")


class MitigationBackend:
    """Abstract backend for mitigation actions. Override for production use."""

    def block_ip(self, ip: str, reason: str = "") -> bool:
        logger.info(f"[MOCK] Would block IP {ip}: {reason}")
        return True

    def unblock_ip(self, ip: str) -> bool:
        logger.info(f"[MOCK] Would unblock IP {ip}")
        return True

    def rate_limit(self, ip: str, max_rps: int) -> bool:
        logger.info(f"[MOCK] Would rate-limit IP {ip} to {max_rps} rps")
        return True

    def get_blocked_ips(self) -> Dict[str, str]:
        return {}


class IPTablesBackend(MitigationBackend):
    """Production backend using iptables for IP blocking."""

    def block_ip(self, ip: str, reason: str = "") -> bool:
        try:
            import subprocess
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, timeout=10
            )
            logger.warning(f"Blocked IP {ip} via iptables: {reason}")
            return True
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        try:
            import subprocess
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, timeout=10
            )
            logger.info(f"Unblocked IP {ip} via iptables")
            return True
        except Exception as e:
            logger.error(f"Failed to unblock IP {ip}: {e}")
            return False


class MitigationAgent:
    """Receives detection events and applies mitigation actions."""

    def __init__(
        self,
        auto_mitigate: bool = False,
        confidence_threshold: float = 0.8,
        detection_count_threshold: int = 3,
        block_duration_minutes: int = 60,
        backend: Optional[MitigationBackend] = None,
    ):
        self.auto_mitigate = auto_mitigate
        self.confidence_threshold = confidence_threshold
        self.detection_count_threshold = detection_count_threshold
        self.block_duration = timedelta(minutes=block_duration_minutes)
        self.backend = backend or MitigationBackend()
        self._lock = threading.Lock()
        self._blocked_ips: Dict[str, datetime] = {}
        self._detection_counts: Dict[str, list] = defaultdict(list)
        self._mitigation_log: list = []
        self._max_log_size = 1000

    def on_detection(self, detection: Dict[str, Any]) -> Optional[str]:
        """Called by controller.record_detection() for each detection."""
        status = detection.get("status", "")
        confidence = detection.get("confidence", 0.0)
        src_ip = detection.get("src_ip", "unknown")
        timestamp = datetime.now()

        if status not in ("DDoS", "Suspicious") or src_ip == "unknown":
            return None

        with self._lock:
            if src_ip in self._blocked_ips:
                expiry = self._blocked_ips[src_ip]
                if timestamp < expiry:
                    return None
                del self._blocked_ips[src_ip]

            self._detection_counts[src_ip].append(timestamp)
            recent = [
                t for t in self._detection_counts[src_ip]
                if timestamp - t < timedelta(minutes=5)
            ]
            self._detection_counts[src_ip] = recent

            if (
                self.auto_mitigate
                and len(recent) >= self.detection_count_threshold
                and confidence >= self.confidence_threshold
            ):
                self._block_ip(src_ip, timestamp, confidence, status)
                return src_ip

        return None

    def _block_ip(self, ip: str, timestamp: datetime, confidence: float, status: str):
        """Block an IP and invoke the mitigation backend."""
        expiry = timestamp + self.block_duration
        self._blocked_ips[ip] = expiry

        reason = f"{status} detected (confidence={confidence:.2f}, count={len(self._detection_counts[ip])})"
        success = self.backend.block_ip(ip, reason=reason)

        action = {
            "action": "block" if success else "block_failed",
            "ip": ip,
            "reason": reason,
            "confidence": confidence,
            "timestamp": timestamp.isoformat(),
            "expiry": expiry.isoformat(),
        }
        self._mitigation_log.append(action)
        if len(self._mitigation_log) > self._max_log_size:
            self._mitigation_log = self._mitigation_log[-self._max_log_size // 2:]

        if success:
            logger.warning(f"Blocked IP {ip} until {expiry.isoformat()}")
        else:
            logger.error(f"Failed to block IP {ip}")

    def unblock(self, ip: str) -> bool:
        """Manually unblock an IP."""
        with self._lock:
            if ip in self._blocked_ips:
                del self._blocked_ips[ip]
                success = self.backend.unblock_ip(ip)
                action = {
                    "action": "unblock" if success else "unblock_failed",
                    "ip": ip,
                    "timestamp": datetime.now().isoformat(),
                }
                self._mitigation_log.append(action)
                return success
            return False

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        with self._lock:
            expiry = self._blocked_ips.get(ip)
            if expiry and datetime.now() < expiry:
                return True
            if expiry:
                del self._blocked_ips[ip]
            return False

    def get_status(self) -> Dict[str, Any]:
        """Get current mitigation status."""
        with self._lock:
            now = datetime.now()
            active = {
                ip: exp.isoformat()
                for ip, exp in self._blocked_ips.items()
                if exp > now
            }
            return {
                "enabled": self.auto_mitigate,
                "active_blocks": active,
                "total_blocked": len(active),
                "recent_actions": self._mitigation_log[-10:],
                "confidence_threshold": self.confidence_threshold,
                "detection_count_threshold": self.detection_count_threshold,
            }
