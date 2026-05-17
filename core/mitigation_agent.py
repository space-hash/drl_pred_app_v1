# core/mitigation_agent.py
"""
Mitigation Agent with Rate-Based Auto-Block and Dashboard Controls.

Features:
- Rate-based auto-block: Block IPs sending >N packets per minute (default 100)
- ML-based auto-block: Block IPs after N DDoS detections with high confidence
- Manual block/unblock from dashboard
- Whitelist: Never block these IPs
- Blacklist: Always block these IPs
- All features toggleable from dashboard
"""
import threading
import logging
from typing import Dict, Any, Optional, Set, List
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger("MitigationAgent")


class MitigationAgent:
    """Mitigation agent with rate-based + ML-based blocking."""

    def __init__(
        self,
        auto_block: bool = False,
        rate_limit_enabled: bool = True,
        rate_limit_ppm: int = 100,
        ml_auto_block: bool = False,
        confidence_threshold: float = 0.8,
        detection_count: int = 3,
        block_duration_minutes: int = 60,
    ):
        self.auto_block = auto_block
        self.rate_limit_enabled = rate_limit_enabled
        self.rate_limit_ppm = rate_limit_ppm
        self.ml_auto_block = ml_auto_block
        self.confidence_threshold = confidence_threshold
        self.detection_count = detection_count
        self.block_duration = timedelta(minutes=block_duration_minutes)

        self._lock = threading.RLock()
        self._blocked_ips: Dict[str, Dict[str, Any]] = {}
        self._whitelist: Set[str] = set()
        self._blacklist: Set[str] = set()
        self._detection_counts: Dict[str, int] = {}
        self._packet_counts: Dict[str, List[datetime]] = defaultdict(list)
        self._log: List[Dict[str, Any]] = []

    def on_detection(self, detection: Dict[str, Any]) -> Optional[str]:
        """Called for each ML detection. Returns blocked IP or None."""
        src_ip = detection.get("src_ip", "unknown")
        if src_ip == "unknown":
            return None

        with self._lock:
            if src_ip in self._whitelist:
                return None
            if src_ip in self._blocked_ips:
                return None
            if src_ip in self._blacklist:
                self._do_block(src_ip, "Blacklisted (ML detection)")
                return src_ip

            if self.ml_auto_block:
                status = detection.get("status", "")
                confidence = detection.get("confidence", 0.0)
                if status in ("DDoS", "Suspicious"):
                    self._detection_counts[src_ip] = self._detection_counts.get(src_ip, 0) + 1
                    if self._detection_counts[src_ip] >= self.detection_count and confidence >= self.confidence_threshold:
                        self._do_block(src_ip, f"ML auto-block: {status} (conf={confidence:.2f})")
                        return src_ip

        return None

    def on_packet(self, src_ip: str) -> Optional[str]:
        """Called for every packet. Returns blocked IP if rate exceeded."""
        if not self.auto_block or not self.rate_limit_enabled:
            return None
        if src_ip == "unknown":
            return None

        with self._lock:
            if src_ip in self._whitelist:
                return None
            if src_ip in self._blocked_ips:
                return None
            if src_ip in self._blacklist:
                self._do_block(src_ip, "Blacklisted (packet)")
                return src_ip

            now = datetime.now()
            cutoff = now - timedelta(minutes=1)
            self._packet_counts[src_ip] = [t for t in self._packet_counts[src_ip] if t > cutoff]
            self._packet_counts[src_ip].append(now)

            if len(self._packet_counts[src_ip]) > self.rate_limit_ppm:
                self._do_block(src_ip, f"Rate limit: {len(self._packet_counts[src_ip])} packets/min (limit={self.rate_limit_ppm})")
                del self._packet_counts[src_ip]
                return src_ip

        return None

    def _do_block(self, ip: str, reason: str):
        expiry = datetime.now() + self.block_duration
        self._blocked_ips[ip] = {"expiry": expiry, "reason": reason, "timestamp": datetime.now()}
        self._log.append({
            "action": "block",
            "ip": ip,
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
            "expiry": expiry.isoformat(),
        })
        logger.warning(f"Blocked {ip}: {reason}")

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked (not expired)."""
        with self._lock:
            if ip not in self._blocked_ips:
                return False
            return self._blocked_ips[ip]["expiry"] > datetime.now()

    def block_ip(self, ip: str, reason: str = "Manual block") -> bool:
        with self._lock:
            self._do_block(ip, reason)
        return True

    def unblock_ip(self, ip: str) -> bool:
        with self._lock:
            if ip in self._blocked_ips:
                del self._blocked_ips[ip]
                self._log.append({"action": "unblock", "ip": ip, "timestamp": datetime.now().isoformat()})
                return True
        return False

    def add_whitelist(self, ip: str):
        with self._lock:
            self._whitelist.add(ip)
            self._blocked_ips.pop(ip, None)

    def remove_whitelist(self, ip: str):
        with self._lock:
            self._whitelist.discard(ip)

    def add_blacklist(self, ip: str):
        with self._lock:
            self._blacklist.add(ip)
            self._do_block(ip, "Blacklisted")

    def remove_blacklist(self, ip: str):
        with self._lock:
            self._blacklist.discard(ip)

    def clear_detection_counts(self):
        with self._lock:
            self._detection_counts.clear()

    def get_packet_rates(self) -> Dict[str, int]:
        now = datetime.now()
        cutoff = now - timedelta(minutes=1)
        with self._lock:
            return {ip: len([t for t in times if t > cutoff]) for ip, times in self._packet_counts.items() if times}

    def get_status(self) -> Dict[str, Any]:
        now = datetime.now()
        with self._lock:
            active = []
            expired = []
            for ip, info in self._blocked_ips.items():
                if info["expiry"] > now:
                    remaining = int((info["expiry"] - now).total_seconds() / 60)
                    active.append({"ip": ip, "reason": info["reason"], "remaining_min": remaining})
                else:
                    expired.append(ip)
            for ip in expired:
                del self._blocked_ips[ip]

            rates = self.get_packet_rates()

            return {
                "enabled": self.auto_block or self.rate_limit_enabled or self.ml_auto_block,
                "auto_block": self.auto_block,
                "rate_limit_enabled": self.rate_limit_enabled,
                "rate_limit_ppm": self.rate_limit_ppm,
                "ml_auto_block": self.ml_auto_block,
                "confidence_threshold": self.confidence_threshold,
                "detection_count": self.detection_count,
                "block_duration_min": int(self.block_duration.total_seconds() / 60),
                "blocked_ips": active,
                "total_blocked": len(active),
                "whitelist": list(self._whitelist),
                "blacklist": list(self._blacklist),
                "detection_counts": dict(self._detection_counts),
                "packet_rates": rates,
                "log": self._log[-50:],
            }

    def set_auto_block(self, enabled: bool):
        self.auto_block = enabled

    def set_enabled(self, enabled: bool):
        self.auto_block = enabled
        self.rate_limit_enabled = enabled
        self.ml_auto_block = enabled

    def set_rate_limit_enabled(self, enabled: bool):
        self.rate_limit_enabled = enabled

    def set_rate_limit_ppm(self, val: int):
        self.rate_limit_ppm = max(10, val)

    def set_ml_auto_block(self, enabled: bool):
        self.ml_auto_block = enabled

    def set_confidence(self, val: float):
        self.confidence_threshold = max(0.0, min(1.0, val))

    def set_detection_count(self, val: int):
        self.detection_count = max(1, val)

    def set_block_duration(self, val: int):
        self.block_duration = timedelta(minutes=max(1, val))
