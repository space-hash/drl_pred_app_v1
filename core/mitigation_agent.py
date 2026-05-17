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
- iptables integration for actual packet dropping
- Persistent blocking with disk storage
- Multi-vector DDoS detection (SYN/UDP/HTTP/ICMP flood)
"""
import threading
import logging
import subprocess
import json
import ipaddress
from pathlib import Path
from typing import Dict, Any, Optional, Set, List
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger("MitigationAgent")

BLOCKS_FILE = Path(__file__).parent.parent / "data" / "blocked_ips.json"


class FirewallManager:
    """Manages iptables/ip6tables rules for actual packet dropping."""

    @staticmethod
    def _is_ipv6(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).version == 6
        except ValueError:
            return False

    @staticmethod
    def block_ip(ip: str, chain: str = "DDOS_BLOCK") -> bool:
        """Add iptables DROP rule for an IP."""
        try:
            if FirewallManager._is_ipv6(ip):
                cmd = ["/usr/sbin/ip6tables", "-C", chain, "-s", ip, "-j", "DROP"]
                result = subprocess.run(cmd, capture_output=True, timeout=5)
                if result.returncode == 0:
                    return True  # Already blocked
                cmd = ["/usr/sbin/ip6tables", "-A", chain, "-s", ip, "-j", "DROP"]
            else:
                cmd = ["/usr/sbin/iptables", "-C", chain, "-s", ip, "-j", "DROP"]
                result = subprocess.run(cmd, capture_output=True, timeout=5)
                if result.returncode == 0:
                    return True  # Already blocked
                cmd = ["/usr/sbin/iptables", "-A", chain, "-s", ip, "-j", "DROP"]

            result = subprocess.run(cmd, capture_output=True, timeout=5)
            if result.returncode == 0:
                logger.info(f"Firewall: Blocked {ip} via {cmd[0]}")
                return True
            else:
                logger.warning(f"Firewall: Failed to block {ip}: {result.stderr.decode()}")
                return False
        except Exception as e:
            logger.warning(f"Firewall: Error blocking {ip}: {e}")
            return False

    @staticmethod
    def unblock_ip(ip: str, chain: str = "DDOS_BLOCK") -> bool:
        """Remove iptables DROP rule for an IP."""
        try:
            if FirewallManager._is_ipv6(ip):
                cmd = ["/usr/sbin/ip6tables", "-D", chain, "-s", ip, "-j", "DROP"]
            else:
                cmd = ["/usr/sbin/iptables", "-D", chain, "-s", ip, "-j", "DROP"]

            result = subprocess.run(cmd, capture_output=True, timeout=5)
            if result.returncode == 0:
                logger.info(f"Firewall: Unblocked {ip}")
                return True
            return False
        except Exception as e:
            logger.warning(f"Firewall: Error unblocking {ip}: {e}")
            return False

    @staticmethod
    def init_firewall() -> bool:
        """Initialize firewall with custom chain for DDoS protection."""
        try:
            for cmd in [
                ["iptables", "-N", "DDOS_BLOCK"],
                ["iptables", "-I", "INPUT", "-j", "DDOS_BLOCK"],
                ["ip6tables", "-N", "DDOS_BLOCK"],
                ["ip6tables", "-I", "INPUT", "-j", "DDOS_BLOCK"],
            ]:
                result = subprocess.run(cmd, capture_output=True, timeout=5)
                if result.returncode != 0 and "already exists" not in result.stderr.decode():
                    logger.warning(f"Firewall init warning: {result.stderr.decode()}")
            logger.info("Firewall: DDOS_BLOCK chain initialized")
            return True
        except Exception as e:
            logger.warning(f"Firewall init error: {e}")
            return False

    @staticmethod
    def flush_rules() -> bool:
        """Flush all DDOS_BLOCK rules."""
        try:
            for cmd in [
                ["iptables", "-F", "DDOS_BLOCK"],
                ["ip6tables", "-F", "DDOS_BLOCK"],
            ]:
                subprocess.run(cmd, capture_output=True, timeout=5)
            return True
        except Exception:
            return False


class MultiVectorDetector:
    """Detects specific DDoS attack vectors in real-time."""

    def __init__(self, syn_threshold: int = 100, udp_threshold: int = 200,
                 icmp_threshold: int = 50, http_threshold: int = 300):
        self.syn_threshold = syn_threshold
        self.udp_threshold = udp_threshold
        self.icmp_threshold = icmp_threshold
        self.http_threshold = http_threshold

        self._lock = threading.RLock()
        self._syn_counts: Dict[str, int] = defaultdict(int)
        self._udp_counts: Dict[str, int] = defaultdict(int)
        self._icmp_counts: Dict[str, int] = defaultdict(int)
        self._http_counts: Dict[str, int] = defaultdict(int)
        self._last_reset = datetime.now()

    def on_packet(self, src_ip: str, protocol: int, dst_port: int = 0, flags: int = 0) -> Optional[str]:
        """Analyze packet and return attack type if threshold exceeded."""
        with self._lock:
            # Reset counters every minute
            if (datetime.now() - self._last_reset).total_seconds() > 60:
                self._syn_counts.clear()
                self._udp_counts.clear()
                self._icmp_counts.clear()
                self._http_counts.clear()
                self._last_reset = datetime.now()

            # SYN flood detection (TCP SYN without ACK)
            if protocol == 6 and (flags & 0x02) and not (flags & 0x10):
                self._syn_counts[src_ip] += 1
                if self._syn_counts[src_ip] > self.syn_threshold:
                    return f"SYN flood ({self._syn_counts[src_ip]} SYN/min)"

            # UDP flood detection
            if protocol == 17:
                self._udp_counts[src_ip] += 1
                if self._udp_counts[src_ip] > self.udp_threshold:
                    return f"UDP flood ({self._udp_counts[src_ip]} UDP/min)"

            # ICMP flood detection
            if protocol == 1:
                self._icmp_counts[src_ip] += 1
                if self._icmp_counts[src_ip] > self.icmp_threshold:
                    return f"ICMP flood ({self._icmp_counts[src_ip]} ICMP/min)"

            # HTTP flood detection (port 80/443)
            if protocol == 6 and dst_port in (80, 443, 8080):
                self._http_counts[src_ip] += 1
                if self._http_counts[src_ip] > self.http_threshold:
                    return f"HTTP flood ({self._http_counts[src_ip]} HTTP/min)"

        return None

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "syn_flood_ips": len([ip for ip, count in self._syn_counts.items() if count > self.syn_threshold]),
                "udp_flood_ips": len([ip for ip, count in self._udp_counts.items() if count > self.udp_threshold]),
                "icmp_flood_ips": len([ip for ip, count in self._icmp_counts.items() if count > self.icmp_threshold]),
                "http_flood_ips": len([ip for ip, count in self._http_counts.items() if count > self.http_threshold]),
            }


class MitigationAgent:
    """Mitigation agent with rate-based + ML-based blocking + iptables enforcement."""

    def __init__(
        self,
        auto_block: bool = False,
        rate_limit_enabled: bool = True,
        rate_limit_ppm: int = 100,
        ml_auto_block: bool = False,
        confidence_threshold: float = 0.8,
        detection_count: int = 3,
        block_duration_minutes: int = 60,
        use_iptables: bool = True,
    ):
        self.auto_block = auto_block
        self.rate_limit_enabled = rate_limit_enabled
        self.rate_limit_ppm = rate_limit_ppm
        self.ml_auto_block = ml_auto_block
        self.confidence_threshold = confidence_threshold
        self.detection_count = detection_count
        self.block_duration = timedelta(minutes=block_duration_minutes)
        self.use_iptables = use_iptables

        self._lock = threading.RLock()
        self._blocked_ips: Dict[str, Dict[str, Any]] = {}
        self._whitelist: Set[str] = set()
        self._blacklist: Set[str] = set()
        self._detection_counts: Dict[str, int] = {}
        self._packet_counts: Dict[str, List[datetime]] = defaultdict(list)
        self._log: List[Dict[str, Any]] = []

        # Multi-vector detector
        self.vector_detector = MultiVectorDetector()

        # Initialize firewall if enabled
        if self.use_iptables:
            FirewallManager.init_firewall()
            self._restore_blocks()

    def _save_blocks(self):
        """Persist blocked IPs to disk."""
        try:
            data = {
                ip: {
                    "expiry": info["expiry"].isoformat(),
                    "reason": info["reason"],
                    "timestamp": info["timestamp"].isoformat(),
                }
                for ip, info in self._blocked_ips.items()
                if info["expiry"] > datetime.now()
            }
            BLOCKS_FILE.parent.mkdir(parents=True, exist_ok=True)
            BLOCKS_FILE.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.error(f"Failed to save blocks: {e}")

    def _restore_blocks(self):
        """Restore blocked IPs from disk on startup."""
        if not BLOCKS_FILE.exists():
            return
        try:
            data = json.loads(BLOCKS_FILE.read_text())
            now = datetime.now()
            for ip, info in data.items():
                expiry = datetime.fromisoformat(info["expiry"])
                if expiry > now:
                    self._blocked_ips[ip] = {
                        "expiry": expiry,
                        "reason": info["reason"],
                        "timestamp": datetime.fromisoformat(info["timestamp"]),
                    }
                    if self.use_iptables:
                        FirewallManager.block_ip(ip)
            logger.info(f"Restored {len(self._blocked_ips)} blocked IPs from disk")
        except Exception as e:
            logger.error(f"Failed to restore blocks: {e}")

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

    def on_packet_vector(self, src_ip: str, protocol: int, dst_port: int = 0, flags: int = 0) -> Optional[str]:
        """Called for packet vector analysis. Returns attack type if detected."""
        attack = self.vector_detector.on_packet(src_ip, protocol, dst_port, flags)
        if attack:
            with self._lock:
                if src_ip not in self._blocked_ips and src_ip not in self._whitelist:
                    self._do_block(src_ip, f"Multi-vector: {attack}")
                    return attack
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

        # Enforce via iptables
        if self.use_iptables:
            FirewallManager.block_ip(ip)

        # Persist to disk
        self._save_blocks()

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
                if self.use_iptables:
                    FirewallManager.unblock_ip(ip)
                self._save_blocks()
                return True
        return False

    def add_whitelist(self, ip: str):
        with self._lock:
            self._whitelist.add(ip)
            if ip in self._blocked_ips:
                self.unblock_ip(ip)

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
            vector_stats = self.vector_detector.get_stats()

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
                "vector_stats": vector_stats,
                "log": self._log[-50:],
                "use_iptables": self.use_iptables,
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

    def cleanup_expired(self):
        """Remove expired blocks from iptables and memory."""
        now = datetime.now()
        with self._lock:
            expired = [ip for ip, info in self._blocked_ips.items() if info["expiry"] <= now]
            for ip in expired:
                del self._blocked_ips[ip]
                if self.use_iptables:
                    FirewallManager.unblock_ip(ip)
            if expired:
                logger.info(f"Cleaned up {len(expired)} expired blocks")
                self._save_blocks()
