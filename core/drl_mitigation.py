# core/drl_mitigation.py
"""
DRL-based Mitigation Agent for adaptive DDoS protection.

Uses the trained DRL model to make intelligent blocking decisions based on:
- Real-time traffic patterns
- Historical attack data
- Adaptive threshold adjustment
- Multi-dimensional feature analysis

Features:
- DRL model inference for blocking decisions
- Adaptive rate limiting based on traffic conditions
- Feature extraction from live traffic
- Confidence-based blocking with adjustable thresholds
- Integration with existing mitigation pipeline
"""
import threading
import logging
import numpy as np
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque

logger = logging.getLogger("DRLMitigation")

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch not available, DRL mitigation disabled")


class DRLMitigationAgent:
    """
    DRL-based mitigation agent that uses the trained model for adaptive blocking.

    This agent extracts features from live traffic and uses the DRL model to
    make intelligent blocking decisions, adapting to changing attack patterns.
    """

    def __init__(
        self,
        model_path: str = "",
        confidence_threshold: float = 0.7,
        block_duration_minutes: int = 30,
        feature_window_size: int = 10,
        enabled: bool = True,
    ):
        self.confidence_threshold = confidence_threshold
        self.block_duration = timedelta(minutes=block_duration_minutes)
        self.feature_window_size = feature_window_size
        self.enabled = enabled
        self.model_path = model_path

        self._lock = threading.RLock()
        self._blocked_ips: Dict[str, Dict[str, Any]] = {}
        self._traffic_features: Dict[str, deque] = defaultdict(lambda: deque(maxlen=feature_window_size))
        self._decision_log: List[Dict[str, Any]] = []
        self._stats = {
            "decisions_made": 0,
            "blocks_applied": 0,
            "false_positives": 0,
            "true_positives": 0,
        }

        # Load DRL model
        self.model = None
        self.device = None
        if TORCH_AVAILABLE and model_path and Path(model_path).exists():
            self._load_model()

    def _load_model(self):
        """Load the trained DRL model."""
        try:
            from detection_module.detection import EnhancedPPOAgent, FLOW_FEATURE_DIM

            self.model = EnhancedPPOAgent.load_model(self.model_path, map_location="cpu")
            self.device = torch.device("cpu")
            self.feature_dim = FLOW_FEATURE_DIM
            logger.info(f"DRL model loaded from {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to load DRL model: {e}")
            self.model = None

    def extract_features(self, src_ip: str, packet_info: Dict[str, Any]) -> Optional[np.ndarray]:
        """
        Extract flow features from packet information for DRL model input.

        Args:
            src_ip: Source IP address
            packet_info: Dictionary containing packet details:
                - protocol: int (6=TCP, 17=UDP, 1=ICMP)
                - dst_port: int
                - flags: int (TCP flags)
                - packet_size: int
                - flow_duration: float (microseconds)
                - fwd_packets: int
                - bwd_packets: int
                - fwd_bytes: int
                - bwd_bytes: int

        Returns:
            numpy array of shape (81,) or None if insufficient data
        """
        if not self.enabled or not self.model:
            return None

        with self._lock:
            features = self._traffic_features[src_ip]
            features.append(packet_info)

            if len(features) < self.feature_window_size:
                return None

            # Aggregate features over window
            agg = self._aggregate_features(features)
            return agg

    def _aggregate_features(self, features: deque) -> np.ndarray:
        """Aggregate packet features into a single feature vector."""
        # Initialize 81-dimensional feature vector
        feature_vec = np.zeros(81, dtype=np.float32)

        if not features:
            return feature_vec

        # Basic flow statistics
        protocols = [f.get("protocol", 0) for f in features]
        dst_ports = [f.get("dst_port", 0) for f in features]
        packet_sizes = [f.get("packet_size", 0) for f in features]
        fwd_packets = [f.get("fwd_packets", 0) for f in features]
        bwd_packets = [f.get("bwd_packets", 0) for f in features]
        fwd_bytes = [f.get("fwd_bytes", 0) for f in features]
        bwd_bytes = [f.get("bwd_bytes", 0) for f in features]
        flow_durations = [f.get("flow_duration", 0) for f in features]

        # Fill feature vector with aggregated statistics
        feature_vec[0] = np.mean(packet_sizes)
        feature_vec[1] = np.std(packet_sizes)
        feature_vec[2] = np.max(packet_sizes)
        feature_vec[3] = np.min(packet_sizes)

        feature_vec[4] = np.sum(fwd_packets)
        feature_vec[5] = np.sum(bwd_packets)
        feature_vec[6] = np.mean(fwd_packets)
        feature_vec[7] = np.mean(bwd_packets)

        feature_vec[8] = np.sum(fwd_bytes)
        feature_vec[9] = np.sum(bwd_bytes)
        feature_vec[10] = np.mean(fwd_bytes)
        feature_vec[11] = np.mean(bwd_bytes)

        feature_vec[12] = np.mean(flow_durations)
        feature_vec[13] = np.std(flow_durations)
        feature_vec[14] = np.max(flow_durations)

        # Protocol distribution
        for proto in protocols:
            if 0 <= proto < 81:
                feature_vec[proto] += 1

        # Port statistics
        feature_vec[15] = len(set(dst_ports))  # Unique ports
        feature_vec[16] = np.mean(dst_ports)
        feature_vec[17] = np.std(dst_ports)

        # Rate features
        time_span = max(1, (datetime.now() - features[0].get("timestamp", datetime.now())).total_seconds())
        feature_vec[18] = len(features) / time_span  # Packets per second
        feature_vec[19] = sum(packet_sizes) / time_span  # Bytes per second

        # TCP flag analysis
        tcp_flags = [f.get("flags", 0) for f in features if f.get("protocol") == 6]
        if tcp_flags:
            syn_count = sum(1 for f in tcp_flags if f & 0x02 and not f & 0x10)
            ack_count = sum(1 for f in tcp_flags if f & 0x10)
            rst_count = sum(1 for f in tcp_flags if f & 0x04)
            fin_count = sum(1 for f in tcp_flags if f & 0x01)

            feature_vec[20] = syn_count
            feature_vec[21] = ack_count
            feature_vec[22] = rst_count
            feature_vec[23] = fin_count
            feature_vec[24] = syn_count / max(1, len(tcp_flags))  # SYN ratio

        # Fill remaining features with normalized values
        for i in range(25, 81):
            if i < len(features):
                f = features[i % len(features)]
                feature_vec[i] = f.get("packet_size", 0) / 1500.0  # Normalize to MTU

        return feature_vec

    def on_packet(self, src_ip: str, packet_info: Dict[str, Any]) -> Optional[str]:
        """
        Process packet and decide whether to block using DRL model.

        Args:
            src_ip: Source IP address
            packet_info: Dictionary with packet details

        Returns:
            IP address if blocked, None otherwise
        """
        if not self.enabled or not self.model:
            return None

        with self._lock:
            if src_ip in self._blocked_ips:
                return None

        features = self.extract_features(src_ip, packet_info)
        if features is None:
            return None

        try:
            result = self.model.predict(features, return_probs=True)
            action = result["action"]
            confidence = result["confidence"]
            ddos_prob = result["ddos_probability"]

            with self._lock:
                self._stats["decisions_made"] += 1

                if action == 1 and ddos_prob >= self.confidence_threshold:
                    self._do_block(src_ip, f"DRL block: DDoS prob={ddos_prob:.3f}, conf={confidence:.3f}")
                    self._stats["blocks_applied"] += 1
                    self._stats["true_positives"] += 1
                    return src_ip
                elif action == 0:
                    self._stats["false_positives"] += 1

            return None
        except Exception as e:
            logger.error(f"DRL prediction failed for {src_ip}: {e}")
            return None

    def _do_block(self, ip: str, reason: str):
        """Block an IP address."""
        expiry = datetime.now() + self.block_duration
        self._blocked_ips[ip] = {
            "expiry": expiry,
            "reason": reason,
            "timestamp": datetime.now(),
        }
        self._decision_log.append({
            "action": "block",
            "ip": ip,
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
            "expiry": expiry.isoformat(),
        })
        logger.warning(f"DRL blocked {ip}: {reason}")

    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address."""
        with self._lock:
            if ip in self._blocked_ips:
                del self._blocked_ips[ip]
                self._decision_log.append({
                    "action": "unblock",
                    "ip": ip,
                    "timestamp": datetime.now().isoformat(),
                })
                logger.info(f"DRL unblocked {ip}")
                return True
        return False

    def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked."""
        with self._lock:
            if ip not in self._blocked_ips:
                return False
            return self._blocked_ips[ip]["expiry"] > datetime.now()

    def get_status(self) -> Dict[str, Any]:
        """Get DRL mitigation status."""
        now = datetime.now()
        with self._lock:
            active_blocks = []
            expired = []
            for ip, info in self._blocked_ips.items():
                if info["expiry"] > now:
                    remaining = int((info["expiry"] - now).total_seconds() / 60)
                    active_blocks.append({
                        "ip": ip,
                        "reason": info["reason"],
                        "remaining_min": remaining,
                    })
                else:
                    expired.append(ip)

            for ip in expired:
                del self._blocked_ips[ip]

            return {
                "enabled": self.enabled,
                "model_loaded": self.model is not None,
                "model_path": self.model_path,
                "confidence_threshold": self.confidence_threshold,
                "block_duration_min": int(self.block_duration.total_seconds() / 60),
                "blocked_ips": active_blocks,
                "total_blocked": len(active_blocks),
                "stats": self._stats,
                "decision_log": self._decision_log[-50:],
                "feature_window_size": self.feature_window_size,
            }

    def set_enabled(self, enabled: bool):
        """Enable or disable DRL mitigation."""
        self.enabled = enabled
        logger.info(f"DRL mitigation {'enabled' if enabled else 'disabled'}")

    def set_confidence_threshold(self, threshold: float):
        """Set confidence threshold for blocking."""
        self.confidence_threshold = max(0.0, min(1.0, threshold))

    def set_block_duration(self, minutes: int):
        """Set block duration in minutes."""
        self.block_duration = timedelta(minutes=max(1, minutes))

    def cleanup_expired(self):
        """Remove expired blocks."""
        now = datetime.now()
        with self._lock:
            expired = [ip for ip, info in self._blocked_ips.items() if info["expiry"] <= now]
            for ip in expired:
                del self._blocked_ips[ip]
            if expired:
                logger.info(f"DRL: Cleaned up {len(expired)} expired blocks")
