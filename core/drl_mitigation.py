# core/drl_mitigation.py
"""
DRL-based Mitigation Agent with Flow-Based Feature Extraction.

Uses the trained DRL model to make intelligent blocking decisions based on
real-time CICFlowMeter-style flow features extracted from live traffic.

Features:
- Flow-based feature extraction via FlowTracker
- DRL model inference for blocking decisions
- Confidence-based blocking with adjustable thresholds
- Integration with existing mitigation pipeline
"""
import threading
import logging
import numpy as np
import socket
from pathlib import Path
from typing import Dict, Any, Optional, List, Set
from datetime import datetime, timedelta

logger = logging.getLogger("DRLMitigation")

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch not available, DRL mitigation disabled")


class DRLMitigationAgent:
    """
    DRL-based mitigation agent using flow-based CICFlowMeter features.

    Usage:
        agent = DRLMitigationAgent(model_path="...", flow_tracker=tracker)
        flow_key = flow_tracker.update(src_ip, dst_ip, ...)
        if flow_key:
            agent.on_flow(flow_key)
    """

    def __init__(
        self,
        model_path: str = "",
        confidence_threshold: float = 0.7,
        block_duration_minutes: int = 30,
        enabled: bool = True,
        flow_tracker=None,
    ):
        self.confidence_threshold = confidence_threshold
        self.block_duration = timedelta(minutes=block_duration_minutes)
        self.enabled = enabled
        self.model_path = model_path
        self.flow_tracker = flow_tracker

        self._lock = threading.RLock()
        self._blocked_ips: Dict[str, Dict[str, Any]] = {}
        self._decision_log: List[Dict[str, Any]] = []
        self._stats = {
            "decisions_made": 0,
            "blocks_applied": 0,
            "false_positives": 0,
            "true_positives": 0,
            "features_extracted": 0,
        }

        # Auto-whitelist localhost and local IPs to prevent self-blocking
        self._whitelist: Set[str] = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}
        try:
            hostname = socket.gethostname()
            local_ips = socket.getaddrinfo(hostname, None)
            for ip_info in local_ips:
                self._whitelist.add(ip_info[4][0])
        except Exception:
            pass

        # Load DRL model
        self.model = None
        self.device = None
        self.scaler = None
        if TORCH_AVAILABLE and model_path and Path(model_path).exists():
            self._load_model()

    def _load_model(self):
        """Load the trained DRL model and scaler."""
        try:
            from detection_module.detection import EnhancedPPOAgent
            import joblib

            self.model = EnhancedPPOAgent.load_model(self.model_path, map_location="cpu")
            self.device = torch.device("cpu")

            # Load scaler if available
            scaler_path = Path(self.model_path).with_suffix('.scaler.pkl')
            if scaler_path.exists():
                self.scaler = joblib.load(str(scaler_path))
                logger.info(f"DRL model + scaler loaded from {self.model_path}")
            else:
                logger.info(f"DRL model loaded from {self.model_path} (no scaler found)")
        except Exception as e:
            logger.error(f"Failed to load DRL model: {e}")
            self.model = None

    def on_flow(self, flow_key) -> Optional[str]:
        """
        Process a flow and decide whether to block using DRL model.

        Args:
            flow_key: Flow tuple from FlowTracker

        Returns:
            Source IP if blocked, None otherwise
        """
        if not self.enabled or not self.model or not self.flow_tracker:
            return None

        # Get features from flow tracker
        features = self.flow_tracker.get_features(flow_key)
        if features is None:
            return None

        self._stats["features_extracted"] += 1

        # Get source IP from flow key
        src_ip = flow_key[0]

        # Never block localhost or local IPs
        if src_ip in self._whitelist:
            return None

        with self._lock:
            if src_ip in self._blocked_ips:
                return None

        try:
            # Convert to numpy array
            feature_array = np.array(features, dtype=np.float32)

            # Scale features if scaler is available
            if self.scaler is not None:
                feature_array = self.scaler.transform(feature_array.reshape(1, -1)).flatten()

            # Run DRL inference
            result = self.model.predict(feature_array, return_probs=True)
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
            logger.error(f"DRL prediction failed for flow {flow_key}: {e}")
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
                "has_flow_tracker": self.flow_tracker is not None,
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
