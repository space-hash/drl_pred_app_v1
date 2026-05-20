# core/flow_tracker.py
"""
Real-Time Flow Tracker for DRL-based DDoS Mitigation.

Tracks active network flows and computes incremental CICFlowMeter-style features
in real-time. Provides 81-dimensional feature vectors that match the trained
DRL model's expected input format.

Architecture:
  Live Packets → FlowTracker.update() → FlowTracker.get_features() → DRL Model
"""
import threading
import logging
import time
import math
from collections import defaultdict, deque
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime

logger = logging.getLogger("FlowTracker")

# Flow timeout: expire flows after this many seconds of inactivity
FLOW_TIMEOUT_SECONDS = 120

# Maximum number of concurrent flows to track (memory limit)
MAX_FLOWS = 10000

# Minimum packets per flow before triggering DRL inference
MIN_PACKETS_FOR_INFERENCE = 3

# Trigger DRL inference every N packets per flow
INFERENCE_INTERVAL = 5


class FlowRecord:
    """Tracks a single bidirectional network flow."""

    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol

        # Flow timing
        self.start_time = time.time()
        self.last_seen = self.start_time
        self.duration = 0.0

        # Packet counts (forward = src→dst, backward = dst→src)
        self.fwd_packets = 0
        self.bwd_packets = 0

        # Byte counts
        self.fwd_bytes = 0
        self.bwd_bytes = 0

        # Packet lengths (all packets)
        self.packet_lengths: List[int] = []
        self.fwd_packet_lengths: List[int] = []
        self.bwd_packet_lengths: List[int] = []

        # Inter-arrival times (IAT) in seconds
        self.flow_iats: List[float] = []
        self.fwd_iats: List[float] = []
        self.bwd_iats: List[float] = []
        self._last_flow_time: Optional[float] = None
        self._last_fwd_time: Optional[float] = None
        self._last_bwd_time: Optional[float] = None

        # TCP flags
        self.fin_count = 0
        self.syn_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.urg_count = 0
        self.cwe_count = 0
        self.ece_count = 0

        # TCP header info
        self.fwd_header_length = 0
        self.bwd_header_length = 0
        self.fwd_init_win = 0
        self.bwd_init_win = 0
        self.fwd_min_seg_size = 0

        # Active/Idle tracking
        self.active_periods: List[float] = []
        self.idle_periods: List[float] = []
        self._active_start: Optional[float] = None
        self._idle_start: Optional[float] = None
        self._last_packet_time: Optional[float] = None

        # Subflow tracking (simplified: count packets in 5-second windows)
        self.subflow_fwd_packets = 0
        self.subflow_fwd_bytes = 0
        self.subflow_bwd_packets = 0
        self.subflow_bwd_bytes = 0
        self._subflow_window_start = self.start_time

        # Bulk transfer tracking (simplified)
        self.fwd_bulk_packets = 0
        self.fwd_bulk_bytes = 0
        self.bwd_bulk_packets = 0
        self.bwd_bulk_bytes = 0

        # PSH/URG flag counts per direction
        self.fwd_psh_flags = 0
        self.bwd_psh_flags = 0
        self.fwd_urg_flags = 0
        self.bwd_urg_flags = 0

        # Total inference count
        self.inference_count = 0

    @property
    def total_packets(self) -> int:
        return self.fwd_packets + self.bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.fwd_bytes + self.bwd_bytes

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.last_seen) > FLOW_TIMEOUT_SECONDS

    def update(self, packet_length: int, is_forward: bool, timestamp: float,
               tcp_flags: int = 0, tcp_header_len: int = 0, tcp_window: int = 0,
               tcp_seg_size: int = 0):
        """Update flow statistics with a new packet."""
        now = timestamp
        self.last_seen = now
        self.duration = now - self.start_time

        # Direction
        if is_forward:
            self.fwd_packets += 1
            self.fwd_bytes += packet_length
            self.fwd_packet_lengths.append(packet_length)
            self.fwd_header_length += tcp_header_len

            # TCP flags (forward direction)
            if tcp_flags & 0x01: self.fin_count += 1; self.fwd_psh_flags += 0
            if tcp_flags & 0x02: self.syn_count += 1
            if tcp_flags & 0x04: self.rst_count += 1
            if tcp_flags & 0x08: self.psh_count += 1; self.fwd_psh_flags += 1
            if tcp_flags & 0x10: self.ack_count += 1
            if tcp_flags & 0x20: self.urg_count += 1; self.fwd_urg_flags += 1
            if tcp_flags & 0x40: self.ece_count += 1
            if tcp_flags & 0x80: self.cwe_count += 1

            # TCP window and segment size (first packet only)
            if self.fwd_packets == 1:
                self.fwd_init_win = tcp_window
                self.fwd_min_seg_size = tcp_seg_size if tcp_seg_size > 0 else 0

            # Subflow tracking (5-second windows)
            if (now - self._subflow_window_start) > 5.0:
                self._subflow_window_start = now
                self.subflow_fwd_packets = 0
                self.subflow_fwd_bytes = 0
                self.subflow_bwd_packets = 0
                self.subflow_bwd_bytes = 0
            self.subflow_fwd_packets += 1
            self.subflow_fwd_bytes += packet_length

        else:
            self.bwd_packets += 1
            self.bwd_bytes += packet_length
            self.bwd_packet_lengths.append(packet_length)
            self.bwd_header_length += tcp_header_len

            # TCP flags (backward direction)
            if tcp_flags & 0x01: self.fin_count += 1
            if tcp_flags & 0x02: self.syn_count += 1
            if tcp_flags & 0x04: self.rst_count += 1
            if tcp_flags & 0x08: self.psh_count += 1; self.bwd_psh_flags += 1
            if tcp_flags & 0x10: self.ack_count += 1
            if tcp_flags & 0x20: self.urg_count += 1; self.bwd_urg_flags += 1
            if tcp_flags & 0x40: self.ece_count += 1
            if tcp_flags & 0x80: self.cwe_count += 1

            # TCP window (first backward packet)
            if self.bwd_packets == 1:
                self.bwd_init_win = tcp_window

            # Subflow tracking
            if (now - self._subflow_window_start) > 5.0:
                self._subflow_window_start = now
                self.subflow_fwd_packets = 0
                self.subflow_fwd_bytes = 0
                self.subflow_bwd_packets = 0
                self.subflow_bwd_bytes = 0
            self.subflow_bwd_packets += 1
            self.subflow_bwd_bytes += packet_length

        # All packet lengths
        self.packet_lengths.append(packet_length)

        # Inter-arrival times
        if self._last_flow_time is not None:
            iat = now - self._last_flow_time
            if iat > 0:
                self.flow_iats.append(iat)
        self._last_flow_time = now

        if is_forward:
            if self._last_fwd_time is not None:
                fwd_iat = now - self._last_fwd_time
                if fwd_iat > 0:
                    self.fwd_iats.append(fwd_iat)
            self._last_fwd_time = now
        else:
            if self._last_bwd_time is not None:
                bwd_iat = now - self._last_bwd_time
                if bwd_iat > 0:
                    self.bwd_iats.append(bwd_iat)
            self._last_bwd_time = now

        # Active/Idle tracking (idle threshold = 1 second)
        if self._last_packet_time is not None:
            gap = now - self._last_packet_time
            if gap > 1.0:
                # Idle period
                if self._active_start is not None:
                    self.active_periods.append(self._active_start - (now - gap))
                if self._idle_start is None:
                    self._idle_start = now - gap
                self.idle_periods.append(gap)
                self._active_start = now
            else:
                # Active period
                if self._idle_start is not None:
                    self._idle_start = None
                if self._active_start is None:
                    self._active_start = now
        else:
            self._active_start = now

        self._last_packet_time = now

    def should_trigger_inference(self) -> bool:
        """Check if this flow should trigger DRL inference."""
        if self.total_packets < MIN_PACKETS_FOR_INFERENCE:
            return False
        if self.total_packets % INFERENCE_INTERVAL == 0:
            return True
        return False

    def mark_inference(self):
        """Mark that inference was triggered for this flow."""
        self.inference_count += 1


class FlowTracker:
    """
    Manages all active flows and computes CICFlowMeter-style features.

    Usage:
        tracker = FlowTracker()
        tracker.update(src_ip, dst_ip, src_port, dst_port, protocol, ...)
        features = tracker.get_features(flow_key)  # Returns 81-dim vector
    """

    def __init__(self, max_flows: int = MAX_FLOWS, timeout: float = FLOW_TIMEOUT_SECONDS):
        self.max_flows = max_flows
        self.timeout = timeout
        self._lock = threading.RLock()
        self._flows: Dict[Tuple, FlowRecord] = {}
        self._stats = {
            "total_flows_seen": 0,
            "active_flows": 0,
            "expired_flows": 0,
            "evicted_flows": 0,
            "inferences_triggered": 0,
        }

    def update(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
               protocol: int, packet_length: int, timestamp: float,
               tcp_flags: int = 0, tcp_header_len: int = 20,
               tcp_window: int = 0, tcp_seg_size: int = 0,
               is_forward: Optional[bool] = None) -> Optional[Tuple]:
        """
        Update flow with a new packet.

        Returns flow_key if inference should be triggered, None otherwise.
        """
        with self._lock:
            # Determine direction
            if is_forward is None:
                is_forward = True  # Default: first packet is forward

            flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)

            # Create new flow if needed
            if flow_key not in self._flows:
                if len(self._flows) >= self.max_flows:
                    self._evict_expired()
                    if len(self._flows) >= self.max_flows:
                        # Evict oldest flow
                        oldest_key = min(self._flows.keys(),
                                        key=lambda k: self._flows[k].last_seen)
                        del self._flows[oldest_key]
                        self._stats["evicted_flows"] += 1

                self._flows[flow_key] = FlowRecord(src_ip, dst_ip, src_port, dst_port, protocol)
                self._stats["total_flows_seen"] += 1

            flow = self._flows[flow_key]
            flow.update(packet_length, is_forward, timestamp, tcp_flags,
                       tcp_header_len, tcp_window, tcp_seg_size)

            # Check if inference should be triggered
            if flow.should_trigger_inference():
                flow.mark_inference()
                self._stats["inferences_triggered"] += 1
                self._stats["active_flows"] = len(self._flows)
                return flow_key

            self._stats["active_flows"] = len(self._flows)
            return None

    def get_features(self, flow_key: Tuple) -> Optional[List[float]]:
        """
        Compute 81-dimensional CICFlowMeter feature vector for a flow.

        Returns list of 81 floats, or None if flow not found.
        """
        with self._lock:
            if flow_key not in self._flows:
                return None

            flow = self._flows[flow_key]
            return self._compute_features(flow)

    def _compute_features(self, flow: FlowRecord) -> List[float]:
        """Compute 81 CICFlowMeter-style features from a flow record."""
        f = []

        # 1-5: Flow identifiers
        f.append(self._ip_to_int(flow.src_ip))
        f.append(float(flow.src_port))
        f.append(self._ip_to_int(flow.dst_ip))
        f.append(float(flow.dst_port))
        f.append(float(flow.protocol))

        # 6: Flow Duration (microseconds)
        f.append(flow.duration * 1_000_000)

        # 7-8: Total packets
        f.append(float(flow.fwd_packets))
        f.append(float(flow.bwd_packets))

        # 9-10: Total bytes
        f.append(float(flow.fwd_bytes))
        f.append(float(flow.bwd_bytes))

        # 11-14: Fwd packet length stats
        f.append(float(max(flow.fwd_packet_lengths)) if flow.fwd_packet_lengths else 0)
        f.append(float(min(flow.fwd_packet_lengths)) if flow.fwd_packet_lengths else 0)
        f.append(self._mean(flow.fwd_packet_lengths))
        f.append(self._std(flow.fwd_packet_lengths))

        # 15-18: Bwd packet length stats
        f.append(float(max(flow.bwd_packet_lengths)) if flow.bwd_packet_lengths else 0)
        f.append(float(min(flow.bwd_packet_lengths)) if flow.bwd_packet_lengths else 0)
        f.append(self._mean(flow.bwd_packet_lengths))
        f.append(self._std(flow.bwd_packet_lengths))

        # 19-20: Flow rates
        duration_sec = max(flow.duration, 0.001)
        f.append(flow.total_bytes / duration_sec)
        f.append(flow.total_packets / duration_sec)

        # 21-24: Flow IAT stats
        f.append(self._mean(flow.flow_iats))
        f.append(self._std(flow.flow_iats))
        f.append(float(max(flow.flow_iats)) if flow.flow_iats else 0)
        f.append(float(min(flow.flow_iats)) if flow.flow_iats else 0)

        # 25-29: Fwd IAT stats
        f.append(sum(flow.fwd_iats))
        f.append(self._mean(flow.fwd_iats))
        f.append(self._std(flow.fwd_iats))
        f.append(float(max(flow.fwd_iats)) if flow.fwd_iats else 0)
        f.append(float(min(flow.fwd_iats)) if flow.fwd_iats else 0)

        # 30-34: Bwd IAT stats
        f.append(sum(flow.bwd_iats))
        f.append(self._mean(flow.bwd_iats))
        f.append(self._std(flow.bwd_iats))
        f.append(float(max(flow.bwd_iats)) if flow.bwd_iats else 0)
        f.append(float(min(flow.bwd_iats)) if flow.bwd_iats else 0)

        # 35-38: PSH/URG flags
        f.append(float(flow.fwd_psh_flags))
        f.append(float(flow.bwd_psh_flags))
        f.append(float(flow.fwd_urg_flags))
        f.append(float(flow.bwd_urg_flags))

        # 39-40: Header lengths
        f.append(float(flow.fwd_header_length))
        f.append(float(flow.bwd_header_length))

        # 41-42: Directional rates
        f.append(flow.fwd_packets / duration_sec)
        f.append(flow.bwd_packets / duration_sec)

        # 43-47: Overall packet length stats
        f.append(float(min(flow.packet_lengths)) if flow.packet_lengths else 0)
        f.append(float(max(flow.packet_lengths)) if flow.packet_lengths else 0)
        f.append(self._mean(flow.packet_lengths))
        f.append(self._std(flow.packet_lengths))
        f.append(self._variance(flow.packet_lengths))

        # 48-55: Flag counts
        f.append(float(flow.fin_count))
        f.append(float(flow.syn_count))
        f.append(float(flow.rst_count))
        f.append(float(flow.psh_count))
        f.append(float(flow.ack_count))
        f.append(float(flow.urg_count))
        f.append(float(flow.cwe_count))
        f.append(float(flow.ece_count))

        # 56: Down/Up ratio
        fwd_pkts = max(flow.fwd_packets, 1)
        f.append(flow.bwd_packets / fwd_pkts)

        # 57-59: Average sizes
        f.append(self._mean(flow.packet_lengths))
        f.append(self._mean(flow.fwd_packet_lengths))
        f.append(self._mean(flow.bwd_packet_lengths))

        # 60-65: Bulk transfer stats (simplified)
        f.append(float(flow.fwd_bulk_bytes) / max(flow.fwd_bulk_packets, 1))
        f.append(float(flow.fwd_bulk_packets) / max(flow.fwd_packets, 1))
        f.append(float(flow.fwd_bulk_bytes) / duration_sec)
        f.append(float(flow.bwd_bulk_bytes) / max(flow.bwd_bulk_packets, 1))
        f.append(float(flow.bwd_bulk_packets) / max(flow.bwd_packets, 1))
        f.append(float(flow.bwd_bulk_bytes) / duration_sec)

        # 66-69: Subflow stats
        f.append(float(flow.subflow_fwd_packets))
        f.append(float(flow.subflow_fwd_bytes))
        f.append(float(flow.subflow_bwd_packets))
        f.append(float(flow.subflow_bwd_bytes))

        # 70-73: TCP window/segment
        f.append(float(flow.fwd_init_win))
        f.append(float(flow.bwd_init_win))
        f.append(float(flow.fwd_packets - flow.syn_count))  # act_data_pkt_fwd
        f.append(float(flow.fwd_min_seg_size))

        # 74-81: Active/Idle stats
        f.append(self._mean(flow.active_periods))
        f.append(self._std(flow.active_periods))
        f.append(float(max(flow.active_periods)) if flow.active_periods else 0)
        f.append(float(min(flow.active_periods)) if flow.active_periods else 0)
        f.append(self._mean(flow.idle_periods))
        f.append(self._std(flow.idle_periods))
        f.append(float(max(flow.idle_periods)) if flow.idle_periods else 0)
        f.append(float(min(flow.idle_periods)) if flow.idle_periods else 0)

        # Ensure exactly 81 features
        if len(f) != 81:
            logger.warning(f"Expected 81 features, got {len(f)}. Padding/truncating.")
            if len(f) < 81:
                f.extend([0.0] * (81 - len(f)))
            else:
                f = f[:81]
        return f

    def cleanup_expired(self) -> int:
        """Remove expired flows. Returns count of removed flows."""
        with self._lock:
            expired = [k for k, v in self._flows.items() if v.is_expired]
            for k in expired:
                del self._flows[k]
            self._stats["expired_flows"] += len(expired)
            self._stats["active_flows"] = len(self._flows)
            return len(expired)

    def get_active_flows(self) -> int:
        """Get count of active flows."""
        with self._lock:
            return len(self._flows)

    def get_stats(self) -> Dict[str, Any]:
        """Get flow tracker statistics."""
        with self._lock:
            return {
                **self._stats,
                "active_flows": len(self._flows),
            }

    def _evict_expired(self):
        """Evict expired flows (must hold lock)."""
        expired = [k for k, v in self._flows.items() if v.is_expired]
        for k in expired:
            del self._flows[k]
        self._stats["expired_flows"] += len(expired)

    @staticmethod
    def _ip_to_int(ip: str) -> float:
        """Convert IP address to integer (handles IPv4 and IPv6)."""
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))
            else:
                # IPv6: use hash for simplicity
                return float(hash(ip) % (2**32))
        except Exception:
            return 0.0

    @staticmethod
    def _mean(values: List[float]) -> float:
        if not values:
            return 0.0
        return sum(values) / len(values)

    @staticmethod
    def _std(values: List[float]) -> float:
        if len(values) < 2:
            return 0.0
        m = sum(values) / len(values)
        variance = sum((x - m) ** 2 for x in values) / (len(values) - 1)
        return math.sqrt(variance)

    @staticmethod
    def _variance(values: List[float]) -> float:
        if len(values) < 2:
            return 0.0
        m = sum(values) / len(values)
        return sum((x - m) ** 2 for x in values) / (len(values) - 1)
