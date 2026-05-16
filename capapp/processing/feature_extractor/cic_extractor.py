# capapp/processing/feature_extractor/cic_extractor.py
"""
Extracts CICFlowMeter-compliant network flow features from .pcap files.
Uses a thread pool for parallel processing of multiple pcap files.
"""
import csv
import math
import time
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from datetime import datetime

from scapy.all import rdpcap, IP, TCP, UDP, Scapy_Exception

from capapp.config.settings import config
from capapp.utils.logger import logger


class _Flow:
    """Internal class representing a single network flow with directional separation."""

    def __init__(self, first_packet, packet_time_ns):
        self.src_ip = first_packet[IP].src
        self.dst_ip = first_packet[IP].dst
        self.proto = first_packet[IP].proto

        if first_packet.haslayer(TCP) or first_packet.haslayer(UDP):
            self.src_port = first_packet.sport
            self.dst_port = first_packet.dport
        else:
            self.src_port = 0
            self.dst_port = 0

        self.start_time_ns = packet_time_ns
        self.last_seen_ns = packet_time_ns

        self.fwd_packets = []
        self.bwd_packets = []

        self.fwd_flags = defaultdict(int)
        self.bwd_flags = defaultdict(int)

        self.fwd_bulk_size = 0
        self.fwd_bulk_packets = 0
        self.bwd_bulk_size = 0
        self.bwd_bulk_packets = 0

        self.fwd_init_win = 0
        self.bwd_init_win = 0
        self.min_fwd_seg_size = float("inf")

        self.add_packet(first_packet, packet_time_ns)

    def add_packet(self, packet, packet_time_ns):
        """Add a packet to the flow with proper directional handling."""
        current_sport = packet.sport if packet.haslayer(TCP) or packet.haslayer(UDP) else 0
        is_forward = packet[IP].src == self.src_ip and current_sport == self.src_port

        if is_forward:
            self.fwd_packets.append(packet)
            self._update_fwd_flags(packet)
            self._update_fwd_bulk(packet)
        else:
            self.bwd_packets.append(packet)
            self._update_bwd_flags(packet)
            self._update_bwd_bulk(packet)

        self.last_seen_ns = packet_time_ns

        if is_forward and packet.haslayer(TCP):
            seg_size = packet[IP].len - (packet[IP].ihl * 4)
            if seg_size < self.min_fwd_seg_size:
                self.min_fwd_seg_size = seg_size

        if packet.haslayer(TCP) and packet[TCP].flags.S:
            if is_forward:
                self.fwd_init_win = packet[TCP].window
            else:
                self.bwd_init_win = packet[TCP].window

    def _update_fwd_flags(self, packet):
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            self.fwd_flags["FIN"] += int(tcp.flags.F)
            self.fwd_flags["SYN"] += int(tcp.flags.S)
            self.fwd_flags["RST"] += int(tcp.flags.R)
            self.fwd_flags["PSH"] += int(tcp.flags.P)
            self.fwd_flags["ACK"] += int(tcp.flags.A)
            self.fwd_flags["URG"] += int(tcp.flags.U)
            self.fwd_flags["ECE"] += int(tcp.flags.E)
            self.fwd_flags["CWR"] += int(tcp.flags.C)

    def _update_bwd_flags(self, packet):
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            self.bwd_flags["FIN"] += int(tcp.flags.F)
            self.bwd_flags["SYN"] += int(tcp.flags.S)
            self.bwd_flags["RST"] += int(tcp.flags.R)
            self.bwd_flags["PSH"] += int(tcp.flags.P)
            self.bwd_flags["ACK"] += int(tcp.flags.A)
            self.bwd_flags["URG"] += int(tcp.flags.U)
            self.bwd_flags["ECE"] += int(tcp.flags.E)
            self.bwd_flags["CWR"] += int(tcp.flags.C)

    def _update_fwd_bulk(self, packet):
        if packet.haslayer(TCP) and packet[TCP].flags.P:
            self.fwd_bulk_size += len(packet)
            self.fwd_bulk_packets += 1

    def _update_bwd_bulk(self, packet):
        if packet.haslayer(TCP) and packet[TCP].flags.P:
            self.bwd_bulk_size += len(packet)
            self.bwd_bulk_packets += 1

    @staticmethod
    def _calculate_stats(values):
        """Calculate min, max, mean, std for a list of values."""
        if not values:
            return {"min": 0, "max": 0, "mean": 0, "std": 0}

        n = len(values)
        mean = sum(values) / n
        std = math.sqrt(sum((x - mean) ** 2 for x in values) / (n - 1)) if n > 1 else 0
        return {"min": min(values), "max": max(values), "mean": mean, "std": std}

    def _calculate_active_idle_stats(self):
        """Calculate active and idle times for the flow."""
        all_packets = sorted(self.fwd_packets + self.bwd_packets, key=lambda p: p.time)

        active_times = []
        idle_times = []
        active_threshold = 1.0

        for i in range(1, len(all_packets)):
            iat = (all_packets[i].time - all_packets[i - 1].time) * 1e6
            if iat < active_threshold * 1e6:
                active_times.append(iat)
            else:
                idle_times.append(iat)

        active_stats = self._calculate_stats(active_times) if active_times else {"min": 0, "max": 0, "mean": 0, "std": 0}
        idle_stats = self._calculate_stats(idle_times) if idle_times else {"min": 0, "max": 0, "mean": 0, "std": 0}

        return active_stats, idle_stats

    def get_features(self, feature_names):
        """Extract all CICFlowMeter features from the flow."""
        flow_duration_us = (self.last_seen_ns - self.start_time_ns) // 1000
        if flow_duration_us == 0:
            flow_duration_us = 1

        fwd_pkt_lengths = [len(p) for p in self.fwd_packets]
        bwd_pkt_lengths = [len(p) for p in self.bwd_packets]
        all_pkt_lengths = fwd_pkt_lengths + bwd_pkt_lengths

        fwd_len_stats = self._calculate_stats(fwd_pkt_lengths)
        bwd_len_stats = self._calculate_stats(bwd_pkt_lengths)
        all_len_stats = self._calculate_stats(all_pkt_lengths)

        fwd_iat = [
            (self.fwd_packets[i].time - self.fwd_packets[i - 1].time) * 1e6
            for i in range(1, len(self.fwd_packets))
        ] if len(self.fwd_packets) > 1 else []

        bwd_iat = [
            (self.bwd_packets[i].time - self.bwd_packets[i - 1].time) * 1e6
            for i in range(1, len(self.bwd_packets))
        ] if len(self.bwd_packets) > 1 else []

        all_packets = sorted(self.fwd_packets + self.bwd_packets, key=lambda p: p.time)
        flow_iat = [
            (all_packets[i].time - all_packets[i - 1].time) * 1e6
            for i in range(1, len(all_packets))
        ] if len(all_packets) > 1 else []

        fwd_iat_stats = self._calculate_stats(fwd_iat)
        bwd_iat_stats = self._calculate_stats(bwd_iat)
        flow_iat_stats = self._calculate_stats(flow_iat)

        fwd_header_bytes = sum(p[IP].ihl * 4 for p in self.fwd_packets)
        bwd_header_bytes = sum(p[IP].ihl * 4 for p in self.bwd_packets)

        fwd_avg_bytes_bulk = self.fwd_bulk_size / self.fwd_bulk_packets if self.fwd_bulk_packets > 0 else 0
        bwd_avg_bytes_bulk = self.bwd_bulk_size / self.bwd_bulk_packets if self.bwd_bulk_packets > 0 else 0

        active_stats, idle_stats = self._calculate_active_idle_stats()

        features = {
            "Flow ID": f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}",
            "Src IP": self.src_ip,
            "Src Port": self.src_port,
            "Dst IP": self.dst_ip,
            "Dst Port": self.dst_port,
            "Protocol": self.proto,
            "Timestamp": datetime.fromtimestamp(self.start_time_ns / 1e9).isoformat(),
            "Flow Duration": flow_duration_us,
            "Total Fwd Packets": len(self.fwd_packets),
            "Total Bwd Packets": len(self.bwd_packets),
            "Total Length of Fwd Packets": sum(fwd_pkt_lengths),
            "Total Length of Bwd Packets": sum(bwd_pkt_lengths),
            "Fwd Packet Length Max": fwd_len_stats["max"],
            "Fwd Packet Length Min": fwd_len_stats["min"],
            "Fwd Packet Length Mean": fwd_len_stats["mean"],
            "Fwd Packet Length Std": fwd_len_stats["std"],
            "Bwd Packet Length Max": bwd_len_stats["max"],
            "Bwd Packet Length Min": bwd_len_stats["min"],
            "Bwd Packet Length Mean": bwd_len_stats["mean"],
            "Bwd Packet Length Std": bwd_len_stats["std"],
            "Flow Bytes/s": (sum(fwd_pkt_lengths) + sum(bwd_pkt_lengths)) / (flow_duration_us / 1e6),
            "Flow Packets/s": (len(self.fwd_packets) + len(self.bwd_packets)) / (flow_duration_us / 1e6),
            "Flow IAT Mean": flow_iat_stats["mean"],
            "Flow IAT Std": flow_iat_stats["std"],
            "Flow IAT Max": flow_iat_stats["max"],
            "Flow IAT Min": flow_iat_stats["min"],
            "Fwd IAT Total": sum(fwd_iat),
            "Fwd IAT Mean": fwd_iat_stats["mean"],
            "Fwd IAT Std": fwd_iat_stats["std"],
            "Fwd IAT Max": fwd_iat_stats["max"],
            "Fwd IAT Min": fwd_iat_stats["min"],
            "Bwd IAT Total": sum(bwd_iat),
            "Bwd IAT Mean": bwd_iat_stats["mean"],
            "Bwd IAT Std": bwd_iat_stats["std"],
            "Bwd IAT Max": bwd_iat_stats["max"],
            "Bwd IAT Min": bwd_iat_stats["min"],
            "Fwd PSH Flags": self.fwd_flags["PSH"],
            "Bwd PSH Flags": self.bwd_flags["PSH"],
            "Fwd URG Flags": self.fwd_flags["URG"],
            "Bwd URG Flags": self.bwd_flags["URG"],
            "Fwd Header Length": fwd_header_bytes,
            "Bwd Header Length": bwd_header_bytes,
            "Fwd Packets/s": len(self.fwd_packets) / (flow_duration_us / 1e6),
            "Bwd Packets/s": len(self.bwd_packets) / (flow_duration_us / 1e6),
            "Min Packet Length": all_len_stats["min"],
            "Max Packet Length": all_len_stats["max"],
            "Packet Length Mean": all_len_stats["mean"],
            "Packet Length Std": all_len_stats["std"],
            "Packet Length Variance": all_len_stats["std"] ** 2,
            "FIN Flag Count": self.fwd_flags["FIN"] + self.bwd_flags["FIN"],
            "SYN Flag Count": self.fwd_flags["SYN"] + self.bwd_flags["SYN"],
            "RST Flag Count": self.fwd_flags["RST"] + self.bwd_flags["RST"],
            "PSH Flag Count": self.fwd_flags["PSH"] + self.bwd_flags["PSH"],
            "ACK Flag Count": self.fwd_flags["ACK"] + self.bwd_flags["ACK"],
            "URG Flag Count": self.fwd_flags["URG"] + self.bwd_flags["URG"],
            "CWE Flag Count": self.fwd_flags["CWR"] + self.bwd_flags["CWR"],
            "ECE Flag Count": self.fwd_flags["ECE"] + self.bwd_flags["ECE"],
            "Down/Up Ratio": len(self.bwd_packets) / len(self.fwd_packets) if self.fwd_packets else 0,
            "Average Packet Size": all_len_stats["mean"],
            "Avg Fwd Segment Size": fwd_len_stats["mean"],
            "Avg Bwd Segment Size": bwd_len_stats["mean"],
            "Fwd Header Length.1": fwd_header_bytes,
            "Fwd Avg Bytes/Bulk": fwd_avg_bytes_bulk,
            "Fwd Avg Packets/Bulk": self.fwd_bulk_packets / len(self.fwd_packets) if self.fwd_packets else 0,
            "Fwd Avg Bulk Rate": self.fwd_bulk_size / (flow_duration_us / 1e6) if flow_duration_us > 0 else 0,
            "Bwd Avg Bytes/Bulk": bwd_avg_bytes_bulk,
            "Bwd Avg Packets/Bulk": self.bwd_bulk_packets / len(self.bwd_packets) if self.bwd_packets else 0,
            "Bwd Avg Bulk Rate": self.bwd_bulk_size / (flow_duration_us / 1e6) if flow_duration_us > 0 else 0,
            "Subflow Fwd Packets": len(self.fwd_packets),
            "Subflow Fwd Bytes": sum(fwd_pkt_lengths),
            "Subflow Bwd Packets": len(self.bwd_packets),
            "Subflow Bwd Bytes": sum(bwd_pkt_lengths),
            "Init_Win_bytes_forward": self.fwd_init_win,
            "Init_Win_bytes_backward": self.bwd_init_win,
            "act_data_pkt_fwd": sum(1 for p in self.fwd_packets if p.haslayer(TCP) and p[TCP].payload),
            "min_seg_size_forward": self.min_fwd_seg_size if self.min_fwd_seg_size != float("inf") else 0,
            "Active Mean": active_stats["mean"],
            "Active Std": active_stats["std"],
            "Active Max": active_stats["max"],
            "Active Min": active_stats["min"],
            "Idle Mean": idle_stats["mean"],
            "Idle Std": idle_stats["std"],
            "Idle Max": idle_stats["max"],
            "Idle Min": idle_stats["min"],
        }

        return {key: features.get(key, 0) for key in feature_names}


class CICFeatureExtractor:
    """Extracts CICFlowMeter-compliant network flow features from .pcap files."""

    FEATURE_NAMES = [
        "Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Timestamp", "Flow Duration",
        "Total Fwd Packets", "Total Bwd Packets", "Total Length of Fwd Packets", "Total Length of Bwd Packets",
        "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
        "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
        "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
        "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
        "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
        "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
        "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length", "Packet Length Mean",
        "Packet Length Std", "Packet Length Variance", "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
        "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio",
        "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Header Length.1",
        "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk",
        "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
        "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
        "act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min",
        "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
    ]

    ACTIVE_TIMEOUT = 120 * 1_000_000_000
    INACTIVE_TIMEOUT = 5 * 1_000_000_000

    def __init__(self):
        self.executor = ThreadPoolExecutor(
            max_workers=config.MAX_PROCESSING_WORKERS,
            thread_name_prefix="CICExtractorWorker",
        )

    def _get_flow_key(self, packet):
        if not packet.haslayer(IP):
            return None
        src_ip, dst_ip, proto = packet[IP].src, packet[IP].dst, packet[IP].proto
        sport, dport = (packet.sport, packet.dport) if packet.haslayer(TCP) or packet.haslayer(UDP) else (0, 0)
        if (src_ip, sport) > (dst_ip, dport):
            return (dst_ip, dport, src_ip, sport, proto)
        return (src_ip, sport, dst_ip, dport, proto)

    def _process_pcap_task(self, pcap_path):
        active_flows = {}
        completed_flows = []
        try:
            packets = rdpcap(str(pcap_path))
        except Scapy_Exception as e:
            logger.error("Scapy failed to read %s: %s", pcap_path.name, e)
            return []

        for packet in packets:
            packet_time_ns = int(packet.time * 1_000_000_000)
            flow_key = self._get_flow_key(packet)
            if not flow_key:
                continue

            expired_keys = [
                key for key, flow in active_flows.items()
                if (packet_time_ns - flow.last_seen_ns > self.INACTIVE_TIMEOUT or
                    packet_time_ns - flow.start_time_ns > self.ACTIVE_TIMEOUT)
            ]
            for key in expired_keys:
                completed_flows.append(active_flows.pop(key))

            if flow_key in active_flows:
                active_flows[flow_key].add_packet(packet, packet_time_ns)
            else:
                active_flows[flow_key] = _Flow(packet, packet_time_ns)

        completed_flows.extend(active_flows.values())
        return [flow.get_features(self.FEATURE_NAMES) for flow in completed_flows]

    def process_pcap(self, pcap_path):
        """Public interface to process a single .pcap file."""
        output_filename = f"{pcap_path.stem}_features.csv"
        output_path = config.PROCESSED_FEATURES_DIR / output_filename

        try:
            future = self.executor.submit(self._process_pcap_task, pcap_path)
            flow_features = future.result(timeout=config.PROCESSING_TIMEOUT_SECONDS)

            if not flow_features:
                logger.warning("No processable flows found in %s.", pcap_path.name)
                return True, None

            with open(output_path, "w", newline="") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self.FEATURE_NAMES)
                writer.writeheader()
                writer.writerows(flow_features)

            logger.info("Extracted %d flows to %s", len(flow_features), output_path.name)
            return True, output_path

        except TimeoutError:
            logger.error("Processing timed out for %s after %ds.", pcap_path.name, config.PROCESSING_TIMEOUT_SECONDS)
            return False, None
        except Exception as e:
            logger.critical("Unexpected error processing %s: %s", pcap_path.name, e, exc_info=True)
            return False, None

    def shutdown(self):
        """Gracefully shuts down the thread pool."""
        logger.info("Shutting down feature extractor thread pool...")
        self.executor.shutdown(wait=True, cancel_futures=False)
