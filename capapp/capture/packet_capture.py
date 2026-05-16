# capapp/capture/packet_capture.py
"""
Packet capture module that sniffs network traffic, buffers packets in memory,
and rotates .pcap files to disk based on time or size thresholds.
Supports real-time packet callback for rate-based mitigation.
"""
import time
import threading
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from scapy.all import sniff, wrpcap, get_if_list

from capapp.config.settings import config
from capapp.utils.logger import logger

MAX_PACKETS_IN_MEMORY = 100000


class PacketCapturer:
    """Captures network traffic and rotates .pcap files to disk."""

    def __init__(self, packet_callback=None):
        self.shutdown_event = threading.Event()
        self.capture_thread = None
        self.packets = []
        self.current_file_path = None
        self.last_rotation_time = 0
        self.lock = threading.Lock()
        self.interface = self._validate_interface()
        self._write_executor = None
        self.packet_callback = packet_callback
        self._blocked_ips = set()

    def _validate_interface(self) -> str:
        """Validates the configured interface or auto-detects a suitable one."""
        available_interfaces = get_if_list()
        configured_iface = config.CAPTURE_INTERFACE

        if configured_iface in available_interfaces:
            logger.info("Using configured interface: %s", configured_iface)
            return configured_iface

        logger.warning("Configured interface '%s' not found.", configured_iface)

        non_loopback = [iface for iface in available_interfaces if "lo" not in iface]
        if non_loopback:
            selected = non_loopback[0]
            logger.warning("Auto-selected interface: %s", selected)
            return selected

        logger.error("No suitable network interfaces found. Available: %s", available_interfaces)
        raise SystemExit("Fatal: No network interface available for capture.")

    def _get_new_filepath(self) -> Path:
        """Generates a unique, timestamped filename."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        return config.CAPTURE_DIR / f"B_{timestamp}.pcap"

    def _packet_handler(self, packet):
        """Callback for Scapy's sniff. Buffers packet and triggers mitigation callback."""
        with self.lock:
            if len(self.packets) < MAX_PACKETS_IN_MEMORY:
                self.packets.append(packet)
            else:
                self.packets.pop(0)
                self.packets.append(packet)

        if self.packet_callback:
            try:
                src_ip = None
                if packet.haslayer("IP"):
                    src_ip = packet["IP"].src
                elif packet.haslayer("IPv6"):
                    src_ip = packet["IPv6"].src

                if src_ip and src_ip not in self._blocked_ips:
                    blocked = self.packet_callback(src_ip)
                    if blocked:
                        self._blocked_ips.add(blocked)
                        logger.warning("Rate-blocked %s", blocked)
            except Exception as e:
                logger.debug("Packet callback error: %s", e)

    def _rotation_manager(self):
        """Periodically rotates capture files based on time or size."""
        self.current_file_path = self._get_new_filepath()
        self.last_rotation_time = time.time()
        logger.info("Starting new capture file: %s", self.current_file_path.name)

        while not self.shutdown_event.is_set():
            time.sleep(1)

            with self.lock:
                current_size_bytes = sum(len(p) for p in self.packets)
                time_elapsed = time.time() - self.last_rotation_time

                size_exceeded = current_size_bytes >= (config.ROTATE_MAX_SIZE_MB * 1024 * 1024)
                time_exceeded = time_elapsed >= config.ROTATE_INTERVAL_SECONDS

                if (size_exceeded or time_exceeded) and self.packets:
                    packets_to_write = self.packets[:]
                    self.packets = []

                    old_file_path = self.current_file_path
                    self.current_file_path = self._get_new_filepath()
                    self.last_rotation_time = time.time()

                    if self._write_executor and not self._write_executor._shutdown:
                        self._write_executor.submit(self._write_file, packets_to_write, old_file_path)

                    logger.info("Rotated capture file: %s (%d packets)", old_file_path.name, len(packets_to_write))

    def _write_file(self, packets, filepath):
        """Writes packets to a .pcap file atomically."""
        try:
            tmp_path = filepath.with_suffix(".pcap.tmp")
            wrpcap(str(tmp_path), packets)
            tmp_path.rename(filepath)
            logger.info("Saved %s (%d packets)", filepath.name, len(packets))
        except Exception as e:
            logger.error("Failed to write .pcap file %s: %s", filepath.name, e)

    def start(self):
        """Starts the packet capture and rotation manager threads."""
        if not self.interface:
            logger.critical("Cannot start capture: No valid network interface.")
            return

        if self.capture_thread and self.capture_thread.is_alive():
            logger.warning("Capture is already running.")
            return

        logger.info("Starting packet capture on interface '%s'...", self.interface)
        self.shutdown_event.clear()
        self._write_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="PCAPWriter")
        self.packets = []
        self._blocked_ips = set()

        manager_thread = threading.Thread(target=self._rotation_manager, name="RotationManager", daemon=True)
        manager_thread.start()

        self.capture_thread = threading.Thread(target=self._run_sniffer, name="PacketSniffer", daemon=True)
        self.capture_thread.start()

    def _run_sniffer(self):
        """Run sniffer in a loop to handle timeout gracefully."""
        logger.info("PacketSniffer thread started on %s", self.interface)
        while not self.shutdown_event.is_set():
            try:
                sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    filter=config.CAPTURE_FILTER,
                    stop_filter=lambda p: self.shutdown_event.is_set(),
                    timeout=5,
                )
                if not self.shutdown_event.is_set():
                    logger.debug("Sniffer timeout, restarting...")
            except Exception as e:
                if self.shutdown_event.is_set():
                    break
                logger.error("Sniffer error: %s", e)
                time.sleep(1)

    def stop(self):
        """Stops the capture process gracefully."""
        logger.info("Stopping packet capture...")
        self.shutdown_event.set()

        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
            if self.capture_thread.is_alive():
                logger.warning("Packet sniffer thread did not stop in time")

        with self.lock:
            if self.packets and self.current_file_path:
                logger.info("Final write of %d packets", len(self.packets))
                self._write_file(self.packets, self.current_file_path)

        if self._write_executor:
            self._write_executor.shutdown(wait=True, cancel_futures=False)

        logger.info("Packet capture stopped.")
