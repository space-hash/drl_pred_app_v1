# capapp/capture/packet_capture.py
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
    """
    Captures network traffic directly to disk and rotates .pcap files.
    This component is fully independent and does not use in-memory queues.
    """
    def __init__(self, packet_callback=None, flow_tracker=None):
        self.shutdown_event = threading.Event()
        self.capture_thread = None
        self.packets = []
        self.current_file_path: Path = None
        self.last_rotation_time = 0
        self.lock = threading.Lock()
        self.interface = self._validate_interface()
        self._write_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="PCAPWriter")
        self.packet_callback = packet_callback
        self.flow_tracker = flow_tracker
        self._packet_count = 0
        self._blocked_ips = set()
        self._seen_flows = set()  # Track direction of first packet per flow
        self._max_seen_flows = 50000  # Memory limit for flow tracking

    def _validate_interface(self) -> str:
        """
        Validates the configured interface or auto-detects a suitable one.
        """
        available_interfaces = get_if_list()
        configured_iface = config.CAPTURE_INTERFACE

        if configured_iface in available_interfaces:
            logger.info(f"Successfully validated configured interface: {configured_iface}")
            return configured_iface

        logger.warning(f"Configured interface '{configured_iface}' not found.")
        
        non_loopback = [iface for iface in available_interfaces if "lo" not in iface]
        if non_loopback:
            auto_selected_iface = non_loopback[0]
            logger.warning(f"Automatically selected the first available non-loopback interface: {auto_selected_iface}")
            return auto_selected_iface

        logger.error(f"No suitable non-loopback network interfaces found. Available: {available_interfaces}")
        raise SystemExit("Fatal: Could not find a network interface to capture on.")


    def _get_new_filepath(self) -> Path:
        """Generates a unique, timestamped filename."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        return config.CAPTURE_DIR / f"B_{timestamp}.pcap"

    def _packet_handler(self, packet):
        """Callback for Scapy's sniff. Appends packet to the in-memory list."""
        with self.lock:
            if len(self.packets) < MAX_PACKETS_IN_MEMORY:
                self.packets.append(packet)
            else:
                self.packets.pop(0)
                self.packets.append(packet)

        if self.packet_callback or self.flow_tracker:
            try:
                src_ip = dst_ip = None
                src_port = dst_port = 0
                protocol = 0
                flags = 0
                pkt_len = len(packet)
                timestamp = float(packet.time)
                tcp_header_len = 0
                tcp_window = 0

                if packet.haslayer("IP"):
                    src_ip = packet["IP"].src
                    dst_ip = packet["IP"].dst
                    protocol = packet["IP"].proto
                elif packet.haslayer("IPv6"):
                    src_ip = packet["IPv6"].src
                    dst_ip = packet["IPv6"].dst
                    protocol = packet["IPv6"].nh

                if packet.haslayer("TCP"):
                    src_port = packet["TCP"].sport
                    dst_port = packet["TCP"].dport
                    flags = int(packet["TCP"].flags)
                    tcp_header_len = len(packet["TCP"])
                    tcp_window = packet["TCP"].window
                elif packet.haslayer("UDP"):
                    src_port = packet["UDP"].sport
                    dst_port = packet["UDP"].dport

                # Feed to flow tracker
                if self.flow_tracker and src_ip and dst_ip:
                    flow_key = (src_ip, dst_ip, src_port, dst_port, protocol)
                    is_forward = flow_key not in self._seen_flows
                    if is_forward:
                        self._seen_flows.add(flow_key)
                        # Also add reverse key to avoid duplicate tracking
                        self._seen_flows.add((dst_ip, src_ip, dst_port, src_port, protocol))
                        
                        # Prevent memory leak: evict old entries if limit exceeded
                        if len(self._seen_flows) > self._max_seen_flows:
                            # Clear oldest 50% of entries
                            to_remove = list(self._seen_flows)[:len(self._seen_flows)//2]
                            for key in to_remove:
                                self._seen_flows.discard(key)

                    triggered_key = self.flow_tracker.update(
                        src_ip=src_ip, dst_ip=dst_ip,
                        src_port=src_port, dst_port=dst_port,
                        protocol=protocol, packet_length=pkt_len,
                        timestamp=timestamp, tcp_flags=flags,
                        tcp_header_len=tcp_header_len, tcp_window=tcp_window,
                        is_forward=is_forward,
                    )

                    # If flow tracker triggered inference, notify callback
                    if triggered_key and hasattr(self.packet_callback, '__self__'):
                        agent = self.packet_callback.__self__
                        if hasattr(agent, 'on_flow'):
                            blocked_ip = agent.on_flow(triggered_key)
                            if blocked_ip:
                                self._blocked_ips.add(blocked_ip)
                                logger.warning(f"DRL-blocked {blocked_ip}")

                if src_ip and src_ip not in self._blocked_ips:
                    # Rate-based blocking
                    if self.packet_callback:
                        blocked = self.packet_callback(src_ip)
                        if blocked:
                            self._blocked_ips.add(blocked)
                            logger.warning(f"Rate-blocked {blocked}")

                        # Multi-vector analysis
                        if hasattr(self.packet_callback, '__self__'):
                            agent = self.packet_callback.__self__
                            if hasattr(agent, 'on_packet_vector'):
                                attack = agent.on_packet_vector(src_ip, protocol, dst_port, flags)
                                if attack:
                                    self._blocked_ips.add(src_ip)
                                    logger.warning(f"Vector-blocked {src_ip}: {attack}")
            except Exception as e:
                logger.error(f"Packet handler error: {e}")

    def _rotation_manager(self):
        """
        Periodically checks if the current capture file needs to be rotated
        based on time or size, and writes the batch to disk.
        """
        self.current_file_path = self._get_new_filepath()
        self.last_rotation_time = time.time()
        logger.info(f"Starting new capture file: {self.current_file_path.name}")

        while not self.shutdown_event.is_set():
            time.sleep(1)

            with self.lock:
                current_size_bytes = sum(len(p) for p in self.packets)
                time_elapsed = time.time() - self.last_rotation_time

                size_exceeded = current_size_bytes >= (config.ROTATE_MAX_SIZE_MB * 1024 * 1024)
                time_exceeded = time_elapsed >= config.ROTATE_INTERVAL_SECONDS

                if int(time_elapsed) % 10 == 0 and time_elapsed > 0:
                    logger.info(f"Rotation check: elapsed={int(time_elapsed)}s, packets={len(self.packets)}, size={current_size_bytes}B")

                if (size_exceeded or time_exceeded) and self.packets:
                    packets_to_write = self.packets[:]
                    self.packets = []
                    
                    old_file_path = self.current_file_path
                    self.current_file_path = self._get_new_filepath()
                    self.last_rotation_time = time.time()

                    self._write_executor.submit(self._write_file, packets_to_write, old_file_path)
                    
                    logger.info(f"Starting new capture file: {self.current_file_path.name}")

    def _write_file(self, packets: list, filepath: Path):
        """Writes a list of packets to a .pcap file atomically to prevent race conditions."""
        try:
            tmp_path = filepath.with_suffix(".pcap.tmp")
            wrpcap(str(tmp_path), packets)
            tmp_path.rename(filepath)
            logger.info(f"Rotated and saved: {filepath.name} ({len(packets)} packets)")
        except Exception as e:
            logger.error(f"Failed to write .pcap file {filepath.name}: {e}")

    def start(self):
        """Starts the packet capture and rotation manager threads."""
        if not self.interface:
            logger.critical("Cannot start capture: No valid network interface was found.")
            return

        if self.capture_thread and self.capture_thread.is_alive():
            logger.warning("Capture is already running.")
            return

        logger.info(f"Starting packet capture on interface '{self.interface}'...")
        self.shutdown_event.clear()
        self._write_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="PCAPWriter")
        self.packets = []
        self._blocked_ips = set()
        self._packet_count = 0
        self._seen_flows = set()

        manager_thread = threading.Thread(target=self._rotation_manager, name="RotationManager")
        manager_thread.daemon = True
        manager_thread.start()

        self.capture_thread = threading.Thread(
            target=self._run_sniffer,
            name="PacketSniffer"
        )
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def _run_sniffer(self):
        """Run sniffer in a loop to handle timeout gracefully."""
        logger.info(f"PacketSniffer thread started on {self.interface}")
        while not self.shutdown_event.is_set():
            try:
                sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    filter=config.CAPTURE_FILTER,
                    stop_filter=lambda p: self.shutdown_event.is_set(),
                    timeout=5
                )
                if not self.shutdown_event.is_set():
                    logger.debug("Sniffer timeout reached, restarting...")
            except Exception as e:
                if self.shutdown_event.is_set():
                    break
                logger.error(f"Sniffer error: {e}")
                time.sleep(1)

    def stop(self):
        """Stops the capture process gracefully."""
        logger.info("Stopping packet capture...")
        self.shutdown_event.set()
        
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=5)
            if self.capture_thread.is_alive():
                logger.warning("Packet sniffer thread did not stop in time, forcing")

        with self.lock:
            if self.packets:
                logger.info(f"Performing final write of {len(self.packets)} packets.")
                self._write_file(self.packets, self.current_file_path)
        
        self._write_executor.shutdown(wait=True)
        logger.info("Packet capture stopped.")
