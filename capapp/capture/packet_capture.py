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
    def __init__(self):
        self.shutdown_event = threading.Event()
        self.capture_thread = None
        self.packets = []
        self.current_file_path: Path = None
        self.last_rotation_time = 0
        self.lock = threading.Lock()
        self.interface = self._validate_interface()
        self._write_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="PCAPWriter")

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
