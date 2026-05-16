# capapp/capture/file_writer.py
# NOTE: This file is currently unused. The active capture component is packet_capture.py.
# Kept for reference only. Do not import until config values are added.
import time
import threading
from queue import Queue, Empty
from datetime import datetime
from scapy.all import wrpcap
from capapp.utils.logger import logger
from capapp.config.settings import config

class PCAPFileWriter:
    """
    Writes packets from a queue to .pcap files, rotating them based on size or time.
    This version is optimized for high traffic by draining the queue in batches.

    WARNING: This class requires the following config values which are not yet defined:
      - config.PACKET_QUEUE_MAXSIZE
      - config.MAX_PCAP_SIZE
      - config.CAPTURE_INTERVAL
      - config.PCAP_DIR
    """
    def __init__(self, packet_queue: Queue, file_queue: Queue):
        self.packet_queue = packet_queue
        self.file_queue = file_queue
        self.shutdown_event = threading.Event()
        self.writer_thread = None

    def _write_loop(self):
        packets_batch = []
        last_rotation_time = time.time()
        current_batch_size = 0

        while not self.shutdown_event.is_set():
            try:
                max_size = getattr(config, "PACKET_QUEUE_MAXSIZE", 100)
                for _ in range(max_size):
                    packet = self.packet_queue.get_nowait()
                    packets_batch.append(packet)
                    current_batch_size += len(packet)
                    self.packet_queue.task_done()
            except Empty:
                pass

            time_since_rotation = time.time() - last_rotation_time
            max_pcap_size = getattr(config, "MAX_PCAP_SIZE", 50 * 1024 * 1024)
            capture_interval = getattr(config, "CAPTURE_INTERVAL", 30)
            size_exceeded = current_batch_size >= max_pcap_size
            time_exceeded = time_since_rotation >= capture_interval

            if (size_exceeded or time_exceeded) and packets_batch:
                self._write_and_enqueue(packets_batch)
                packets_batch = []
                current_batch_size = 0
                last_rotation_time = time.time()

            if not packets_batch:
                time.sleep(0.05)

        if packets_batch:
            logger.info(f"Performing final write of {len(packets_batch)} packets before shutdown.")
            self._write_and_enqueue(packets_batch)

        logger.info("File writer loop has stopped.")

    def _write_and_enqueue(self, packets: list):
        timestamp = datetime.now()
        pcap_dir = getattr(config, "PCAP_DIR", config.CAPTURE_DIR)
        file_path = pcap_dir / f"B_{timestamp}.pcap"

        try:
            logger.info(f"Writing {len(packets)} packets to {file_path.name}...")
            wrpcap(str(file_path), packets)

            if not self.file_queue.full():
                self.file_queue.put(file_path)
                logger.info(f"File rotated and enqueued: {file_path.name}")
            else:
                logger.error(f"File processing queue is full. Discarding {file_path.name}.")
                file_path.unlink()
        except Exception as e:
            logger.error(f"Failed to write .pcap file {file_path.name}: {e}", exc_info=True)

    def start(self):
        if self.writer_thread and self.writer_thread.is_alive():
            logger.warning("File writer thread is already running.")
            return

        self.shutdown_event.clear()
        self.writer_thread = threading.Thread(target=self._write_loop, name="FileWriterThread")
        self.writer_thread.daemon = True
        self.writer_thread.start()
        logger.info("PCAP file writer started.")

    def stop(self):
        logger.info("Stopping file writer...")
        self.shutdown_event.set()
        if self.writer_thread and self.writer_thread.is_alive():
            self.writer_thread.join(timeout=5)
        logger.info("File writer stopped.")
