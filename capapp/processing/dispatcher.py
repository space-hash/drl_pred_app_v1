# capapp/processing/dispatcher.py
"""
File dispatcher that scans the capture directory for new .pcap files
and dispatches them to the CIC feature extractor.
"""
import time
import threading
from capapp.utils.logger import logger
from capapp.config.settings import config
from capapp.processing.feature_extractor.cic_extractor import CICFeatureExtractor
from capapp.storage.file_manager import FileManager


class FileDispatcher:
    """Continuously scans for new .pcap files and dispatches them for feature extraction."""

    def __init__(self):
        self.shutdown_event = threading.Event()
        self.dispatcher_thread = None
        self.feature_extractor = None

    def _find_oldest_file(self):
        """Finds the oldest settled .pcap file in the capture directory."""
        try:
            settling_time = 10
            now = time.time()
            files = []
            for f in config.CAPTURE_DIR.iterdir():
                if f.is_file() and f.suffix == ".pcap" and not f.name.endswith(".tmp"):
                    age = now - f.stat().st_mtime
                    if age >= settling_time:
                        files.append(f)
            if not files:
                return None
            return min(files, key=lambda f: f.stat().st_mtime)
        except Exception as e:
            logger.error("Error scanning for files in %s: %s", config.CAPTURE_DIR, e)
            return None

    def _dispatch_loop(self):
        """Main loop that finds and processes files."""
        while not self.shutdown_event.is_set():
            pcap_path = self._find_oldest_file()
            if not pcap_path:
                time.sleep(config.DISPATCHER_POLL_INTERVAL_SECONDS)
                continue

            logger.info("Found file to process: %s", pcap_path.name)
            in_progress_path = FileManager.move_to_in_progress(pcap_path)
            if not in_progress_path:
                continue

            logger.info("Dispatching %s for feature extraction...", in_progress_path.name)
            success, output_path = self.feature_extractor.process_pcap(in_progress_path)

            if success:
                FileManager.move_to_processed(in_progress_path)
            else:
                FileManager.move_to_error(in_progress_path)

        logger.info("File dispatcher loop has stopped.")

    def start(self):
        """Starts the file dispatcher thread."""
        if self.dispatcher_thread and self.dispatcher_thread.is_alive():
            logger.warning("Dispatcher is already running.")
            return

        self.shutdown_event.clear()
        self.feature_extractor = CICFeatureExtractor()
        self.dispatcher_thread = threading.Thread(target=self._dispatch_loop, name="FileDispatcher", daemon=True)
        self.dispatcher_thread.start()
        logger.info("File dispatcher started.")

    def stop(self):
        """Stops the dispatcher gracefully."""
        logger.info("Stopping file dispatcher...")
        self.shutdown_event.set()
        if self.dispatcher_thread and self.dispatcher_thread.is_alive():
            self.dispatcher_thread.join(timeout=10)
        if self.feature_extractor:
            self.feature_extractor.shutdown()
        logger.info("File dispatcher stopped.")
