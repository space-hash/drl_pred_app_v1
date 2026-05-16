# capapp/orchestration/pipeline.py
"""
Master orchestrator for the disk-based DDoS detection pipeline.
Initializes, starts, and stops all components in the correct order.
"""
import time
import threading
from capapp.utils.logger import logger
from capapp.capture.packet_capture import PacketCapturer
from capapp.processing.dispatcher import FileDispatcher


class DDoSPipeline:
    """Orchestrates packet capture, dispatching, and feature extraction."""

    def __init__(self, mitigation_agent=None):
        logger.info("Initializing pipeline components...")
        self.mitigation_agent = mitigation_agent
        packet_cb = mitigation_agent.on_packet if mitigation_agent else None
        self.capturer = PacketCapturer(packet_callback=packet_cb)
        self.dispatcher = FileDispatcher()
        self.components = [self.capturer, self.dispatcher]
        self._shutdown_event = threading.Event()

    def start(self):
        """Starts all pipeline components."""
        logger.info("Starting all pipeline components...")
        self._shutdown_event.clear()
        for component in self.components:
            component.start()
        logger.info("All pipeline components are running.")

    def stop(self):
        """Stops all pipeline components gracefully in reverse order."""
        logger.info("Stopping all pipeline components...")
        self._shutdown_event.set()
        for component in reversed(self.components):
            try:
                component.stop()
            except Exception as e:
                logger.error("Error stopping component %s: %s", component.__class__.__name__, e)
        logger.info("Pipeline shutdown complete.")

    def run(self):
        """Runs the pipeline indefinitely until a stop signal is received."""
        self.start()
        try:
            while not self._shutdown_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("KeyboardInterrupt received. Initiating shutdown...")
        finally:
            self.stop()

    def get_status(self):
        """Returns the current status of all pipeline components."""
        return {
            "capturer": {
                "interface": self.capturer.interface,
                "running": self.capturer.capture_thread.is_alive() if self.capturer.capture_thread else False,
                "buffer_size": len(self.capturer.packets),
            },
            "dispatcher": {
                "running": self.dispatcher.dispatcher_thread.is_alive() if self.dispatcher.dispatcher_thread else False,
            },
        }
