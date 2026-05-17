# core/controller.py
"""
Pipeline controller - orchestrates the full DDoS detection pipeline.
Manages lifecycle of capture, feature extraction, prediction, and mitigation.
"""
from threading import Thread, Event, RLock
from typing import Optional, Dict, Any, List
from datetime import datetime
import uuid
from detection_module.model_update import ModelUpdater
from capapp.orchestration.pipeline import DDoSPipeline
from detection_module.predict_pipeline import LocalPredictionPipeline
from capapp.utils.logger import logger
from capapp.config.settings import config

config.setup_directories()


class PipelineController:
    def __init__(self):
        self.pipeline_active = Event()
        self.lock = RLock()

        self.pipeline: Optional[DDoSPipeline] = None
        self.detect: Optional[LocalPredictionPipeline] = None
        self.model_updater: Optional[ModelUpdater] = None
        self.mitigation_agent = None

        self.ddos_count = 0
        self.normal_count = 0
        self.suspicious_count = 0
        self.recent_detections: List[Dict[str, Any]] = []
        self.start_time: Optional[datetime] = None
        self.model_path = str(config.MODEL_PATH)

        if config.MITIGATION_ENABLED:
            from core.mitigation_agent import MitigationAgent
            self.mitigation_agent = MitigationAgent(
                auto_block=config.MITIGATION_AUTO_BLOCK,
                rate_limit_enabled=config.MITIGATION_RATE_LIMIT_ENABLED,
                rate_limit_ppm=config.MITIGATION_RATE_LIMIT_PPM,
                ml_auto_block=config.MITIGATION_ML_AUTO_BLOCK,
                confidence_threshold=config.MITIGATION_CONFIDENCE_THRESHOLD,
                detection_count=config.MITIGATION_DETECTION_COUNT,
                block_duration_minutes=config.MITIGATION_BLOCK_DURATION_MINUTES,
            )
            logger.info("Mitigation agent initialized (auto_block=%s, rate_limit=%s ppm=%s)",
                       config.MITIGATION_AUTO_BLOCK, config.MITIGATION_RATE_LIMIT_ENABLED, config.MITIGATION_RATE_LIMIT_PPM)

    def initialize_components(self) -> None:
        with self.lock:
            self.model_updater = ModelUpdater(
                model_api_url=config.MODEL_API_URL,
                current_model_path=self.model_path,
                update_interval_hours=config.MODEL_UPDATE_INTERVAL_HOURS,
            )
            self.pipeline = DDoSPipeline(mitigation_agent=self.mitigation_agent)
            self.detect = LocalPredictionPipeline(
                model_path=self.model_path,
                processed_dir=str(config.PROCESSED_FEATURES_DIR),
                output_dir=str(config.PREDICTION_OUTPUT_DIR),
                queue_maxsize=config.QUEUE_MAXSIZE,
                force_cpu=config.FORCE_CPU,
                model_updater=self.model_updater,
                detection_callback=self.record_detection,
            )
            self._reset_counters()

    def _reset_counters(self) -> None:
        self.ddos_count = 0
        self.normal_count = 0
        self.suspicious_count = 0
        self.recent_detections = []
        self.start_time = datetime.now()

    def start_all(self) -> bool:
        if self.pipeline_active.is_set():
            logger.warning("Pipeline already running")
            return False

        try:
            self.initialize_components()
            self.model_updater.start_periodic_update()

            threads = [
                Thread(target=self._run_pipeline, name="DDoSPipelineThread"),
                Thread(target=self._run_detection, name="DetectionThread"),
            ]

            for t in threads:
                t.daemon = True
                t.start()

            with self.lock:
                self.pipeline_threads = threads
                self.pipeline_active.set()

            logger.info("Pipeline started successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to start pipeline: {e}")
            self.stop_all()
            return False

    def _run_pipeline(self) -> None:
        try:
            if self.pipeline:
                self.pipeline.run()
        except Exception as e:
            logger.error(f"Pipeline thread failed: {e}")

    def _run_detection(self) -> None:
        try:
            if self.detect:
                self.detect.start()
        except Exception as e:
            logger.error(f"Detection thread failed: {e}")

    def stop_all(self) -> bool:
        if not self.pipeline_active.is_set():
            logger.warning("Pipeline not running")
            return False

        try:
            if self.pipeline:
                self.pipeline.stop()
            if self.detect:
                self.detect.stop()
            if self.model_updater:
                self.model_updater.stop_periodic_update()

            with self.lock:
                self.pipeline_active.clear()
                self.pipeline = None
                self.detect = None
                self.model_updater = None
                self.pipeline_threads = []

            logger.info("Pipeline stopped successfully")
            return True

        except Exception as e:
            logger.error(f"Error stopping pipeline: {e}")
            return False

    def is_running(self) -> bool:
        return self.pipeline_active.is_set()

    def get_status(self) -> Dict[str, Any]:
        with self.lock:
            queue_size = 0
            if self.detect and hasattr(self.detect, "file_queue"):
                queue_size = self.detect.file_queue.qsize()

            # Count non-blocked detections
            visible_count = len(self.recent_detections)
            if self.mitigation_agent:
                blocked_ips = {ip for ip, info in self.mitigation_agent._blocked_ips.items()
                               if info["expiry"] > datetime.now()}
                visible_count = len([d for d in self.recent_detections if d["src_ip"] not in blocked_ips])

            return {
                "running": self.is_running(),
                "start_time": self.start_time.isoformat() if self.start_time else None,
                "uptime": (datetime.now() - self.start_time).total_seconds() if self.start_time else 0,
                "processed_files": self.detect.processed_files if self.detect else 0,
                "failed_files": self.detect.failed_files if self.detect else 0,
                "ddos_detections": self.ddos_count,
                "normal_detections": self.normal_count,
                "suspicious_detections": self.suspicious_count,
                "recent_detections_count": visible_count,
                "model_loaded": self.detect is not None and self.detect.model is not None,
                "queue_size": queue_size,
                "device": str(getattr(self.detect, "device", "unknown")) if self.detect else "unknown",
            }

    def get_recent_detections(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self.lock:
            # Filter out detections from currently blocked IPs
            if self.mitigation_agent:
                blocked_ips = {ip for ip, info in self.mitigation_agent._blocked_ips.items()
                               if info["expiry"] > datetime.now()}
                filtered = [d for d in self.recent_detections if d["src_ip"] not in blocked_ips]
                return list(reversed(filtered[-limit:]))
            return list(reversed(self.recent_detections[-limit:]))

    def get_detection_details(self, detection_id: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            for detection in self.recent_detections:
                if detection.get("id") == detection_id:
                    return dict(detection)
            return None

    def record_detection(self, detection_data: Dict[str, Any]) -> None:
        prediction_val = detection_data.get("prediction", 0)
        confidence = float(detection_data.get("confidence", 0.0) or 0.0)

        if isinstance(prediction_val, (int, float)):
            is_ddos = int(prediction_val) == 1
        else:
            is_ddos = str(prediction_val).strip().lower() in ("ddos", "1", "attack")

        src_ip = detection_data.get("Src IP", "unknown")
        dst_ip = detection_data.get("Dst IP", "unknown")

        if isinstance(src_ip, (int, float)):
            import ipaddress
            try:
                src_ip = str(ipaddress.ip_address(int(src_ip)))
            except Exception:
                src_ip = str(src_ip)

        if isinstance(dst_ip, (int, float)):
            import ipaddress
            try:
                dst_ip = str(ipaddress.ip_address(int(dst_ip)))
            except Exception:
                dst_ip = str(dst_ip)

        if is_ddos and confidence < 0.6:
            status = "Suspicious"
            severity = "warning"
        elif is_ddos:
            status = "DDoS"
            severity = "critical"
        else:
            status = "Normal"
            severity = "info"

        protocol = detection_data.get("Protocol", "unknown")
        if isinstance(protocol, (int, float)):
            protocol_num = int(protocol)
            protocol_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
            protocol = protocol_map.get(protocol_num, f"Proto-{protocol_num}")

        duration_us = float(detection_data.get("Flow Duration", 0) or 0)
        duration_sec = duration_us / 1_000_000.0

        with self.lock:
            # Skip recording if source IP is already blocked
            if self.mitigation_agent and self.mitigation_agent.is_blocked(src_ip):
                self.mitigation_agent.on_detection({**detection_data, "src_ip": src_ip, "dst_ip": dst_ip})
                return

            if status == "DDoS":
                self.ddos_count += 1
            elif status == "Suspicious":
                self.suspicious_count += 1
            else:
                self.normal_count += 1

            detection = {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.now().isoformat(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "duration": round(duration_sec, 4),
                "status": status,
                "severity": severity,
                "confidence": round(confidence, 4),
                "flow_id": detection_data.get("Flow ID", "unknown"),
                "packets": int(
                    detection_data.get("Total Fwd Packets", 0) or 0
                )
                + int(detection_data.get("Total Bwd Packets", 0) or 0),
                "bytes": int(
                    detection_data.get("Total Length of Fwd Packets", 0) or 0
                )
                + int(detection_data.get("Total Length of Bwd Packets", 0) or 0),
            }

            self.recent_detections.append(detection)
            if len(self.recent_detections) > 200:
                self.recent_detections = self.recent_detections[-100:]

        if self.mitigation_agent:
            self.mitigation_agent.on_detection(detection)


controller = PipelineController()


def start_pipeline() -> bool:
    return controller.start_all()


def stop_pipeline() -> bool:
    return controller.stop_all()


def pipeline_status() -> Dict[str, Any]:
    return controller.get_status()


def is_pipeline_running() -> bool:
    return controller.is_running()


def get_recent_detections(limit: int = 20) -> List[Dict[str, Any]]:
    return controller.get_recent_detections(limit)


def get_detection_details(detection_id: str) -> Optional[Dict[str, Any]]:
    return controller.get_detection_details(detection_id)
