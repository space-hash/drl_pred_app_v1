# capapp/config/settings.py
"""
Centralized configuration for the DDoS detection application.
All settings loaded from environment variables with sensible defaults.
"""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CAPAPP_ROOT = Path(__file__).resolve().parents[1]

if load_dotenv is not None:
    load_dotenv(PROJECT_ROOT / ".env")


def _get_bool(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name, default):
    value = os.getenv(name)
    if value is None:
        return default
    return int(value)


def _get_path(name, default):
    value = os.getenv(name)
    path = Path(value).expanduser() if value is not None else default
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve()


class Config:
    """Centralized configuration for the DDoS detection application."""

    PROJECT_ROOT = PROJECT_ROOT
    CAPAPP_ROOT = CAPAPP_ROOT

    # Core directories
    CAPTURE_DIR = CAPAPP_ROOT / "capture_output"
    IN_PROGRESS_DIR = CAPTURE_DIR / "in_progress"
    FEATURES_DIR = CAPAPP_ROOT / "features_output"
    ERROR_DIR = CAPTURE_DIR / "error"
    LOG_DIR = CAPAPP_ROOT / "logs"
    PREDICTIONS_DIR = PROJECT_ROOT / "data" / "predictions"
    MODEL_DIR = PROJECT_ROOT / "detection_module" / "trained_models"

    # Flask app settings
    FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
    FLASK_PORT = _get_int("FLASK_PORT", 5000)
    FLASK_DEBUG = _get_bool("FLASK_DEBUG", False)
    FLASK_APP_URL = os.getenv("FLASK_APP_URL", f"http://127.0.0.1:{FLASK_PORT}")

    # Capture settings
    CAPTURE_INTERFACE = os.getenv("CAPTURE_INTERFACE", "enp0s3")
    CAPTURE_FILTER = os.getenv("CAPTURE_FILTER", "")
    ROTATE_INTERVAL_SECONDS = _get_int("ROTATE_INTERVAL_SECONDS", 5)
    ROTATE_MAX_SIZE_MB = _get_int("ROTATE_MAX_SIZE_MB", 50)

    # Dispatcher and processing settings
    DISPATCHER_POLL_INTERVAL_SECONDS = _get_int("DISPATCHER_POLL_INTERVAL_SECONDS", 5)
    MAX_PROCESSING_WORKERS = _get_int("MAX_PROCESSING_WORKERS", os.cpu_count() or 1)
    PROCESSING_TIMEOUT_SECONDS = _get_int("PROCESSING_TIMEOUT_SECONDS", 300)

    # Feature extraction thresholds
    FLOW_TIMEOUT_NS = _get_int("FLOW_TIMEOUT_NS", 1_200_000_000)
    MAX_FLOW_DURATION_NS = _get_int("MAX_FLOW_DURATION_NS", 120_000_000_000)
    ACTIVE_THRESHOLD_US = _get_int("ACTIVE_THRESHOLD_US", 1_000_000)

    # Model and prediction pipeline settings
    MODEL_PATH = _get_path("MODEL_PATH", MODEL_DIR / "final_drl1.pt")
    PREDICTION_OUTPUT_DIR = _get_path("PREDICTION_OUTPUT_DIR", PREDICTIONS_DIR)
    PROCESSED_FEATURES_DIR = _get_path("PROCESSED_FEATURES_DIR", FEATURES_DIR)
    FORCE_CPU = _get_bool("FORCE_CPU", True)
    QUEUE_MAXSIZE = _get_int("QUEUE_MAXSIZE", 10)

    # Model updater settings
    MODEL_API_URL = os.getenv("MODEL_API_URL", "http://127.0.0.1:8000/api/pipeline/model/download")
    MODEL_UPDATE_INTERVAL_HOURS = _get_int("MODEL_UPDATE_INTERVAL_HOURS", 2)

    # Mitigation agent settings
    MITIGATION_ENABLED = _get_bool("MITIGATION_ENABLED", False)
    MITIGATION_AUTO_BLOCK = _get_bool("MITIGATION_AUTO_BLOCK", False)
    MITIGATION_RATE_LIMIT_ENABLED = _get_bool("MITIGATION_RATE_LIMIT_ENABLED", True)
    MITIGATION_RATE_LIMIT_PPM = _get_int("MITIGATION_RATE_LIMIT_PPM", 1000)
    MITIGATION_ML_AUTO_BLOCK = _get_bool("MITIGATION_ML_AUTO_BLOCK", False)
    MITIGATION_CONFIDENCE_THRESHOLD = float(os.getenv("MITIGATION_CONFIDENCE_THRESHOLD", "0.8"))
    MITIGATION_DETECTION_COUNT = _get_int("MITIGATION_DETECTION_COUNT", 3)
    MITIGATION_BLOCK_DURATION_MINUTES = _get_int("MITIGATION_BLOCK_DURATION_MINUTES", 60)
    MITIGATION_USE_IPTABLES = _get_bool("MITIGATION_USE_IPTABLES", True)

    # eBPF/XDP settings (optional, requires bcc library)
    EBPF_ENABLED = _get_bool("EBPF_ENABLED", False)
    EBPF_USE_XDP = _get_bool("EBPF_USE_XDP", True)
    EBPF_FALLBACK_TO_IPTABLES = _get_bool("EBPF_FALLBACK_TO_IPTABLES", True)

    # DRL mitigation settings
    DRL_MITIGATION_ENABLED = _get_bool("DRL_MITIGATION_ENABLED", False)
    DRL_MITIGATION_MODEL_PATH = os.getenv("DRL_MITIGATION_MODEL_PATH", str(MODEL_DIR / "final_drl1.pt"))
    DRL_MITIGATION_CONFIDENCE_THRESHOLD = float(os.getenv("DRL_MITIGATION_CONFIDENCE_THRESHOLD", "0.7"))
    DRL_MITIGATION_BLOCK_DURATION_MINUTES = _get_int("DRL_MITIGATION_BLOCK_DURATION_MINUTES", 30)
    DRL_MITIGATION_FEATURE_WINDOW_SIZE = _get_int("DRL_MITIGATION_FEATURE_WINDOW_SIZE", 10)

    # Alerting settings
    ALERTING_ENABLED = _get_bool("ALERTING_ENABLED", True)
    ALERTING_RATE_LIMIT_SECONDS = _get_int("ALERTING_RATE_LIMIT_SECONDS", 60)
    ALERTING_DEDUP_WINDOW_SECONDS = _get_int("ALERTING_DEDUP_WINDOW_SECONDS", 300)

    # Email alerting
    ALERTING_EMAIL_ENABLED = _get_bool("ALERTING_EMAIL_ENABLED", False)
    ALERTING_EMAIL_SMTP_HOST = os.getenv("ALERTING_EMAIL_SMTP_HOST", "smtp.gmail.com")
    ALERTING_EMAIL_SMTP_PORT = _get_int("ALERTING_EMAIL_SMTP_PORT", 587)
    ALERTING_EMAIL_USERNAME = os.getenv("ALERTING_EMAIL_USERNAME", "")
    ALERTING_EMAIL_PASSWORD = os.getenv("ALERTING_EMAIL_PASSWORD", "")
    ALERTING_EMAIL_FROM = os.getenv("ALERTING_EMAIL_FROM", "")
    ALERTING_EMAIL_TO = os.getenv("ALERTING_EMAIL_TO", "").split(",") if os.getenv("ALERTING_EMAIL_TO") else []

    # Webhook alerting (Slack, Discord, etc.)
    ALERTING_WEBHOOK_ENABLED = _get_bool("ALERTING_WEBHOOK_ENABLED", False)
    ALERTING_WEBHOOK_URL = os.getenv("ALERTING_WEBHOOK_URL", "")
    ALERTING_WEBHOOK_TYPE = os.getenv("ALERTING_WEBHOOK_TYPE", "generic")

    @classmethod
    def setup_directories(cls):
        """Creates all necessary directories for the pipeline to operate."""
        setup_logger = logging.getLogger("ConfigSetup")
        setup_logger.info("Setting up required directories...")
        for directory in [
            cls.CAPTURE_DIR,
            cls.IN_PROGRESS_DIR,
            cls.FEATURES_DIR,
            cls.ERROR_DIR,
            cls.LOG_DIR,
            cls.PREDICTIONS_DIR,
            cls.MODEL_DIR,
            cls.PROCESSED_FEATURES_DIR,
            cls.PREDICTION_OUTPUT_DIR,
        ]:
            directory.mkdir(parents=True, exist_ok=True)
        setup_logger.info("Directories are ready.")


import logging
config = Config()
