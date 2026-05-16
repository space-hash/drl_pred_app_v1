# capapp/config/settings.py
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None


PROJECT_ROOT = Path(__file__).resolve().parents[2]
CAPAPP_ROOT = Path(__file__).resolve().parents[1]

if load_dotenv is not None:
    load_dotenv(PROJECT_ROOT / ".env")


def _get_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    return int(value)


def _get_path(name: str, default: Path) -> Path:
    value = os.getenv(name)
    path = Path(value).expanduser() if value is not None else default
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve()


class Config:
    """
    Centralized configuration for the DDoS detection application.
    """

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
    ROTATE_INTERVAL_SECONDS = _get_int("ROTATE_INTERVAL_SECONDS", 30)
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
    MODEL_API_URL = os.getenv(
        "MODEL_API_URL",
        "http://127.0.0.1:8000/api/pipeline/model/download",
    )
    MODEL_UPDATE_INTERVAL_HOURS = _get_int("MODEL_UPDATE_INTERVAL_HOURS", 2)

    # Mitigation agent settings (disabled by default)
    MITIGATION_ENABLED = _get_bool("MITIGATION_ENABLED", False)
    MITIGATION_AUTO_BLOCK = _get_bool("MITIGATION_AUTO_BLOCK", False)
    MITIGATION_RATE_LIMIT_ENABLED = _get_bool("MITIGATION_RATE_LIMIT_ENABLED", True)
    MITIGATION_RATE_LIMIT_PPM = _get_int("MITIGATION_RATE_LIMIT_PPM", 100)
    MITIGATION_ML_AUTO_BLOCK = _get_bool("MITIGATION_ML_AUTO_BLOCK", False)
    MITIGATION_CONFIDENCE_THRESHOLD = float(os.getenv("MITIGATION_CONFIDENCE_THRESHOLD", "0.8"))
    MITIGATION_DETECTION_COUNT = _get_int("MITIGATION_DETECTION_COUNT", 3)
    MITIGATION_BLOCK_DURATION_MINUTES = _get_int("MITIGATION_BLOCK_DURATION_MINUTES", 60)

    @classmethod
    def setup_directories(cls):
        """Creates all necessary directories for the pipeline to operate."""
        import logging
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


config = Config()
