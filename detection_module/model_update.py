import requests
import os
import tempfile
import time
import torch
import shutil
import threading
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from detection_module.detection import EnhancedPPOAgent
import logging

logger = logging.getLogger("ModelUpdater")


class ModelUpdater:
    def __init__(
        self,
        model_api_url: str,
        current_model_path: str,
        update_interval_hours: int = 2,
    ):
        self.model_api_url = model_api_url
        self.current_model_path = Path(current_model_path)
        self.update_interval = timedelta(hours=update_interval_hours)
        self.last_update = None
        self._stop_event = threading.Event()
        self.lock = threading.Lock()
        self.model = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self._update_thread = None

    def download_model(self) -> Optional[Path]:
        try:
            response = requests.get(self.model_api_url, stream=True, timeout=60)
            response.raise_for_status()
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pt") as tmp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    tmp_file.write(chunk)
                return Path(tmp_file.name)
        except Exception as e:
            logger.error(f"Model download failed: {e}")
            return None

    def validate_model(self, model_path: Path) -> bool:
        try:
            temp_model = EnhancedPPOAgent.load_model(str(model_path), map_location="cpu")
            if hasattr(temp_model, "policy"):
                return True
            return False
        except Exception as e:
            logger.error(f"Model validation failed: {e}")
            return False

    def update_model(self) -> bool:
        logger.info("Starting model update process...")
        temp_model_path = None
        backup_path = None

        try:
            temp_model_path = self.download_model()
            if not temp_model_path:
                logger.error("Failed to download model")
                return False

            if not self.validate_model(temp_model_path):
                logger.error("Model validation failed")
                return False

            if self.current_model_path.exists():
                backup_path = self.current_model_path.with_suffix(
                    f".bak.{int(time.time())}"
                )
                shutil.copy2(self.current_model_path, backup_path)
                logger.info(f"Created backup at {backup_path}")

            shutil.copy2(temp_model_path, self.current_model_path)
            logger.info(f"Copied new model to {self.current_model_path}")

            with self.lock:
                self.model = EnhancedPPOAgent.load_model(
                    str(self.current_model_path), map_location="cpu"
                )
                self.last_update = datetime.now()

            if temp_model_path.exists():
                os.unlink(temp_model_path)
            if backup_path and backup_path.exists():
                os.unlink(backup_path)

            logger.info("Model successfully updated")
            return True

        except Exception as e:
            logger.error(f"Model update failed: {e}")

            if backup_path and backup_path.exists():
                try:
                    logger.info("Attempting to restore from backup")
                    shutil.copy2(backup_path, self.current_model_path)
                    logger.info("Backup restored successfully")
                except Exception as restore_error:
                    logger.critical(f"Failed to restore backup: {restore_error}")

            if temp_model_path and temp_model_path.exists():
                try:
                    os.unlink(temp_model_path)
                except Exception:
                    pass

            return False

    def start_periodic_update(self):
        if self._update_thread and self._update_thread.is_alive():
            logger.info("Periodic update thread already running")
            return

        self.last_update = datetime.now()

        def update_loop():
            while not self._stop_event.is_set():
                try:
                    now = datetime.now()
                    if (now - self.last_update) >= self.update_interval:
                        self.update_model()
                except Exception as e:
                    logger.error(f"Error in update loop: {e}")
                self._stop_event.wait(900)

        self._update_thread = threading.Thread(target=update_loop, daemon=True)
        self._update_thread.start()
        logger.info("Started periodic model updater")

    def stop_periodic_update(self):
        self._stop_event.set()
        if self._update_thread and self._update_thread.is_alive():
            self._update_thread.join(timeout=5)
        logger.info("Stopped periodic model updater")

    def get_status(self) -> Dict[str, Any]:
        return {
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "next_update": (self.last_update + self.update_interval).isoformat()
            if self.last_update
            else None,
            "update_interval_hours": self.update_interval.total_seconds() / 3600,
            "model_path": str(self.current_model_path),
            "model_loaded": self.model is not None,
        }
