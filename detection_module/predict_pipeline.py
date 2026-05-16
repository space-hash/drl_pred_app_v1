# detection_module/predict_pipeline.py
"""
Local prediction pipeline that discovers feature CSV files, runs them through
the DRL model, and calls back with detection results for each flow.
"""
import pandas as pd
import numpy as np
import torch
import ipaddress
import joblib
import shutil
import os
import logging
import queue
import threading
import time
from pathlib import Path
from datetime import datetime
from collections import OrderedDict
from sklearn.preprocessing import StandardScaler
from detection_module.model_update import ModelUpdater
from typing import Optional, Tuple, Dict, Any, List, Callable

logger = logging.getLogger("LocalPredictionPipeline")

EXPECTED_FEATURE_COUNT = 81
MAX_PROCESSED_FILES_TRACKED = 5000


class LocalPredictionPipeline:
    """Discovers feature files, runs predictions, and reports detections."""

    def __init__(
        self,
        model_path,
        processed_dir,
        output_dir="./predictions",
        queue_maxsize=10,
        force_cpu=False,
        model_updater=None,
        detection_callback=None,
    ):
        self.model_updater = model_updater
        self.model_path = model_path
        self.device = self._select_device(force_cpu)
        self.model = self._load_model(model_path)
        self.scaler = self._load_scaler(model_path)
        self.processed_dir = Path(processed_dir)
        self.output_dir = Path(output_dir)
        self.file_queue = queue.Queue(maxsize=queue_maxsize)
        self._stop_event = threading.Event()
        self.processed_files = 0
        self.failed_files = 0
        self._counter_lock = threading.Lock()
        self.detection_callback = detection_callback
        self._setup_directories()
        self._processed_files = OrderedDict()
        self._processing_lock = threading.Lock()
        self._discovery_thread = None
        self._processing_thread = None

    def _select_device(self, force_cpu):
        if force_cpu:
            logger.info("Forcing CPU usage")
            return torch.device("cpu")
        if torch.cuda.is_available():
            logger.info("Using CUDA GPU")
            return torch.device("cuda")
        logger.info("No GPU available, using CPU")
        return torch.device("cpu")

    def _load_model(self, model_path):
        if not Path(model_path).exists():
            raise FileNotFoundError(f"Model file not found at {model_path}")

        try:
            if self.model_updater is not None:
                with self.model_updater.lock:
                    if self.model_updater.model is not None:
                        logger.info("Using model from ModelUpdater")
                        return self.model_updater.model

            from detection_module.detection import EnhancedPPOAgent
            model = EnhancedPPOAgent.load_model(model_path, map_location="cpu")
            if hasattr(model, "policy"):
                logger.info("Model loaded successfully on %s", self.device)
                return model
            raise ValueError("Loaded agent has no policy attribute")
        except FileNotFoundError:
            raise
        except Exception as e:
            logger.error("Model loading failed: %s", e)
            raise RuntimeError(f"Could not load model: {e}")

    def _load_scaler(self, model_path):
        scaler_path = Path(model_path).with_suffix(".scaler.pkl")
        if scaler_path.exists():
            scaler = joblib.load(str(scaler_path))
            logger.info("Loaded scaler from %s", scaler_path)
            return scaler
        raise FileNotFoundError(f"Scaler not found at {scaler_path}")

    def _setup_directories(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        quarantine_dir = self.processed_dir / "quarantine"
        quarantine_dir.mkdir(parents=True, exist_ok=True)

    def _get_oldest_file(self):
        oldest = None
        oldest_mtime = float("inf")
        for f in self.processed_dir.glob("B_*_features.csv"):
            try:
                mtime = f.stat().st_mtime
                if mtime < oldest_mtime:
                    oldest_mtime = mtime
                    oldest = f
            except OSError:
                continue
        return oldest

    def _preprocess_data(self, df):
        output_df = df.copy()
        drop_cols = [c for c in ["Flow ID", "Timestamp", "Fwd Header Length.1"] if c in df.columns]
        df = df.drop(columns=drop_cols)

        for col in ["Src IP", "Dst IP"]:
            if col in df.columns:
                df[col] = df[col].apply(lambda x: int(ipaddress.IPv4Address(str(x))))

        df = df.replace([np.inf, -np.inf], np.nan)
        col_means = df.mean()
        df = df.fillna(col_means).fillna(0)

        X_scaled = self.scaler.transform(df)
        return X_scaled, output_df

    def _postprocess_results(self, predictions, original_df):
        result_df = original_df.copy()
        result_df["prediction"] = predictions["labels"]
        result_df["confidence"] = predictions.get(
            "ddos_probabilities",
            predictions.get("confidences", [0.0] * len(predictions["labels"])),
        )
        return result_df

    def _save_predictions(self, df, input_filename):
        output_file = self.output_dir / f"pred_{input_filename}"
        df.to_csv(output_file, index=False)
        logger.info("Predictions saved to %s", output_file)

    def _quarantine_file(self, file_path):
        quarantine_dir = self.processed_dir / "quarantine"
        new_path = quarantine_dir / file_path.name
        try:
            shutil.move(str(file_path), str(new_path))
            logger.warning("Moved %s to quarantine", file_path.name)
            with self._counter_lock:
                self.failed_files += 1
        except Exception as e:
            logger.error("Failed to quarantine %s: %s", file_path.name, e)

    def _process_file(self, file_path):
        with self._processing_lock:
            if file_path.name in self._processed_files:
                logger.debug("Skipping already processed file: %s", file_path.name)
                return
            self._processed_files[file_path.name] = True
            if len(self._processed_files) > MAX_PROCESSED_FILES_TRACKED:
                for _ in range(MAX_PROCESSED_FILES_TRACKED // 2):
                    self._processed_files.popitem(last=False)

        try:
            logger.info("Processing file: %s", file_path.name)
            if not file_path.exists():
                logger.error("File %s does not exist", file_path.name)
                return

            if file_path.stat().st_size == 0:
                logger.warning("Skipping empty file: %s", file_path.name)
                os.remove(file_path)
                return

            df = pd.read_csv(file_path)
            if df.empty:
                raise ValueError("Empty DataFrame")

            feature_cols = [c for c in df.columns if c not in ["Flow ID", "Timestamp", "Fwd Header Length.1"]]
            if len(feature_cols) != EXPECTED_FEATURE_COUNT:
                raise ValueError(f"Expected {EXPECTED_FEATURE_COUNT} features, got {len(feature_cols)}")

            input_tensor, original_df = self._preprocess_data(df)

            with torch.no_grad():
                predictions = self.model.predict_batch(input_tensor)

            result_df = self._postprocess_results(predictions, original_df)
            self._save_predictions(result_df, file_path.name)

            if self.detection_callback:
                records = result_df.to_dict(orient="records")
                for record in records:
                    try:
                        self.detection_callback(record)
                    except Exception as e:
                        logger.error("Detection callback error: %s", e)

            try:
                os.remove(file_path)
                logger.info("Deleted %s", file_path)
                with self._counter_lock:
                    self.processed_files += 1
            except Exception as e:
                logger.error("Error deleting %s: %s", file_path.name, e)
                self._quarantine_file(file_path)

        except Exception as e:
            logger.error("Error processing %s: %s", file_path.name, e)
            self._quarantine_file(file_path)

    def _file_discovery_worker(self):
        logger.info("File discovery worker started")
        while not self._stop_event.is_set():
            try:
                if not self.file_queue.full():
                    file_path = self._get_oldest_file()
                    if file_path:
                        with self._processing_lock:
                            if file_path.name not in self._processed_files:
                                self.file_queue.put(file_path)
                                logger.debug("Queued file: %s", file_path.name)
                time.sleep(1)
            except Exception as e:
                logger.error("File discovery error: %s", e)
                time.sleep(5)

    def _processing_worker(self):
        logger.info("Processing worker started")
        while not self._stop_event.is_set() or not self.file_queue.empty():
            try:
                file_path = self.file_queue.get(timeout=1)
                self._process_file(file_path)
                self.file_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error("Processing error: %s", e)
                time.sleep(1)

    def start(self):
        if self._discovery_thread and self._discovery_thread.is_alive():
            logger.warning("Pipeline is already running")
            return
        self._stop_event.clear()
        self._discovery_thread = threading.Thread(target=self._file_discovery_worker, name="FileDiscoveryThread", daemon=True)
        self._processing_thread = threading.Thread(target=self._processing_worker, name="ProcessingWorkerThread", daemon=True)
        self._discovery_thread.start()
        self._processing_thread.start()
        logger.info("Pipeline started successfully")

    def stop(self):
        self._stop_event.set()
        if self._discovery_thread and self._discovery_thread.is_alive():
            self._discovery_thread.join(timeout=5)
        if self._processing_thread and self._processing_thread.is_alive():
            self._processing_thread.join(timeout=5)
        logger.info("Pipeline stopped. Processed %d files, %d failed", self.processed_files, self.failed_files)

    def get_status(self):
        return {
            "running": not self._stop_event.is_set(),
            "processed_files": self.processed_files,
            "failed_files": self.failed_files,
            "queue_size": self.file_queue.qsize(),
            "device": str(self.device),
            "model_loaded": self.model is not None,
        }
