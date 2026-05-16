import pandas as pd
import numpy as np
import torch
import ipaddress
from pathlib import Path
import os
import logging
import queue
import threading
from datetime import datetime
import requests
import time
from sklearn.preprocessing import StandardScaler
from detection_module.model_update import ModelUpdater
from typing import Optional, Tuple, Dict, Any, List
from detection_module.detection import EnhancedPPOAgent, EnhancedDDoSEnvironment

logger = logging.getLogger("LocalPredictionPipeline")


class LocalPredictionPipeline:
    def __init__(
        self,
        model_path: str,
        processed_dir: str,
        flask_app_url: str = "http://127.0.0.1:5000",
        output_dir: str = "./predictions",
        queue_maxsize: int = 10,
        force_cpu: bool = False,
        model_updater: ModelUpdater = None,
    ):
        self.model_updater = model_updater
        self.ddos_count = 0
        self.normal_count = 0
        self.suspicious_count = 0
        self.recent_detections = []
        self.device = self._select_device(force_cpu)
        self.model = self._load_model(model_path)
        self.processed_dir = Path(processed_dir)
        self.output_dir = Path(output_dir)
        self.flask_app_url = flask_app_url
        self.file_queue = queue.Queue(maxsize=queue_maxsize)
        self._stop_event = threading.Event()
        self.processed_files = 0
        self.failed_files = 0
        self._setup_directories()
        self._processed_files = set()
        self._processing_lock = threading.Lock()

    def _select_device(self, force_cpu: bool) -> torch.device:
        if force_cpu:
            logger.info("Forcing CPU usage as requested")
            return torch.device("cpu")
        if torch.cuda.is_available():
            logger.info("CUDA GPU available, using GPU acceleration")
            return torch.device("cuda")
        logger.info("No GPU available, falling back to CPU")
        return torch.device("cpu")

    def _load_model(self, model_path: str) -> torch.nn.Module:
        if not Path(model_path).exists():
            raise FileNotFoundError(f"Model file not found at {model_path}")

        try:
            if self.model_updater is not None:
                with self.model_updater.lock:
                    if self.model_updater.model is not None:
                        logger.info("Using model from ModelUpdater")
                        return self.model_updater.model

            model = EnhancedPPOAgent.load_model(model_path, map_location="cpu")
            if hasattr(model, "policy"):
                logger.info("Model loaded successfully to %s", self.device)
                return model
            raise ValueError("Loaded agent has no policy attribute")
        except FileNotFoundError:
            raise
        except Exception as e:
            logger.error(f"Model loading failed: {e}")
            raise RuntimeError(f"Could not load model: {e}")

    def _setup_directories(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        quarantine_dir = self.processed_dir / "quarantine"
        quarantine_dir.mkdir(parents=True, exist_ok=True)

    def _get_oldest_file(self) -> Optional[Path]:
        files = []
        for f in self.processed_dir.glob("B_*_features.csv"):
            try:
                ts_str = "_".join(f.name.split("_")[1:3])
                timestamp = datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
                files.append((timestamp, f))
            except Exception as e:
                logger.warning(f"Skipping file with invalid timestamp {f.name}: {e}")
                continue
        return min(files, key=lambda x: x[0])[1] if files else None

    def _send_to_flask_app(self, data: Dict[str, Any], endpoint: str) -> bool:
        max_retries = 3
        retry_delay = 2
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    f"{self.flask_app_url}/{endpoint}",
                    json=data,
                    timeout=10,
                )
                if response.status_code == 200:
                    logger.info(f"Data sent successfully: {response.status_code}")
                    return True
                logger.warning(
                    f"Flask app returned status {response.status_code} (attempt {attempt + 1}/{max_retries})"
                )
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
            except Exception as e:
                logger.warning(
                    f"Failed to connect to Flask app (attempt {attempt + 1}/{max_retries}): {e}"
                )
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
        return False

    def _preprocess_data(self, df: pd.DataFrame) -> Tuple[np.ndarray, pd.DataFrame]:
        output_df = df.copy()
        drop_cols = [c for c in ["Flow ID", "Timestamp", "Fwd Header Length.1"] if c in df.columns]
        df = df.drop(columns=drop_cols)

        for col in ["Src IP", "Dst IP"]:
            if col in df.columns:
                df[col] = df[col].apply(lambda x: int(ipaddress.IPv4Address(str(x))))

        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(df.mean(), inplace=True)

        scaler = StandardScaler()
        X_train = scaler.fit_transform(df)
        return X_train, output_df

    def _postprocess_results(
        self, predictions: Dict[str, np.ndarray], original_df: pd.DataFrame
    ) -> pd.DataFrame:
        result_df = original_df.copy()
        result_df["prediction"] = predictions["labels"]
        return result_df

    def _save_predictions(self, df: pd.DataFrame, input_filename: str):
        output_file = self.output_dir / f"pred_{input_filename}"
        df.to_csv(output_file, index=False)
        logger.info(f"Predictions saved to {output_file}")

    def _quarantine_file(self, file_path: Path):
        quarantine_dir = self.processed_dir / "quarantine"
        new_path = quarantine_dir / file_path.name
        try:
            os.rename(file_path, new_path)
            logger.warning(f"Moved {file_path.name} to quarantine")
            self.failed_files += 1
        except Exception as e:
            logger.error(f"Failed to quarantine {file_path.name}: {e}")

    def _process_file(self, file_path: Path):
        with self._processing_lock:
            if file_path.name in self._processed_files:
                logger.debug(f"Skipping already processed file: {file_path.name}")
                return
            self._processed_files.add(file_path.name)

        try:
            logger.info(f"Processing file: {file_path.name}")
            if not file_path.exists():
                logger.error(f"File {file_path.name} does not exist")
                return

            df = pd.read_csv(file_path)
            if df.empty:
                raise ValueError("Empty DataFrame")

            raw_data = df.to_dict(orient="records")
            self._send_to_flask_app(
                {
                    "filename": file_path.name,
                    "data": raw_data,
                    "timestamp": datetime.now().isoformat(),
                },
                "raw_data",
            )

            input_tensor, original_df = self._preprocess_data(df)

            try:
                with torch.no_grad():
                    predictions = self.model.predict_batch(input_tensor)
            except RuntimeError as e:
                if "CUDA" in str(e):
                    logger.warning("CUDA error during prediction, retrying on CPU...")
                    input_tensor_cpu = torch.tensor(input_tensor).to("cpu")
                    model_cpu = self.model.to("cpu")
                    with torch.no_grad():
                        predictions = model_cpu.predict_batch(input_tensor_cpu)
                else:
                    raise

            result_df = self._postprocess_results(predictions, original_df)
            self._save_predictions(result_df, file_path.name)

            for _, row in result_df.iterrows():
                from core.controller import controller

                controller.record_detection(row.to_dict())

            self._send_to_flask_app(
                {
                    "filename": file_path.name,
                    "predictions": result_df.to_dict(orient="records"),
                    "metadata": {
                        "model_version": "1.0",
                        "processing_time": datetime.now().isoformat(),
                        "device": str(self.device),
                    },
                },
                "api/data",
            )

            try:
                os.remove(file_path)
                logger.info(f"Successfully deleted {file_path}")
                self.processed_files += 1
            except Exception as e:
                logger.error(f"Error deleting {file_path.name}: {e}")
                self._quarantine_file(file_path)

        except Exception as e:
            logger.error(f"Error processing {file_path.name}: {e}")
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
                                logger.debug(f"Queued file: {file_path.name}")
                time.sleep(1)
            except Exception as e:
                logger.error(f"File discovery error: {e}")
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
                logger.error(f"Processing error: {e}")
                time.sleep(1)

    def start(self):
        if hasattr(self, "_discovery_thread") and self._discovery_thread.is_alive():
            logger.warning("Pipeline is already running")
            return
        self._stop_event.clear()
        self._discovery_thread = threading.Thread(
            target=self._file_discovery_worker,
            name="FileDiscoveryThread",
            daemon=True,
        )
        self._processing_thread = threading.Thread(
            target=self._processing_worker,
            name="ProcessingWorkerThread",
            daemon=True,
        )
        self._discovery_thread.start()
        self._processing_thread.start()
        logger.info("Pipeline started successfully")

    def stop(self):
        self._stop_event.set()
        if self.model_updater is not None:
            self.model_updater.stop_periodic_update()
        if hasattr(self, "_discovery_thread"):
            self._discovery_thread.join(timeout=5)
        if hasattr(self, "_processing_thread"):
            self._processing_thread.join(timeout=5)
        logger.info(
            f"Pipeline stopped. Processed {self.processed_files} files, {self.failed_files} failed"
        )

    def get_status(self) -> Dict[str, Any]:
        return {
            "running": not self._stop_event.is_set(),
            "processed_files": self.processed_files,
            "failed_files": self.failed_files,
            "queue_size": self.file_queue.qsize(),
            "device": str(self.device),
            "model_loaded": self.model is not None,
        }
