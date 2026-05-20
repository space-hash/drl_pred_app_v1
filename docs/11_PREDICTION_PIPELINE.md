# Prediction Pipeline — Batch DRL Inference

**File:** `detection_module/predict_pipeline.py` (303 lines)

## Overview

The Local Prediction Pipeline watches for feature CSV files produced by the CIC Feature Extractor, preprocesses them, runs batch PPO inference, saves prediction results, and triggers the detection callback for mitigation.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                 LocalPredictionPipeline                        │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  Thread 1: "FileDiscoveryThread"                         │ │
│  │  ┌───────────────────────────────────────────────────┐  │ │
│  │  │ _file_discovery_worker()                          │  │ │
│  │  │                                                   │  │ │
│  │  │  While not stopped:                               │  │ │
│  │  │  ├── Scan processed_features/ for B_*_features.csv│  │ │
│  │  │  ├── Find oldest file by mtime                    │  │ │
│  │  │  ├── Check if already processed (OrderedDict)     │  │ │
│  │  │  └── Put in file_queue (maxsize=10)               │  │ │
│  │  └───────────────────────────────────────────────────┘  │ │
│  │                                                          │ │
│  │  Thread 2: "ProcessingWorkerThread"                      │ │
│  │  ┌───────────────────────────────────────────────────┐  │ │
│  │  │ _processing_worker()                              │  │ │
│  │  │                                                   │  │ │
│  │  │  While not stopped or queue not empty:            │  │ │
│  │  │  ├── Get file from queue                          │  │ │
│  │  │  ├── _process_file(file_path)                     │  │ │
│  │  │  │   ├── Read CSV                                 │  │ │
│  │  │  │   ├── Preprocess (IP convert, scale, NaN fill) │  │ │
│  │  │  │   ├── model.predict_batch(input_tensor)        │  │ │
│  │  │  │   ├── Save prediction CSV                      │  │ │
│  │  │  │   ├── Call detection_callback for each row     │  │ │
│  │  │  │   └── Delete input CSV                         │  │ │
│  │  │  └── task_done()                                  │  │ │
│  │  └───────────────────────────────────────────────────┘  │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
│  Components:                                                  │
│  ├── model: EnhancedPPOAgent (loaded .pt)                     │
│  ├── scaler: StandardScaler (optional .scaler.pkl)            │
│  ├── device: torch.device (CPU or CUDA)                       │
│  ├── file_queue: Queue(maxsize=10)                            │
│  ├── model_updater: ModelUpdater (optional)                   │
│  └── detection_callback: Callable[[Dict], None]               │
└──────────────────────────────────────────────────────────────┘
```

## Preprocessing Pipeline

```
_preprocess_data(df) → (X_scaled, original_df)
│
├── Drop metadata columns:
│   └── ["Flow ID", "Timestamp", "Fwd Header Length.1"]
│
├── Convert IP addresses to integers:
│   ├── ipaddress.ip_address(str(x))
│   ├── IPv4: int(addr)
│   └── IPv6: int(addr) % (2**32)  # Truncate to 32-bit
│
├── Handle infinities:
│   └── df.replace([inf, -inf], nan)
│
├── Fill NaN values:
│   └── df.fillna(col_means).fillna(0)
│
├── Scale features (if scaler available):
│   └── X_scaled = scaler.transform(df)
│
└── Return: (numpy array, original DataFrame)
```

## File Processing Flow

```
_process_file(file_path)
│
├── Check if already processed (OrderedDict tracking)
│   └── Max 5,000 tracked files, evicts oldest 2,500 when full
│
├── Read CSV: df = pd.read_csv(file_path)
│
├── Validate feature count:
│   └── len(feature_cols) must equal 81
│   └── If not → quarantine file
│
├── Preprocess: X_scaled, original_df = _preprocess_data(df)
│
├── Batch inference:
│   ├── predictions = model.predict_batch(X_scaled)
│   │   └── Returns: {
│   │       "actions": np.array([0, 1, 0, ...]),
│   │       "labels": ['Normal', 'DDoS', 'Normal', ...],
│   │       "confidences": np.array([0.95, 0.87, ...]),
│   │       "ddos_probabilities": np.array([0.05, 0.87, ...]),
│   │   }
│   │
│   └── If CUDA error → retry on CPU, then restore device
│
├── Postprocess:
│   └── Add "prediction" and "confidence" columns to original_df
│
├── Save predictions:
│   └── data/predictions/pred_B_..._features.csv
│
├── Call detection_callback for each row:
│   └── controller.record_detection(record)
│       ├── Updates counters
│       ├── Routes through mitigation
│       └── Triggers alerts
│
├── Delete input CSV file
│   └── If deletion fails → quarantine file
│
└── Increment processed_files counter
```

## Error Handling

| Error | Action |
|-------|--------|
| File not found | Log error, skip |
| Empty file | Delete file, skip |
| Empty DataFrame | Quarantine |
| Wrong feature count | Quarantine |
| CUDA error during inference | Retry on CPU, restore device |
| File deletion fails | Quarantine |
| Any other exception | Quarantine |

### Quarantine

Failed files are moved to `processed_features/quarantine/`:

```python
def _quarantine_file(file_path):
    quarantine_dir = processed_dir / "quarantine"
    shutil.move(file_path, quarantine_dir / file_path.name)
    failed_files += 1
```

## Device Selection

```python
def _select_device(force_cpu):
    if force_cpu:
        return torch.device("cpu")
    if torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")
```

## Model Loading Priority

```
_load_model(model_path)
│
├── If model_updater has a loaded model:
│   └── Use model_updater.model (hot-swapped model)
│
└── Otherwise:
    └── EnhancedPPOAgent.load_model(model_path)
```

## Status Output

```python
get_status() → {
    "running": bool,
    "processed_files": int,
    "failed_files": int,
    "queue_size": int,
    "device": str,       # "cpu" or "cuda"
    "model_loaded": bool,
}
```
