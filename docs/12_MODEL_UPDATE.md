# Model Update System — Remote Model Hot-Swapping

**File:** `detection_module/model_update.py` (150 lines)

## Overview

The Model Updater periodically downloads new PPO model files from a remote API, validates them, and hot-swaps the active model without restarting the pipeline.

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      ModelUpdater                             │
│                                                               │
│  Configuration:                                               │
│  ├── model_api_url: str  # "http://127.0.0.1:8000/api/..."   │
│  ├── current_model_path: Path  # Active model location        │
│  ├── update_interval: timedelta  # Default: 2 hours           │
│  └── lock: threading.Lock  # Thread-safe model access         │
│                                                               │
│  State:                                                       │
│  ├── last_update: datetime  # Last successful update time     │
│  ├── model: EnhancedPPOAgent  # Loaded model in memory        │
│  ├── device: torch.device                                     │
│  └── _stop_event: threading.Event                             │
│                                                               │
│  update_model() → bool  # Download, validate, swap            │
│  start_periodic_update()  # Background thread                 │
│  stop_periodic_update()   # Stop background thread            │
│  get_status() → Dict      # Update status info                │
└──────────────────────────────────────────────────────────────┘
```

## Update Flow

```
update_model()
│
├── Step 1: Download
│   └── download_model() → temp_file_path
│       ├── GET model_api_url with stream=True, timeout=60s
│       ├── Write chunks (8192 bytes) to temp file
│       └── Return Path to temp file
│       └── On failure → return None
│
├── Step 2: Validate
│   └── validate_model(temp_file_path) → bool
│       ├── EnhancedPPOAgent.load_model(temp_path, map_location="cpu")
│       └── Check: hasattr(model, "policy") → True
│       └── On failure → return False
│
├── Step 3: Backup
│   └── If current_model_path exists:
│       ├── backup_path = current_model_path.with_suffix(".bak.{timestamp}")
│       └── shutil.copy2(current_model_path, backup_path)
│
├── Step 4: Swap
│   └── shutil.copy2(temp_model_path, current_model_path)
│
├── Step 5: Load into Memory
│   └── with lock:
│       ├── model = EnhancedPPOAgent.load_model(current_model_path)
│       └── last_update = datetime.now()
│
├── Step 6: Cleanup
│   └── Delete temp file and backup
│
└── Return True
```

## Error Recovery

If any step fails after backup creation:

```
On failure:
│
├── If backup_path exists:
│   └── Try to restore:
│       ├── shutil.copy2(backup_path, current_model_path)
│       └── Log "Backup restored successfully"
│       └── On restore failure → Log CRITICAL
│
└── Delete temp file if it exists
```

## Periodic Update Thread

```
start_periodic_update()
│
└── Spawn daemon thread: update_loop()
    │
    └── While not stopped:
        ├── If (now - last_update) >= update_interval:
        │   └── update_model()
        │
        └── Wait 900 seconds (15 min) or until stop signal
```

The thread checks every 15 minutes whether an update is due, but only performs the actual download when the configured interval (default 2 hours) has elapsed.

## Integration with Prediction Pipeline

The ModelUpdater is shared with the `LocalPredictionPipeline`:

```python
# In PipelineController.initialize_components():
model_updater = ModelUpdater(
    model_api_url=config.MODEL_API_URL,
    current_model_path=self.model_path,
    update_interval_hours=config.MODEL_UPDATE_INTERVAL_HOURS,
)

detect = LocalPredictionPipeline(
    model_path=self.model_path,
    model_updater=model_updater,  # Shared reference
    ...
)
```

When the prediction pipeline loads the model, it first checks if the ModelUpdater has a loaded model in memory:

```python
def _load_model(self, model_path):
    if self.model_updater is not None:
        with self.model_updater.lock:
            if self.model_updater.model is not None:
                return self.model_updater.model  # Use hot-swapped model
    # Fall back to loading from disk
```

## Status Output

```python
get_status() → {
    "last_update": str (ISO) or None,
    "next_update": str (ISO) or None,
    "update_interval_hours": float,
    "model_path": str,
    "model_loaded": bool,
}
```

## API Endpoint

The default model download URL is:

```
http://127.0.0.1:8000/api/pipeline/model/download
```

This expects a raw `.pt` file response. The remote server should serve PyTorch checkpoint files compatible with `EnhancedPPOAgent.load_model()`.
