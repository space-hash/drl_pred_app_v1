# Model Management Utilities

**Files:**
- `model_manager.py` (358 lines) — Model lifecycle CLI
- `evaluate_model.py` (314 lines) — Model evaluation & validation
- `compare_models.py` (225 lines) — Model comparison utility
- `generate_sample_data.py` (502 lines) — Synthetic data generator
- `add_model_metadata.py` (112 lines) — Metadata enhancer

## Overview

These standalone scripts provide CLI tools for the full model lifecycle: generating training data, training, evaluating, comparing, managing metadata, and cleaning up models.

---

## Model Manager (`model_manager.py`)

A comprehensive CLI for managing trained models with subcommands:

### Subcommands

```bash
# Show detailed model info (JSON output)
python model_manager.py info models/my_model.pt

# Update metadata with key=value pairs
python model_manager.py metadata models/my_model.pt --set name="DDoS v2" description="..."

# View current metadata
python model_manager.py metadata models/my_model.pt

# Validate model integrity
python model_manager.py validate models/my_model.pt

# Export model to different format
python model_manager.py export models/my_model.pt --format pt
python model_manager.py export models/my_model.pt --format state_dict

# List all models
python model_manager.py list detection_module/trained_models/
python model_manager.py list detection_module/trained_models/ -v  # verbose table

# Clean up old models (keep N most recent)
python model_manager.py cleanup detection_module/trained_models/ --keep 3
python model_manager.py cleanup detection_module/trained_models/ --keep 3 --dry-run
```

### Info Command

```
model_manager.py info <path>
│
├── Load checkpoint: torch.load(path, weights_only=False)
├── Extract metadata
├── Calculate model size
├── Show network architecture:
│   ├── Input: 81 features
│   ├── Hidden: 256 → 256 (with LayerNorm + ReLU + Dropout)
│   ├── Policy head: 256 → 128 → 2 (action logits)
│   └── Value head: 256 → 128 → 1 (state value)
│
└── Print formatted report:
    ├── Model name, description, version
    ├── Training info (epochs, samples, time)
    ├── Performance metrics (best reward, final reward)
    ├── Platform info (Python, PyTorch versions)
    └── File info (size, created, modified)
```

### Metadata Command

```
model_manager.py metadata <path> [--set key=value ...]
│
├── With --set: update metadata dict with key=value pairs
│   └── Adds "last_modified" timestamp
│   └── Saves back to same path (modern PyTorch format)
│
└── Without --set: print current metadata as JSON
```

### Validate Command

```
model_manager.py validate <path>
│
├── Check file exists and is readable
├── Load checkpoint
├── Verify required keys:
│   ├── model_state_dict
│   ├── optimizer_state_dict (optional)
│   └── scheduler_state_dict (optional)
│
├── Load model: EnhancedPPOAgent.load_model(path)
├── Verify model has policy attribute
├── Test prediction with dummy 81-dim input
│   └── agent.predict(np.zeros(81, dtype=np.float32))
│
└── Print validation report:
    ├── File integrity: PASS/FAIL
    ├── Checkpoint structure: PASS/FAIL
    ├── Model loading: PASS/FAIL
    └── Inference test: PASS/FAIL
```

### Export Command

```
model_manager.py export <path> [--output PATH] [--format FORMAT]
│
├── Supported formats:
│   ├── pt: Modern PyTorch format (with metadata, optimizer, scheduler)
│   └── state_dict: Raw policy.state_dict() only
│
├── Load model and agent
├── Convert to target format
│
└── Save to: {path.stem}.{ext} (or --output path)
```

### Cleanup Command

```
model_manager.py cleanup <directory> [--keep N] [--dry-run]
│
├── List all .pt files in directory
├── Sort by modification time (newest first)
├── Keep N most recent (default: 3)
│
├── With --dry-run:
│   └── Print what would be removed (no deletion)
│
└── Without --dry-run:
    └── Delete oldest files beyond keep threshold
```

---

## Model Evaluation (`evaluate_model.py`)

Comprehensive model evaluation with detailed metrics:

### CLI Usage

```bash
# Evaluate with real data
python evaluate_model.py --model models/my_model.pt --data data/test.csv

# Evaluate with synthetic data
python evaluate_model.py --model models/my_model.pt --auto-generate --n-samples 5000

# With benchmark (inference speed)
python evaluate_model.py --model models/my_model.pt --auto-generate --benchmark

# Print formatted report
python evaluate_model.py --model models/my_model.pt --auto-generate --report

# Save results to JSON
python evaluate_model.py --model models/my_model.pt --auto-generate --output results.json
```

### CLI Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--model` | Yes | Path to model .pt file |
| `--data` | No* | Path to test data CSV |
| `--auto-generate` | No* | Generate synthetic test data |
| `--n-samples` | No | Number of synthetic samples (default: 5000) |
| `--ddos-ratio` | No | DDoS ratio in synthetic data (default: 0.3) |
| `--benchmark` | No | Run inference speed benchmark |
| `--report` | No | Print formatted report |
| `--output` | No | Save results to JSON file |
| `--seed` | No | Random seed for synthetic data (default: 42) |

*Either `--data` or `--auto-generate` required.

### Evaluation Process

```
evaluate_model(model_path, data, labels, benchmark)
│
├── Load model: EnhancedPPOAgent.load_model(model_path)
├── Set model to eval mode
│
├── Batch inference (batch_size=1000):
│   └── For each batch:
│       └── agent.predict_batch(batch)
│           └── Collect actions, confidences, ddos_probabilities
│
├── Calculate prediction distribution:
│   ├── DDoS count, Normal count, DDoS ratio
│   └── Confidence stats (mean, std, min, max)
│
├── If labels provided:
│   └── compute_metrics(predictions, labels)
│       ├── Accuracy, Precision, Recall, F1
│       ├── FPR, FNR
│       └── Confusion matrix (TP, TN, FP, FN)
│
├── If benchmark:
│   ├── Batch inference timing (10 runs)
│   └── Single prediction timing (100 samples)
│
└── Return results dict (optionally save to JSON)
```

### Output Report Format

```
============================================================
  DRL DDoS Detection - Model Evaluation Report
============================================================

Model: detection_module/trained_models/final_drl1.pt
Evaluated: 2026-05-19T14:30:25
Data samples: 5000

Prediction Distribution:
  DDoS: 1500 (30.00%)
  Normal: 3500

Confidence Statistics:
  Mean: 0.8745
  Std:  0.1234
  Min:  0.5012
  Max:  0.9998

Classification Metrics:
  Accuracy:  0.9452
  Precision: 0.9380
  Recall:    0.9510
  F1 Score:  0.9445
  FPR:       0.0412
  FNR:       0.0490

Confusion Matrix:
                Predicted
                Normal  DDoS
  Actual Normal   3388     112
  Actual DDoS      73    1427

Benchmark (cpu):
  Batch size: 5000
  Avg batch time: 245.32ms
  Samples/sec: 20382
  Single prediction: 0.0489ms

============================================================
```

---

## Model Comparison (`compare_models.py`)

Side-by-side model comparison:

### CLI Usage

```bash
# Compare specific models
python compare_models.py models/model1.pt models/model2.pt models/model3.pt

# Compare with glob patterns
python compare_models.py detection_module/trained_models/*.pt

# With test data CSV
python compare_models.py models/*.pt --data data/test.csv

# With synthetic data
python compare_models.py models/*.pt --auto-generate --n-samples 5000

# With detailed benchmark
python compare_models.py models/*.pt --benchmark

# Save results to JSON
python compare_models.py models/*.pt --benchmark --output comparison.json
```

### CLI Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `models` | Yes | Model files (positional, glob patterns work) |
| `--data` | No | Test data CSV file |
| `--auto-generate` | No | Generate synthetic test data |
| `--n-samples` | No | Number of synthetic samples (default: 5000) |
| `--benchmark` | No | Run detailed benchmarks (5 runs per model) |
| `--output` | No | Save results to JSON file |

### Comparison Process

```
compare_model(model_path, test_data, benchmark)
│
├── Load model → record load_time_ms
├── Extract metadata (version, created, epochs, best_reward)
├── Record file size (MB)
│
├── Batch inference on test_data:
│   ├── Record batch_time_ms
│   ├── Calculate samples_per_sec
│   ├── DDoS predicted, Normal predicted
│   ├── DDoS ratio, avg confidence, avg DDoS prob
│
├── If benchmark (5 runs):
│   ├── avg_ms, min_ms, max_ms, std_ms
│
└── Return result dict
```

### Comparison Table Output

```
========================================================================================================================
  DRL DDoS Detection - Model Comparison
========================================================================================================================

Model                  Size     Load     DDoS%    Confidence   Samples/s    Epochs   Reward
------------------------------------------------------------------------------------------------------------------------
final_drl1.pt          2.40     120.50   30.20%   0.8745       20382        500      2.8
trained_model_v2.pt    2.40     150.20   28.50%   0.9012       23810        1000     3.1

Benchmark (if --benchmark):
Model                  Avg (ms)   Min (ms)   Max (ms)   Std (ms)
----------------------------------------------------------------------
final_drl1.pt          245.32     230.10     260.50     12.30
trained_model_v2.pt    210.45     198.20     225.60     10.15

========================================================================================================================
```

---

## Synthetic Data Generator (`generate_sample_data.py`)

Generates realistic CICFlowMeter-style CSV data for training and testing with 84 columns.

### Traffic Types

| Type | Label | Characteristics |
|------|-------|----------------|
| **Normal** | BENIGN | Low packet counts, regular IAT, small packets, diverse ports |
| **DDoS** | DDoS | High fwd packets, low bwd, targeting single IP, high SYN flags |
| **Flash Crowd** | FlashCrowd | High bidirectional traffic, valid TCP handshakes, diverse destinations |

### CLI Usage

```bash
# Generate single dataset
python generate_sample_data.py --output data/train.csv --n 10000 --ddos-ratio 0.3

# With Flash Crowd traffic
python generate_sample_data.py --output data/train.csv --n 10000 \
    --ddos-ratio 0.3 --flash-crowd-ratio 0.1

# Generate train/test split
python generate_sample_data.py --output data/ --n 100000 \
    --split train test --train-ratio 0.8

# Custom seed for reproducibility
python generate_sample_data.py --output data/test.csv --n 5000 --seed 123
```

### CLI Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--output` | Yes | Output CSV file or directory |
| `--n` | No | Number of samples (default: 10000) |
| `--ddos-ratio` | No | DDoS traffic ratio 0-1 (default: 0.3) |
| `--flash-crowd-ratio` | No | Flash Crowd ratio 0-1 (default: 0.0) |
| `--seed` | No | Random seed (default: 42) |
| `--split` | No | Split data: `--split train test` |
| `--train-ratio` | No | Train split ratio (default: 0.8) |

### Generation Process

```
generate_dataset(n_samples, ddos_ratio, flash_crowd_ratio, seed)
│
├── n_ddos = n_samples * ddos_ratio
├── n_flash = n_samples * flash_crowd_ratio
├── n_normal = n_samples - n_ddos - n_flash
│
├── Normal traffic (generate_normal_traffic):
│   ├── Flow Duration: exponential(1e6)
│   ├── Fwd Packets: poisson(10), Bwd: poisson(8)
│   ├── Packet Lengths: normal(70-100, 20-30)
│   ├── IAT: exponential(1e5)
│   ├── SYN Flags: poisson(3), ACK: poisson(5)
│   └── Ports: common services (80, 443, 22, 53, etc.)
│
├── DDoS traffic (generate_ddos_traffic):
│   ├── Flow Duration: exponential(1e5) — shorter
│   ├── Fwd Packets: poisson(100) — much higher
│   ├── Bwd Packets: poisson(5) — very low
│   ├── Packet Lengths: normal(100, 30) — larger
│   ├── IAT: exponential(1e3) — much faster
│   ├── SYN Flags: poisson(10) — high
│   ├── Target: single IP, ports 80/443
│   └── Down/Up Ratio: 0.01-0.2 — very asymmetric
│
├── Flash Crowd traffic (generate_flash_crowd_traffic):
│   ├── Flow Duration: exponential(2e6) — longer
│   ├── Fwd Packets: poisson(60), Bwd: poisson(55) — balanced
│   ├── Packet Lengths: normal(85-90, 20-25)
│   ├── IAT: exponential(5e4) — moderate
│   ├── SYN Flags: poisson(2), ACK: poisson(15) — valid handshakes
│   ├── Diverse destination IPs
│   └── Down/Up Ratio: 0.7-1.3 — balanced
│
├── Shuffle all traffic together
│
└── Write CSV with 84 CICFlowMeter columns + Label
```

### Output Columns

84 CICFlowMeter columns (same as `CIC_COLUMNS` in the script):
- Flow ID, Src IP, Src Port, Dst IP, Dst Port, Protocol, Timestamp
- Flow Duration, Total Fwd/Bwd Packets, Total Length of Fwd/Bwd Packets
- Fwd/Bwd Packet Length Max/Min/Mean/Std
- Flow Bytes/s, Flow Packets/s
- Flow/Fwd/Bwd IAT Mean/Std/Max/Min (+ Fwd/Bwd IAT Total)
- Fwd/Bwd PSH/URG Flags, Fwd/Bwd Header Length
- Fwd/Bwd Packets/s
- Min/Max/Mean/Std/Variance Packet Length
- FIN/SYN/RST/PSH/ACK/URG/CWE/ECE Flag Count
- Down/Up Ratio, Average Packet Size, Avg Fwd/Bwd Segment Size
- Fwd Header Length.1, Fwd/Bwd Avg Bytes/Packets/Bulk Rate
- Subflow Fwd/Bwd Packets/Bytes
- Init_Win_bytes_forward/backward, act_data_pkt_fwd, min_seg_size_forward
- Active Mean/Std/Max/Min, Idle Mean/Std/Max/Min
- Label (BENIGN / DDoS / FlashCrowd)

---

## Metadata Enhancer (`add_model_metadata.py`)

Scans all `.pt` model files in `detection_module/trained_models/` and adds/enhances metadata for models that lack it.

### CLI Usage

```bash
# Process all models in default directory
python add_model_metadata.py

# Process specific model files
python add_model_metadata.py --models models/final_drl1.pt models/final_drl.pt
```

### What It Does

```
main()
│
├── Default directory: detection_module/trained_models/
│   (or use --models for specific files)
│
├── For each .pt file:
│   ├── Load checkpoint
│   ├── Ensure "metadata" dict exists
│   │
│   ├── Add missing metadata fields:
│   │   ├── model_type: "PPO"
│   │   ├── version: "1.0"
│   │   ├── created_at: file creation timestamp
│   │   ├── state_dim: 81
│   │   └── action_dim: 2
│   │
│   ├── Ensure "model_config" exists:
│   │   ├── state_dim: 81
│   │   ├── action_dim: 2
│   │   ├── hidden_dim: 256
│   │   └── learning_rate: 3e-4
│   │
│   ├── Ensure "platform_info" exists:
│   │   ├── platform: OS name
│   │   ├── python_version
│   │   ├── pytorch_version
│   │   └── saved_device: "cpu"
│   │
│   ├── Ensure "training_metrics" exists (empty dict)
│   │
│   └── Add tracking fields:
│       ├── last_modified: now
│       └── metadata_added_by: "add_model_metadata.py"
│
└── Save updated checkpoint (modern PyTorch format)
```
