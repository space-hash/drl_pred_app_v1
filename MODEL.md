# DRL DDoS Detection - Model Documentation

## Model Overview

This project uses **PPO (Proximal Policy Optimization)**, a Deep Reinforcement Learning algorithm, to classify network traffic flows as **Normal** or **DDoS**.

## Architecture

```
Input (81 CIC features)
    │
    ▼
┌─────────────────────────────┐
│   Shared Feature Extractor   │
│   Linear(81 → 256)          │
│   LayerNorm + ReLU + Dropout │
│   Linear(256 → 256)         │
│   LayerNorm + ReLU + Dropout │
└──────────────┬──────────────┘
               │
       ┌───────┴───────┐
       ▼               ▼
┌──────────────┐ ┌──────────────┐
│ Policy Head   │ │  Value Head   │
│ Linear→128    │ │ Linear→128    │
│ ReLU→Linear→2 │ │ ReLU→Linear→1 │
│ (action probs)│ │ (state value) │
└──────────────┘ └──────────────┘
```

### Configuration

| Parameter | Value |
|---|---|
| Input features | 81 (CICFlowMeter flow features) |
| Hidden dimensions | 256 |
| Actions | 2 (Normal=0, DDoS=1) |
| Learning rate | 3e-4 |
| Gamma (discount) | 0.99 |
| GAE lambda | 0.95 |
| PPO epsilon | 0.2 |
| Batch size | 512 |
| Update epochs | 10 |
| Entropy coefficient | 0.02 |
| Value coefficient | 0.5 |
| Max gradient norm | 0.5 |

## Model Files

Located in `detection_module/trained_models/`:

| File | Size | Purpose |
|---|---|---|
| `final_drl1.pt` | ~1.8 MB | **Default model** used by the pipeline |
| `final_drl.pt` | ~1.8 MB | Alternate trained model |
| `final_drl11.pt` | ~1.8 MB | Alternate trained model |
| `t1.pt` - `t4.pt` | ~1.9-2.0 MB | Training checkpoints |
| `train2.pt` | ~2.0 MB | Training checkpoint |

## Quick Start

### 1. Generate Test Data
```bash
python generate_sample_data.py --output data/ --split train test --n 10000
```

### 2. Train a New Model
```bash
# Using synthetic data (for testing)
python train.py --auto-generate --n-samples 10000 --epochs 100 --output detection_module/trained_models/my_model.pt

# Using real CICFlowMeter CSV data
python train.py --data data/train.csv --epochs 500 --output detection_module/trained_models/my_model.pt
```

### 3. Evaluate a Model
```bash
# With synthetic data
python evaluate_model.py --model detection_module/trained_models/final_drl1.pt --auto-generate --n-samples 5000 --report

# With real test data
python evaluate_model.py --model detection_module/trained_models/final_drl1.pt --data data/test.csv --report --benchmark

# Save results to JSON
python evaluate_model.py --model detection_module/trained_models/final_drl1.pt --auto-generate --output results/evaluation.json
```

### 4. Compare Models
```bash
python compare_models.py detection_module/trained_models/*.pt --auto-generate --n-samples 5000 --benchmark

# Save comparison results
python compare_models.py detection_module/trained_models/*.pt --output results/comparison.json
```

### 5. Manage Models
```bash
# List all models with details
python model_manager.py list detection_module/trained_models/ -v

# Validate a model
python model_manager.py validate detection_module/trained_models/final_drl1.pt

# Show model info
python model_manager.py info detection_module/trained_models/final_drl1.pt

# Export to modern format
python model_manager.py export detection_module/trained_models/final_drl1.pt --format pt

# Cleanup old models (keep 3 newest)
python model_manager.py cleanup detection_module/trained_models/ --keep 3 --dry-run
```

## Training Data Format

The training script expects CSV files with CICFlowMeter-style columns. Required:
- **81 flow feature columns** (see `CIC_COLUMNS` in `generate_sample_data.py`)
- Optional: `Label` column (BENIGN/DDoS) for reference

Columns automatically dropped during preprocessing:
- `Flow ID`, `Timestamp`, `Fwd Header Length.1`

## Inference Pipeline

```
PCAP → Feature Extraction → CSV → StandardScaler → PPO Model → Prediction
                                                      │
                                    ┌─────────────────┼─────────────────┐
                                    ▼                 ▼                 ▼
                              Action: 0/1      Confidence: 0-1    DDoS Prob: 0-1
                              (Normal/DDoS)   (Model certainty)  (Attack likelihood)
```

## Model Update System

The application supports automatic model updates from a remote API:

1. **Periodic Check**: Every `MODEL_UPDATE_INTERVAL_HOURS` (default: 2h)
2. **Download**: Fetches new model from `MODEL_API_URL`
3. **Validate**: Tests the model loads correctly before replacing
4. **Backup**: Creates `.bak.{timestamp}` backup before replacement
5. **Hot Swap**: New model loaded into memory without restart

Configure in `.env`:
```
MODEL_API_URL=http://your-server/api/model/download
MODEL_UPDATE_INTERVAL_HOURS=2
```

## Troubleshooting

### Model fails to load
```bash
python model_manager.py validate detection_module/trained_models/final_drl1.pt
```

### Check model metadata
```bash
python model_manager.py info detection_module/trained_models/final_drl1.pt
```

### Compare all models
```bash
python compare_models.py detection_module/trained_models/*.pt --auto-generate
```

### Retrain from scratch
```bash
python train.py --auto-generate --n-samples 20000 --epochs 500 --output detection_module/trained_models/final_drl1.pt
```
