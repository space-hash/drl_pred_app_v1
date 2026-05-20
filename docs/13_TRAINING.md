# Training Script — PPO Model Training

**File:** `train.py` (347 lines)

## Overview

The training script provides a CLI interface for training, evaluating, listing, and comparing PPO models for DDoS detection.

## CLI Commands

```bash
# Train with real data
python train.py --data path/to/data.csv --epochs 500 --output models/my_model.pt

# Train with synthetic data
python train.py --auto-generate --n-samples 10000

# Evaluate a model
python train.py --evaluate models/my_model.pt --data path/to/test.csv

# List all models
python train.py --list-models detection_module/trained_models

# Compare models
python train.py --compare models/model1.pt models/model2.pt
```

## Training Pipeline

```
main()
│
├── Parse arguments
│
├── Load or generate data:
│   ├── --data: load_cic_data(csv_path)
│   │   ├── Read CSV with pandas
│   │   ├── Drop: Flow ID, Timestamp, Fwd Header Length.1, Label
│   │   ├── Replace inf/-inf with NaN
│   │   ├── Fill NaN with column means
│   │   └── Ensure exactly 81 features (truncate or error)
│   │
│   └── --auto-generate: generate_synthetic_data(n_samples, ddos_ratio)
│       ├── Normal: np.random.normal(0, 1, (n_normal, 81))
│       ├── DDoS: np.random.normal(2, 3, (n_ddos, 81))
│       │   └── Features 0-3 have distinct DDoS patterns:
│       │       ├── Feature 0: exponential(5)
│       │       ├── Feature 1: exponential(10)
│       │       ├── Feature 2: normal(100, 50)
│       │       └── Feature 3: normal(50, 20)
│       └── Shuffle and return
│
├── train_model(data, output_path, epochs, hidden_dim, lr, val_split, device)
│   │
│   ├── env_data = prepare_training_data(data)
│   │   └── Compute anomaly scores + hstack with features
│   │       ├── volume_score = norm(features[:, :20]) / 20
│   │       ├── temporal_score = std(features[:, 20:50]) / 10
│   │       └── entropy_score = mean(abs(features[:, 50:])) / 5
│   │
│   ├── env = EnhancedDDoSEnvironment(env_data, validation_split)
│   ├── agent = EnhancedPPOAgent(state_dim=81, action_dim=2, ...)
│   │
│   ├── metrics = agent.train(env, max_episodes=epochs)
│   │
│   ├── metadata = {
│   │       "model_type": "PPO",
│   │       "version": "2.0",
│   │       "created_at": ISO timestamp,
│   │       "training_time_seconds": float,
│   │       "epochs": int,
│   │       "samples_used": int,
│   │       "validation_split": float,
│   │       "hidden_dim": int,
│   │       "learning_rate": float,
│   │       "flow_feature_dim": 81,
│   │       "action_dim": 2,
│   │       "final_reward": float,
│   │       "best_reward": float,
│   │       "platform": str,
│   │       "python_version": str,
│   │       "pytorch_version": str,
│   │   }
│   │
│   └── agent.save_model(output_path, metadata=metadata)
│
└── Print training summary (JSON)
```

## Evaluation

```
evaluate_model(model_path, data)
│
├── Load model: agent = EnhancedPPOAgent.load_model(model_path)
├── Create environment (no validation split)
│
├── For each sample:
│   └── result = agent.predict(sample)
│       └── Collect action, confidence, ddos_probability
│
├── Calculate metrics:
│   ├── total_samples
│   ├── ddos_predicted (action == 1)
│   ├── normal_predicted (action == 0)
│   ├── ddos_ratio
│   ├── avg_confidence
│   └── avg_ddos_probability
│
└── Return metrics dict
```

## Model Listing

```
list_models(models_dir)
│
└── For each .pt file:
    ├── Load checkpoint: torch.load(path, weights_only=False)
    ├── Extract metadata:
    │   ├── created_at
    │   ├── epochs
    │   └── best_reward
    └── Print formatted table row
```

## Model Comparison

```
compare_models(model_paths)
│
└── For each path:
    ├── Load checkpoint
    ├── Extract metadata:
    │   ├── created_at
    │   ├── epochs
    │   ├── best_reward
    │   └── learning_rate
    └── Print formatted table row
```

## Output Format

### List Models Table
```
Model                     Size         Created                Epochs   Best Reward
-------------------------------------------------------------------------------------
final_drl1.pt             2456.3 KB    2026-05-19T14:30:25    500      2.85
trained_model.pt          2456.3 KB    2026-05-18T10:15:00    1000     3.12
```

### Compare Models Table
```
Model                     Size         Created                Epochs   Best Reward  LR
-----------------------------------------------------------------------------------------------
final_drl1.pt             2456.3 KB    2026-05-19T14:30:25    500      2.85         3.00e-04
trained_model.pt          2456.3 KB    2026-05-18T10:15:00    1000     3.12         3.00e-04
```

### Evaluation Output (JSON)
```json
{
  "total_samples": 10000,
  "ddos_predicted": 3200,
  "normal_predicted": 6800,
  "ddos_ratio": 0.32,
  "avg_confidence": 0.8745,
  "avg_ddos_probability": 0.3156
}
```
