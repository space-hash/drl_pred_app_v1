# Detection Module — PPO Deep Reinforcement Learning

**File:** `detection_module/detection.py` (1377 lines)

## Overview

The detection module contains the core DRL (Deep Reinforcement Learning) implementation: an Enhanced PPO (Proximal Policy Optimization) agent trained to classify network flows as Normal or DDoS based on 81-dimensional CICFlowMeter features.

## Module Components

```
detection.py
├── AdaptiveThresholdDetector    # EWMA-based dynamic anomaly detection
├── EnhancedDDoSEnvironment      # RL environment with train/val split
├── ImprovedPPONetwork           # Neural network architecture
├── EnhancedPPOAgent             # Full PPO implementation
└── Constants                    # Hyperparameters
```

## Constants & Hyperparameters

```python
# Network Architecture
FLOW_FEATURE_DIM = 81    # Input features (CICFlowMeter)
ACTION_DIM = 2           # Normal (0), DDoS (1)
HIDDEN_DIM = 256         # Hidden layer size

# PPO Training
LEARNING_RATE = 3e-4     # Adam optimizer LR
GAMMA = 0.99             # Discount factor
LAMBDA = 0.95            # GAE lambda
EPSILON = 0.2            # PPO clip range
BATCH_SIZE = 512         # Not used (on-policy)
UPDATE_EPOCHS = 10       # PPO epochs per update
ENTROPY_COEF = 0.02      # Entropy bonus coefficient
VALUE_COEF = 0.5         # Value loss coefficient
MAX_GRAD_NORM = 0.5      # Gradient clipping

# EWMA Adaptive Thresholds
SHORT_SPAN = 10          # Short EWMA window
LONG_SPAN = 100          # Long EWMA window
VAR_SPAN = 10            # Volatility window
THRESHOLD_MULTIPLIER = 0.8

# Score Weights
VOLUME_WEIGHT = 0.35     # Volume score weight
TEMPORAL_WEIGHT = 0.35   # Temporal score weight
ENTROPY_WEIGHT = 0.30    # Entropy score weight

# Early Stopping
EARLY_STOP_PATIENCE = 50
EARLY_STOP_WARMUP = 20
EARLY_STOP_THRESHOLD = 0.01
EARLY_STOP_MIN_IMPROVEMENT = 0.01
EARLY_STOP_LOOKBACK_WINDOW = 10
USE_VALIDATION_FOR_EARLY_STOP = True
VAL_CHECK_INTERVAL = 5
EARLY_STOP_METRIC = 'combined'
```

## AdaptiveThresholdDetector

Uses EWMA (Exponentially Weighted Moving Average) to dynamically detect anomalies:

```python
class AdaptiveThresholdDetector:
    """
    Detects anomalies by comparing short-term EWMA vs long-term EWMA.

    Three score types:
    ├── Volume Score:   L2 norm of first 20 features / 20
    ├── Temporal Score: Std of features 20-50 / 10
    └── Entropy Score:  Mean abs of features 50+ / 5

    Combined Score = volume*0.35 + temporal*0.35 + entropy*0.30

    Anomaly Detection:
    ├── short_ewma = EWMA(span=10) of score history
    ├── long_ewma = EWMA(span=100) of score history
    ├── ewma_diff = short_ewma - long_ewma
    ├── rel_diff = ewma_diff / (|long_ewma| + 1e-6)
    ├── ewma_std = sqrt(EWMA of squared deviations)
    ├── dynamic_thresh = 0.8 * ewma_std / (|long_ewma| + 1e-6)
    └── anomaly = |rel_diff| > dynamic_thresh

    Persistence Check:
    └── DDoS confirmed if ≥6 of last 10 samples flagged as anomaly
    """
```

### Update Flow

```
update_scores(volume, temporal, entropy)
│
├── combined = volume*0.35 + temporal*0.35 + entropy*0.30
├── Append all scores to history deques (maxlen=5000)
│
├── For each score type:
│   └── _calculate_anomaly(history) → (is_anomaly, threshold, short_ewma, long_ewma)
│
├── Use combined anomaly as primary decision
├── Append to recent_ddos_flags deque (maxlen=10)
│
└── Return: (persistent_ddos, vol_anomaly, temp_anomaly, ent_anomaly, comb_anomaly)
```

## EnhancedDDoSEnvironment

RL environment that wraps the training data:

```python
class EnhancedDDoSEnvironment:
    """
    RL Environment for DDoS detection training.

    Data format: [81 flow features + volume_score + temporal_score + entropy_score]
                 = 84 columns total

    Train/Validation Split:
    ├── train_flow = flow_features[:split_idx]  # 80% of data
    ├── train_scores = anomaly_scores[:split_idx]
    ├── val_flow = flow_features[split_idx:]    # 20% of data
    └── val_scores = anomaly_scores[split_idx:]

    State: 81 flow features only (anomaly scores used for reward only)
    Action: 0 (Normal) or 1 (DDoS)

    Reward Structure:
    ├── True Positive (action=1, label=1):    +3.0
    ├── True Negative (action=0, label=0):    +3.0
    ├── False Positive (action=1, label=0):   -3.0
    └── False Negative (action=0, label=1):   -4.0  (most severe)

    Episode Bonus:
    ├── DDoS ratio 20-35%: +0.3 (sweet spot)
    ├── DDoS ratio 15-50%: +0.1
    ├── DDoS ratio >70%:   -0.9 (over-detection)
    ├── DDoS ratio <10%:   -0.8 (under-detection)
    └── DDoS ratio <5%:    -1.2 (severe under-detection)
    """
```

### Step Flow

```
step(action)
│
├── current_state = flow_features[current_step]  # 81 dims
├── volume, temporal, entropy = anomaly_scores[current_step]
│
├── label, vol_anom, temp_anom, ent_anom, comb_anom = 
│   threshold_detector.update_scores(volume, temporal, entropy)
│
├── reward = _calculate_reward(action, label)
├── _update_confusion_metrics(action, label)
│
├── current_step += 1
├── done = current_step >= len(flow_features) - 1
├── next_state = flow_features[current_step] or zeros
│
└── return next_state, reward, done, info
```

## ImprovedPPONetwork

Neural network architecture:

```
Input: 81 features
  │
  ▼
┌─────────────────────────────────────┐
│         Shared Layers               │
│                                     │
│  Linear(81, 256)                    │
│  LayerNorm(256)                     │
│  ReLU()                             │
│  Dropout(0.2)                       │
│                                     │
│  Linear(256, 256)                   │
│  LayerNorm(256)                     │
│  ReLU()                             │
│  Dropout(0.2)                       │
└──────────────┬──────────────────────┘
               │
       ┌───────┴───────┐
       ▼               ▼
┌──────────────┐ ┌──────────────┐
│ Policy Head   │ │  Value Head   │
│              │ │              │
│ Linear(256,  │ │ Linear(256,  │
│   128)       │ │   128)       │
│ ReLU()       │ │ ReLU()       │
│ Linear(128,  │ │ Linear(128,  │
│   2)         │ │   1)         │
│              │ │              │
│ → Action     │ │ → State      │
│   logits     │ │   value      │
└──────────────┘ └──────────────┘
```

### Weight Initialization

```python
def _init_weights(module):
    if isinstance(module, nn.Linear):
        orthogonal_(module.weight, gain=sqrt(2))  # Orthogonal init
        constant_(module.bias, 0)                  # Zero bias
```

## EnhancedPPOAgent

Full PPO implementation with advanced features:

### Training Loop

```
train(env, max_episodes=1000)
│
├── For each episode:
│   ├── state = env.reset()
│   │
│   ├── While not done:
│   │   ├── action, log_prob, value = get_action_and_value(state)
│   │   ├── next_state, reward, done, info = env.step(action)
│   │   ├── store_transition(state, action, reward, value, log_prob, done)
│   │   └── state = next_state
│   │
│   ├── Run validation (every VAL_CHECK_INTERVAL episodes)
│   │   └── val_reward, val_loss = run_validation(env)
│   │
│   ├── update_policy()  # PPO update on collected experience
│   │
│   ├── check_early_stopping(episode_reward, val_reward, episode, val_loss)
│   │   └── If no improvement for 50 episodes → stop + restore best model
│   │
│   └── Log progress (every 20 episodes)
│
├── Plot training results, confusion matrix, threshold evolution
│
└── Return episode rewards
```

### PPO Update

```
update_policy()
│
├── Compute GAE (Generalized Advantage Estimation):
│   └── For each step (reversed):
│       delta = reward + gamma * next_value * (1-done) - value
│       gae = delta + gamma * lambda * (1-done) * gae
│       advantage = gae
│       return = advantage + value
│
├── Normalize advantages: (adv - mean) / (std + 1e-8)
│
├── For UPDATE_EPOCHS (10) iterations:
│   ├── Forward pass: action_logits, values = policy(states)
│   ├── action_probs = softmax(action_logits)
│   ├── new_log_probs = log_prob(actions)
│   ├── entropy = entropy(action_probs)
│   │
│   ├── ratio = exp(new_log_probs - old_log_probs)
│   ├── surr1 = ratio * advantages
│   ├── surr2 = clamp(ratio, 1-epsilon, 1+epsilon) * advantages
│   ├── policy_loss = -min(surr1, surr2).mean()
│   ├── value_loss = MSE(values, returns)
│   ├── total_loss = policy_loss + 0.5*value_loss - 0.02*entropy
│   │
│   ├── Backward pass + gradient clipping (max_norm=0.5)
│   └── optimizer.step()
│
├── scheduler.step()  # LR decay: step_size=200, gamma=0.95
│
└── Clear experience buffer
```

### Prediction (Inference)

```
predict_batch(states, return_values=True)
│
├── states: numpy array of shape (N, 81)
├── states_tensor = FloatTensor(states)
│
├── action_logits, values = policy(states_tensor)
├── action_probs = softmax(action_logits)
│
└── return {
    "actions": argmax(action_probs, dim=1).numpy(),     # numpy array [0, 1, 0, ...]
    "labels": ['DDoS' if a==1 else 'Normal' ...],       # string labels
    "confidences": max(action_probs, dim=1).numpy(),    # numpy array
    "ddos_probabilities": action_probs[:, 1].numpy(),   # numpy array
    "probs": action_probs.numpy(),                      # full probability matrix
    "values": values.numpy() (if return_values),
}
```

### Model Save/Load

```
save_model(path, metadata=None)
│
└── torch.save({
    "model_state_dict": policy.state_dict(),
    "optimizer_state_dict": optimizer.state_dict(),
    "scheduler_state_dict": scheduler.state_dict(),
    "metadata": metadata,
}, path)

@staticmethod
load_model(path, map_location=None)
│
└── checkpoint = torch.load(path, map_location)
└── agent = EnhancedPPOAgent(state_dim, action_dim)
└── agent.policy.load_state_dict(checkpoint["model_state_dict"])
└── return agent
```

## Visualization

The module generates three training visualization files:

| File | Content |
|------|---------|
| `training_results.png` | Episode rewards, policy loss, value loss, entropy, confusion matrix, threshold evolution |
| `final_confusion_matrix.png` | Final validation confusion matrix heatmap |
| `threshold_evolution.png` | Adaptive threshold plots for all 4 score types |
