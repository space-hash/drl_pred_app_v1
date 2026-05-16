#!/usr/bin/env python3
"""
DRL DDoS Detection - Model Training Script
Trains a PPO agent on CICFlowMeter-style network flow data.

Usage:
    python train.py --data path/to/data.csv --epochs 500 --output models/my_model.pt
    python train.py --data path/to/data.csv --auto-generate
    python train.py --list-models
    python train.py --compare models/model1.pt models/model2.pt
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import torch

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from detection_module.detection import (
    EnhancedPPOAgent,
    EnhancedDDoSEnvironment,
    FLOW_FEATURE_DIM,
    ACTION_DIM,
    HIDDEN_DIM,
    LEARNING_RATE,
    MAX_EPISODES,
    BATCH_SIZE,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("Training")


def load_cic_data(csv_path: str) -> np.ndarray:
    """Load and preprocess CICFlowMeter CSV data for training.

    Expects CSV with 81 flow features + optional label column.
    Returns numpy array of shape (N, 81) for features.
    """
    import pandas as pd

    df = pd.read_csv(csv_path)
    logger.info(f"Loaded {len(df)} samples from {csv_path}")
    logger.info(f"Columns: {len(df.columns)}")

    drop_cols = [c for c in ["Flow ID", "Timestamp", "Fwd Header Length.1", "Label"] if c in df.columns]
    df = df.drop(columns=drop_cols)

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(df.mean(), inplace=True)

    if df.shape[1] != FLOW_FEATURE_DIM:
        logger.warning(f"Expected {FLOW_FEATURE_DIM} features, got {df.shape[1]}")
        if df.shape[1] > FLOW_FEATURE_DIM:
            df = df.iloc[:, :FLOW_FEATURE_DIM]
        else:
            raise ValueError(f"Insufficient features: {df.shape[1]} < {FLOW_FEATURE_DIM}")

    return df.values.astype(np.float32)


def generate_synthetic_data(n_samples: int = 10000, ddos_ratio: float = 0.3) -> np.ndarray:
    """Generate synthetic CICFlowMeter-style data for testing/training.

    Creates realistic network flow features with distinguishable DDoS patterns.
    """
    np.random.seed(42)
    n_normal = int(n_samples * (1 - ddos_ratio))
    n_ddos = n_samples - n_normal

    normal_features = np.random.normal(0, 1, (n_normal, FLOW_FEATURE_DIM))
    ddos_features = np.random.normal(2, 3, (n_ddos, FLOW_FEATURE_DIM))

    ddos_features[:, 0] = np.random.exponential(5, n_ddos)
    ddos_features[:, 1] = np.random.exponential(10, n_ddos)
    ddos_features[:, 2] = np.random.normal(100, 50, n_ddos)
    ddos_features[:, 3] = np.random.normal(50, 20, n_ddos)

    data = np.vstack([normal_features, ddos_features])
    np.random.shuffle(data)

    logger.info(f"Generated {n_samples} synthetic samples ({n_normal} normal, {n_ddos} DDoS)")
    return data.astype(np.float32)


def compute_anomaly_scores(features: np.ndarray) -> np.ndarray:
    """Compute volume, temporal, and entropy scores for environment input."""
    n = len(features)

    volume_score = np.linalg.norm(features[:, :20], axis=1) / 20.0
    temporal_score = np.std(features[:, 20:50], axis=1) / 10.0
    entropy_score = np.mean(np.abs(features[:, 50:]), axis=1) / 5.0

    scores = np.column_stack([volume_score, temporal_score, entropy_score])
    return scores.astype(np.float32)


def prepare_training_data(data: np.ndarray) -> np.ndarray:
    """Combine features with anomaly scores for the RL environment."""
    scores = compute_anomaly_scores(data)
    return np.hstack([data, scores])


def train_model(
    data: np.ndarray,
    output_path: str,
    epochs: int = MAX_EPISODES,
    hidden_dim: int = HIDDEN_DIM,
    learning_rate: float = LEARNING_RATE,
    validation_split: float = 0.2,
    device: str = "auto",
) -> dict:
    """Train a PPO model on the provided data."""
    logger.info(f"Training with {len(data)} samples for {epochs} episodes")
    logger.info(f"Device: {device}, Hidden dim: {hidden_dim}, LR: {learning_rate}")

    env_data = prepare_training_data(data)
    env = EnhancedDDoSEnvironment(env_data, validation_split=validation_split)

    agent = EnhancedPPOAgent(
        state_dim=FLOW_FEATURE_DIM,
        action_dim=ACTION_DIM,
        hidden_dim=hidden_dim,
        learning_rate=learning_rate,
    )

    if device != "auto":
        agent.device = torch.device(device)
        agent.policy = agent.policy.to(agent.device)

    start_time = time.time()
    metrics = agent.train(env, max_episodes=epochs)
    training_time = time.time() - start_time

    metadata = {
        "model_type": "PPO",
        "version": "2.0",
        "created_at": datetime.now().isoformat(),
        "training_time_seconds": round(training_time, 2),
        "epochs": epochs,
        "samples_used": len(data),
        "validation_split": validation_split,
        "hidden_dim": hidden_dim,
        "learning_rate": learning_rate,
        "flow_feature_dim": FLOW_FEATURE_DIM,
        "action_dim": ACTION_DIM,
        "final_reward": metrics["episode_rewards"][-1] if metrics["episode_rewards"] else 0,
        "best_reward": agent.best_reward,
        "platform": sys.platform,
        "python_version": sys.version,
        "pytorch_version": torch.__version__,
    }

    agent.save_model(output_path, metadata=metadata)
    logger.info(f"Model saved to {output_path}")
    logger.info(f"Training completed in {training_time:.1f}s")
    logger.info(f"Best reward: {agent.best_reward:.2f}")

    return metadata


def evaluate_model(model_path: str, data: np.ndarray) -> dict:
    """Evaluate a trained model and return metrics."""
    logger.info(f"Evaluating model: {model_path}")

    agent = EnhancedPPOAgent.load_model(model_path, map_location="cpu")
    env_data = prepare_training_data(data)
    env = EnhancedDDoSEnvironment(env_data, validation_split=0.0)

    all_predictions = []
    all_actions = []

    for i in range(len(data)):
        state = data[i]
        result = agent.predict(state)
        all_predictions.append(result)
        all_actions.append(result["action"])

    actions = np.array(all_actions)
    ddos_count = np.sum(actions == 1)
    normal_count = np.sum(actions == 0)

    metrics = {
        "total_samples": len(data),
        "ddos_predicted": int(ddos_count),
        "normal_predicted": int(normal_count),
        "ddos_ratio": round(float(ddos_count / len(data)), 4),
        "avg_confidence": round(float(np.mean([p["confidence"] for p in all_predictions])), 4),
        "avg_ddos_probability": round(float(np.mean([p["ddos_probability"] for p in all_predictions])), 4),
    }

    logger.info(f"DDoS: {ddos_count}, Normal: {normal_count}")
    logger.info(f"DDoS ratio: {metrics['ddos_ratio']:.2%}")
    logger.info(f"Avg confidence: {metrics['avg_confidence']:.4f}")

    return metrics


def list_models(models_dir: str) -> None:
    """List all models in the directory with metadata."""
    models_path = Path(models_dir)
    if not models_path.exists():
        logger.error(f"Models directory not found: {models_dir}")
        return

    model_files = sorted(models_path.glob("*.pt"))
    if not model_files:
        logger.info("No models found")
        return

    print(f"\n{'Model':<25} {'Size':<12} {'Created':<22} {'Epochs':<8} {'Best Reward':<12}")
    print("-" * 85)

    for mf in model_files:
        size = mf.stat().st_size
        size_str = f"{size / 1024:.1f} KB"

        try:
            checkpoint = torch.load(str(mf), map_location="cpu", weights_only=False)
            metadata = checkpoint.get("metadata", {})
            created = metadata.get("created_at", "Unknown")[:19]
            epochs = metadata.get("epochs", "N/A")
            best_reward = metadata.get("best_reward", "N/A")
            if isinstance(best_reward, (int, float)):
                best_reward = f"{best_reward:.2f}"
        except Exception:
            created = "Unknown"
            epochs = "N/A"
            best_reward = "N/A"

        print(f"{mf.name:<25} {size_str:<12} {created:<22} {str(epochs):<8} {str(best_reward):<12}")

    print()


def compare_models(model_paths: list) -> None:
    """Compare multiple models side by side."""
    print(f"\n{'Model':<25} {'Size':<12} {'Created':<22} {'Epochs':<8} {'Best Reward':<12} {'LR':<10}")
    print("-" * 95)

    for path in model_paths:
        p = Path(path)
        if not p.exists():
            print(f"{p.name:<25} NOT FOUND")
            continue

        size = p.stat().st_size
        size_str = f"{size / 1024:.1f} KB"

        try:
            checkpoint = torch.load(str(p), map_location="cpu", weights_only=False)
            metadata = checkpoint.get("metadata", {})
            created = metadata.get("created_at", "Unknown")[:19]
            epochs = metadata.get("epochs", "N/A")
            best_reward = metadata.get("best_reward", "N/A")
            lr = metadata.get("learning_rate", "N/A")
            if isinstance(best_reward, (int, float)):
                best_reward = f"{best_reward:.2f}"
            if isinstance(lr, float):
                lr = f"{lr:.2e}"
        except Exception:
            created = "Unknown"
            epochs = "N/A"
            best_reward = "N/A"
            lr = "N/A"

        print(f"{p.name:<25} {size_str:<12} {created:<22} {str(epochs):<8} {str(best_reward):<12} {str(lr):<10}")

    print()


def main():
    parser = argparse.ArgumentParser(description="DRL DDoS Detection - Model Training")
    parser.add_argument("--data", type=str, help="Path to training data CSV")
    parser.add_argument("--output", type=str, default="detection_module/trained_models/trained_model.pt", help="Output model path")
    parser.add_argument("--epochs", type=int, default=MAX_EPISODES, help="Number of training episodes")
    parser.add_argument("--hidden-dim", type=int, default=HIDDEN_DIM, help="Hidden layer dimension")
    parser.add_argument("--lr", type=float, default=LEARNING_RATE, help="Learning rate")
    parser.add_argument("--validation-split", type=float, default=0.2, help="Validation split ratio")
    parser.add_argument("--device", type=str, default="auto", help="Device: cpu, cuda, or auto")
    parser.add_argument("--auto-generate", action="store_true", help="Generate synthetic data for testing")
    parser.add_argument("--n-samples", type=int, default=10000, help="Number of synthetic samples to generate")
    parser.add_argument("--evaluate", type=str, help="Evaluate a model on given data CSV")
    parser.add_argument("--list-models", type=str, default="detection_module/trained_models", help="List models in directory")
    parser.add_argument("--compare", nargs="+", help="Compare multiple models")

    args = parser.parse_args()

    if args.compare:
        compare_models(args.compare)
        return

    if args.list_models:
        list_models(args.list_models)
        return

    if args.evaluate:
        if not args.data:
            logger.error("--data is required for evaluation")
            sys.exit(1)
        data = load_cic_data(args.data)
        metrics = evaluate_model(args.evaluate, data)
        print(json.dumps(metrics, indent=2))
        return

    if not args.data and not args.auto_generate:
        parser.print_help()
        print("\nError: Provide --data or use --auto-generate")
        sys.exit(1)

    if args.auto_generate:
        data = generate_synthetic_data(args.n_samples)
    else:
        data = load_cic_data(args.data)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)

    metadata = train_model(
        data=data,
        output_path=args.output,
        epochs=args.epochs,
        hidden_dim=args.hidden_dim,
        learning_rate=args.lr,
        validation_split=args.validation_split,
        device=args.device,
    )

    print("\nTraining Summary:")
    print(json.dumps(metadata, indent=2, default=str))


if __name__ == "__main__":
    main()
