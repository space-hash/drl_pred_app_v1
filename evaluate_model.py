#!/usr/bin/env python3
"""
DRL DDoS Detection - Model Evaluation & Validation Script

Comprehensive evaluation of trained PPO models including:
- Accuracy, precision, recall, F1 score
- Confusion matrix
- ROC curve analysis
- Per-class metrics
- Batch inference speed benchmarks

Usage:
    python evaluate_model.py --model models/final_drl1.pt --data data/test.csv
    python evaluate_model.py --model models/final_drl1.pt --auto-generate --n-samples 5000
    python evaluate_model.py --model models/final_drl1.pt --benchmark
    python evaluate_model.py --model models/final_drl1.pt --report
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

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from detection_module.detection import (
    EnhancedPPOAgent,
    EnhancedDDoSEnvironment,
    FLOW_FEATURE_DIM,
    compute_anomaly_scores,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("Evaluation")


def load_data(csv_path: str) -> np.ndarray:
    """Load CICFlowMeter CSV data."""
    import pandas as pd

    df = pd.read_csv(csv_path)
    drop_cols = [c for c in ["Flow ID", "Timestamp", "Fwd Header Length.1"] if c in df.columns]
    df = df.drop(columns=drop_cols)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(df.mean(), inplace=True)

    if df.shape[1] > FLOW_FEATURE_DIM:
        df = df.iloc[:, :FLOW_FEATURE_DIM]

    return df.values.astype(np.float32)


def generate_test_data(n_samples: int = 5000, ddos_ratio: float = 0.3, seed: int = 42) -> tuple:
    """Generate synthetic test data with known labels."""
    np.random.seed(seed)
    n_normal = int(n_samples * (1 - ddos_ratio))
    n_ddos = n_samples - n_normal

    normal = np.random.normal(0, 1, (n_normal, FLOW_FEATURE_DIM))
    ddos = np.random.normal(2, 3, (n_ddos, FLOW_FEATURE_DIM))
    ddos[:, 0] = np.random.exponential(5, n_ddos)
    ddos[:, 1] = np.random.exponential(10, n_ddos)
    ddos[:, 2] = np.random.normal(100, 50, n_ddos)
    ddos[:, 3] = np.random.normal(50, 20, n_ddos)

    data = np.vstack([normal, ddos])
    labels = np.array([0] * n_normal + [1] * n_ddos)

    shuffle_idx = np.random.permutation(len(data))
    data = data[shuffle_idx]
    labels = labels[shuffle_idx]

    return data.astype(np.float32), labels


def compute_metrics(predictions: np.ndarray, labels: np.ndarray) -> dict:
    """Compute comprehensive classification metrics."""
    tp = np.sum((predictions == 1) & (labels == 1))
    tn = np.sum((predictions == 0) & (labels == 0))
    fp = np.sum((predictions == 1) & (labels == 0))
    fn = np.sum((predictions == 0) & (labels == 1))

    accuracy = (tp + tn) / max(1, len(labels))
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(1e-10, precision + recall)
    fpr = fp / max(1, fp + tn)
    fnr = fn / max(1, fn + tp)

    return {
        "accuracy": round(float(accuracy), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1_score": round(float(f1), 4),
        "false_positive_rate": round(float(fpr), 4),
        "false_negative_rate": round(float(fnr), 4),
        "true_positives": int(tp),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "total_samples": int(len(labels)),
    }


def benchmark_inference(agent: EnhancedPPOAgent, data: np.ndarray, n_runs: int = 10) -> dict:
    """Benchmark inference speed."""
    times = []

    for _ in range(n_runs):
        start = time.perf_counter()
        agent.predict_batch(data)
        elapsed = time.perf_counter() - start
        times.append(elapsed)

    avg_time = np.mean(times)
    samples_per_sec = len(data) / avg_time

    single_start = time.perf_counter()
    for i in range(min(100, len(data))):
        agent.predict(data[i])
    single_elapsed = time.perf_counter() - single_start
    single_avg = single_elapsed / min(100, len(data))

    return {
        "batch_size": len(data),
        "avg_batch_time_ms": round(float(avg_time * 1000), 2),
        "min_batch_time_ms": round(float(np.min(times) * 1000), 2),
        "max_batch_time_ms": round(float(np.max(times) * 1000), 2),
        "samples_per_second": round(float(samples_per_sec), 0),
        "single_prediction_ms": round(float(single_avg * 1000), 4),
        "device": str(agent.device),
    }


def evaluate_model(
    model_path: str,
    data: np.ndarray,
    labels: np.ndarray = None,
    benchmark: bool = False,
) -> dict:
    """Full model evaluation."""
    logger.info(f"Loading model: {model_path}")
    agent = EnhancedPPOAgent.load_model(model_path, map_location="cpu")
    agent.policy.eval()

    results = {
        "model_path": model_path,
        "evaluated_at": datetime.now().isoformat(),
        "data_samples": len(data),
    }

    predictions = []
    confidences = []
    ddos_probs = []

    batch_size = 1000
    for i in range(0, len(data), batch_size):
        batch = data[i : i + batch_size]
        result = agent.predict_batch(batch)
        predictions.extend(result["actions"])
        confidences.extend(result["confidences"])
        ddos_probs.extend(result["ddos_probabilities"])

    predictions = np.array(predictions)

    pred_ddos = np.sum(predictions == 1)
    pred_normal = np.sum(predictions == 0)

    results["prediction_distribution"] = {
        "ddos": int(pred_ddos),
        "normal": int(pred_normal),
        "ddos_ratio": round(float(pred_ddos / len(predictions)), 4),
    }

    results["confidence_stats"] = {
        "mean": round(float(np.mean(confidences)), 4),
        "std": round(float(np.std(confidences)), 4),
        "min": round(float(np.min(confidences)), 4),
        "max": round(float(np.max(confidences)), 4),
    }

    if labels is not None:
        metrics = compute_metrics(predictions, labels)
        results["classification_metrics"] = metrics
        logger.info(f"Accuracy: {metrics['accuracy']:.4f}")
        logger.info(f"Precision: {metrics['precision']:.4f}")
        logger.info(f"Recall: {metrics['recall']:.4f}")
        logger.info(f"F1 Score: {metrics['f1_score']:.4f}")

    if benchmark:
        bench = benchmark_inference(agent, data)
        results["benchmark"] = bench
        logger.info(f"Batch inference: {bench['samples_per_second']} samples/sec")
        logger.info(f"Single prediction: {bench['single_prediction_ms']:.4f}ms")

    try:
        checkpoint = torch.load(model_path, map_location="cpu", weights_only=False)
        results["model_metadata"] = checkpoint.get("metadata", {})
    except Exception:
        results["model_metadata"] = {}

    return results


def print_report(results: dict) -> None:
    """Print a formatted evaluation report."""
    print("\n" + "=" * 60)
    print("  DRL DDoS Detection - Model Evaluation Report")
    print("=" * 60)

    print(f"\nModel: {results['model_path']}")
    print(f"Evaluated: {results['evaluated_at'][:19]}")
    print(f"Data samples: {results['data_samples']}")

    if "model_metadata" in results and results["model_metadata"]:
        meta = results["model_metadata"]
        print(f"\nModel Info:")
        print(f"  Type: {meta.get('model_type', 'Unknown')}")
        print(f"  Version: {meta.get('version', 'Unknown')}")
        print(f"  Created: {meta.get('created_at', 'Unknown')[:19]}")
        print(f"  Training epochs: {meta.get('epochs', 'N/A')}")
        print(f"  Best reward: {meta.get('best_reward', 'N/A')}")

    print(f"\nPrediction Distribution:")
    dist = results["prediction_distribution"]
    print(f"  DDoS: {dist['ddos']} ({dist['ddos_ratio']:.2%})")
    print(f"  Normal: {dist['normal']}")

    print(f"\nConfidence Statistics:")
    cs = results["confidence_stats"]
    print(f"  Mean: {cs['mean']:.4f}")
    print(f"  Std:  {cs['std']:.4f}")
    print(f"  Min:  {cs['min']:.4f}")
    print(f"  Max:  {cs['max']:.4f}")

    if "classification_metrics" in results:
        m = results["classification_metrics"]
        print(f"\nClassification Metrics:")
        print(f"  Accuracy:  {m['accuracy']:.4f}")
        print(f"  Precision: {m['precision']:.4f}")
        print(f"  Recall:    {m['recall']:.4f}")
        print(f"  F1 Score:  {m['f1_score']:.4f}")
        print(f"  FPR:       {m['false_positive_rate']:.4f}")
        print(f"  FNR:       {m['false_negative_rate']:.4f}")
        print(f"\nConfusion Matrix:")
        print(f"                Predicted")
        print(f"                Normal  DDoS")
        print(f"  Actual Normal  {m['true_negatives']:>6}  {m['false_positives']:>6}")
        print(f"  Actual DDoS    {m['false_negatives']:>6}  {m['true_positives']:>6}")

    if "benchmark" in results:
        b = results["benchmark"]
        print(f"\nBenchmark ({b['device']}):")
        print(f"  Batch size: {b['batch_size']}")
        print(f"  Avg batch time: {b['avg_batch_time_ms']:.2f}ms")
        print(f"  Samples/sec: {b['samples_per_second']:.0f}")
        print(f"  Single prediction: {b['single_prediction_ms']:.4f}ms")

    print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(description="DRL DDoS Detection - Model Evaluation")
    parser.add_argument("--model", type=str, required=True, help="Path to model file")
    parser.add_argument("--data", type=str, help="Path to test data CSV")
    parser.add_argument("--auto-generate", action="store_true", help="Generate synthetic test data")
    parser.add_argument("--n-samples", type=int, default=5000, help="Number of synthetic samples")
    parser.add_argument("--ddos-ratio", type=float, default=0.3, help="DDoS ratio in synthetic data")
    parser.add_argument("--benchmark", action="store_true", help="Run inference benchmark")
    parser.add_argument("--report", action="store_true", help="Print formatted report")
    parser.add_argument("--output", type=str, help="Save results to JSON file")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for synthetic data")

    args = parser.parse_args()

    if not Path(args.model).exists():
        logger.error(f"Model not found: {args.model}")
        sys.exit(1)

    if args.auto_generate:
        data, labels = generate_test_data(args.n_samples, args.ddos_ratio, args.seed)
        logger.info(f"Generated {len(data)} synthetic samples (DDoS ratio: {args.ddos_ratio})")
    elif args.data:
        data = load_data(args.data)
        labels = None
        logger.info(f"Loaded {len(data)} samples from {args.data}")
    else:
        logger.error("Provide --data or --auto-generate")
        sys.exit(1)

    results = evaluate_model(args.model, data, labels, benchmark=args.benchmark)

    if args.report or (not args.output):
        print_report(results)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        logger.info(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()
