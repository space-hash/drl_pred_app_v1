#!/usr/bin/env python3
"""
DRL DDoS Detection - Model Comparison Utility

Compare multiple models side by side with detailed metrics.

Usage:
    python compare_models.py models/final_drl.pt models/final_drl1.pt models/final_drl11.pt
    python compare_models.py models/*.pt --data data/test.csv
    python compare_models.py models/*.pt --auto-generate --n-samples 5000
    python compare_models.py models/*.pt --benchmark --output comparison.json
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import torch

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from detection_module.detection import EnhancedPPOAgent, FLOW_FEATURE_DIM

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("ModelComparison")


def load_test_data(csv_path: str = None, n_synthetic: int = 5000) -> np.ndarray:
    """Load or generate test data."""
    if csv_path:
        import pandas as pd
        df = pd.read_csv(csv_path)
        drop_cols = [c for c in ["Flow ID", "Timestamp", "Fwd Header Length.1", "Label"] if c in df.columns]
        df = df.drop(columns=drop_cols)
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(df.mean(), inplace=True)
        if df.shape[1] > FLOW_FEATURE_DIM:
            df = df.iloc[:, :FLOW_FEATURE_DIM]
        return df.values.astype(np.float32)
    else:
        np.random.seed(42)
        n_normal = int(n_synthetic * 0.7)
        n_ddos = n_synthetic - n_normal
        normal = np.random.normal(0, 1, (n_normal, FLOW_FEATURE_DIM))
        ddos = np.random.normal(2, 3, (n_ddos, FLOW_FEATURE_DIM))
        ddos[:, 0] = np.random.exponential(5, n_ddos)
        ddos[:, 1] = np.random.exponential(10, n_ddos)
        data = np.vstack([normal, ddos])
        np.random.shuffle(data)
        return data.astype(np.float32)


def compare_model(model_path: str, test_data: np.ndarray, benchmark: bool = False) -> dict:
    """Compare a single model."""
    p = Path(model_path)
    result = {"model": p.name, "path": str(p)}

    try:
        start = time.time()
        agent = EnhancedPPOAgent.load_model(str(p), map_location="cpu")
        load_time = time.time() - start
        result["load_time_ms"] = round(load_time * 1000, 2)
        result["loaded"] = True
    except Exception as e:
        result["loaded"] = False
        result["error"] = str(e)
        return result

    try:
        checkpoint = torch.load(str(p), map_location="cpu", weights_only=False)
        meta = checkpoint.get("metadata", {})
        result["metadata"] = {
            "version": meta.get("version", "N/A"),
            "created": meta.get("created_at", "Unknown")[:19],
            "epochs": meta.get("epochs", "N/A"),
            "best_reward": meta.get("best_reward", "N/A"),
            "training_time": meta.get("training_time_seconds", "N/A"),
        }
    except Exception:
        result["metadata"] = {}

    result["size_mb"] = round(p.stat().st_size / (1024 * 1024), 2)

    try:
        batch_start = time.perf_counter()
        predictions = agent.predict_batch(test_data)
        batch_time = time.perf_counter() - batch_start

        result["inference"] = {
            "batch_time_ms": round(batch_time * 1000, 2),
            "samples_per_sec": round(len(test_data) / batch_time, 0),
            "ddos_predicted": int(np.sum(predictions["actions"] == 1)),
            "normal_predicted": int(np.sum(predictions["actions"] == 0)),
            "ddos_ratio": round(float(np.mean(predictions["actions"] == 1)), 4),
            "avg_confidence": round(float(np.mean(predictions["confidences"])), 4),
            "avg_ddos_prob": round(float(np.mean(predictions["ddos_probabilities"])), 4),
        }
    except Exception as e:
        result["inference"] = {"error": str(e)}

    if benchmark:
        times = []
        for _ in range(5):
            start = time.perf_counter()
            agent.predict_batch(test_data)
            times.append(time.perf_counter() - start)

        result["benchmark"] = {
            "avg_ms": round(np.mean(times) * 1000, 2),
            "min_ms": round(np.min(times) * 1000, 2),
            "max_ms": round(np.max(times) * 1000, 2),
            "std_ms": round(np.std(times) * 1000, 2),
        }

    return result


def print_comparison_table(results: list) -> None:
    """Print a formatted comparison table."""
    print("\n" + "=" * 120)
    print("  DRL DDoS Detection - Model Comparison")
    print("=" * 120)

    print(f"\n{'Model':<22} {'Size':<8} {'Load':<8} {'DDoS%':<8} {'Confidence':<12} {'Samples/s':<12} {'Epochs':<8} {'Reward':<10}")
    print("-" * 120)

    for r in results:
        if not r.get("loaded"):
            print(f"{r['model']:<22} {'ERROR':<8} {r.get('error', 'N/A'):<60}")
            continue

        meta = r.get("metadata", {})
        inf = r.get("inference", {})

        reward = meta.get("best_reward", "N/A")
        if isinstance(reward, (int, float)):
            reward = f"{reward:.1f}"

        epochs = meta.get("epochs", "N/A")
        confidence = inf.get("avg_confidence", "N/A")
        if isinstance(confidence, float):
            confidence = f"{confidence:.4f}"

        sps = inf.get("samples_per_sec", "N/A")
        if isinstance(sps, (int, float)):
            sps = f"{sps:.0f}"

        ddos_pct = inf.get("ddos_ratio", "N/A")
        if isinstance(ddos_pct, float):
            ddos_pct = f"{ddos_pct:.2%}"

        print(
            f"{r['model']:<22} {r['size_mb']:<8} {r['load_time_ms']:<8} {ddos_pct:<8} "
            f"{confidence:<12} {sps:<12} {str(epochs):<8} {str(reward):<10}"
        )

    if any(r.get("benchmark") for r in results):
        print(f"\n{'Model':<22} {'Avg (ms)':<10} {'Min (ms)':<10} {'Max (ms)':<10} {'Std (ms)':<10}")
        print("-" * 70)
        for r in results:
            if r.get("benchmark"):
                b = r["benchmark"]
                print(f"{r['model']:<22} {b['avg_ms']:<10} {b['min_ms']:<10} {b['max_ms']:<10} {b['std_ms']:<10}")

    print("\n" + "=" * 120)


def main():
    parser = argparse.ArgumentParser(description="DRL DDoS Detection - Model Comparison")
    parser.add_argument("models", nargs="+", help="Model files to compare (glob patterns work)")
    parser.add_argument("--data", type=str, help="Test data CSV file")
    parser.add_argument("--auto-generate", action="store_true", help="Generate synthetic test data")
    parser.add_argument("--n-samples", type=int, default=5000, help="Number of synthetic samples")
    parser.add_argument("--benchmark", action="store_true", help="Run detailed benchmarks")
    parser.add_argument("--output", type=str, help="Save results to JSON file")

    args = parser.parse_args()

    model_files = []
    for pattern in args.models:
        model_files.extend(sorted(Path(".").glob(pattern)))

    model_files = [f for f in model_files if f.suffix == ".pt"]

    if not model_files:
        logger.error("No model files found")
        sys.exit(1)

    logger.info(f"Found {len(model_files)} models to compare")

    test_data = load_test_data(args.data, args.n_samples)
    logger.info(f"Test data: {len(test_data)} samples, {test_data.shape[1]} features")

    results = []
    for mf in model_files:
        logger.info(f"Evaluating: {mf.name}")
        result = compare_model(str(mf), test_data, args.benchmark)
        results.append(result)

    print_comparison_table(results)

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        output = {
            "comparison_date": datetime.now().isoformat(),
            "test_samples": len(test_data),
            "models": results,
        }
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2, default=str)
        logger.info(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()
