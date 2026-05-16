#!/usr/bin/env python3
"""
DRL DDoS Detection - Sample Data Generator

Generates realistic CICFlowMeter-style synthetic data for testing and training.
Creates CSV files compatible with the feature extraction pipeline.

Usage:
    python generate_sample_data.py --output data/sample_train.csv --n 10000 --ddos-ratio 0.3
    python generate_sample_data.py --output data/sample_test.csv --n 5000 --ddos-ratio 0.5 --seed 123
    python generate_sample_data.py --output data/ --split train test --train-ratio 0.8
"""

import argparse
import os
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent

CIC_COLUMNS = [
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Dst Port",
    "Protocol",
    "Timestamp",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Bwd Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

FEATURE_COLUMNS = [c for c in CIC_COLUMNS if c not in ["Flow ID", "Timestamp", "Fwd Header Length.1"]]


def generate_ip(random_state: np.random.RandomState) -> str:
    """Generate a random IP address."""
    return f"{random_state.randint(1, 255)}.{random_state.randint(0, 255)}.{random_state.randint(0, 255)}.{random_state.randint(1, 255)}"


def generate_normal_traffic(n: int, rng: np.random.RandomState) -> pd.DataFrame:
    """Generate normal network traffic features."""
    data = {
        "Flow ID": [f"Normal-{i}" for i in range(n)],
        "Src IP": [generate_ip(rng) for _ in range(n)],
        "Src Port": rng.randint(1024, 65535, n),
        "Dst IP": [generate_ip(rng) for _ in range(n)],
        "Dst Port": rng.choice([80, 443, 8080, 8443, 22, 53, 25, 110, 143, 993, 995], n),
        "Protocol": rng.choice([6, 17], n, p=[0.8, 0.2]),
        "Timestamp": [f"2024-01-{rng.randint(1,29):02d} {rng.randint(0,24):02d}:{rng.randint(0,60):02d}:{rng.randint(0,60):02d}" for _ in range(n)],
        "Flow Duration": rng.exponential(1e6, n),
        "Total Fwd Packets": rng.poisson(10, n),
        "Total Bwd Packets": rng.poisson(8, n),
        "Total Length of Fwd Packets": rng.normal(500, 200, n).clip(0),
        "Total Length of Bwd Packets": rng.normal(400, 150, n).clip(0),
        "Fwd Packet Length Max": rng.normal(100, 30, n).clip(0),
        "Fwd Packet Length Min": rng.normal(40, 15, n).clip(0),
        "Fwd Packet Length Mean": rng.normal(70, 20, n).clip(0),
        "Fwd Packet Length Std": rng.normal(20, 10, n).clip(0),
        "Bwd Packet Length Max": rng.normal(90, 25, n).clip(0),
        "Bwd Packet Length Min": rng.normal(35, 12, n).clip(0),
        "Bwd Packet Length Mean": rng.normal(60, 18, n).clip(0),
        "Bwd Packet Length Std": rng.normal(18, 8, n).clip(0),
        "Flow Bytes/s": rng.normal(5000, 2000, n).clip(0),
        "Flow Packets/s": rng.normal(50, 20, n).clip(0),
        "Flow IAT Mean": rng.exponential(1e5, n),
        "Flow IAT Std": rng.exponential(5e4, n),
        "Flow IAT Max": rng.exponential(5e5, n),
        "Flow IAT Min": rng.exponential(1e3, n),
        "Fwd IAT Total": rng.exponential(2e5, n),
        "Fwd IAT Mean": rng.exponential(1e5, n),
        "Fwd IAT Std": rng.exponential(5e4, n),
        "Fwd IAT Max": rng.exponential(3e5, n),
        "Fwd IAT Min": rng.exponential(1e3, n),
        "Bwd IAT Total": rng.exponential(2e5, n),
        "Bwd IAT Mean": rng.exponential(1e5, n),
        "Bwd IAT Std": rng.exponential(5e4, n),
        "Bwd IAT Max": rng.exponential(3e5, n),
        "Bwd IAT Min": rng.exponential(1e3, n),
        "Fwd PSH Flags": rng.poisson(1, n),
        "Bwd PSH Flags": rng.poisson(1, n),
        "Fwd URG Flags": np.zeros(n, dtype=int),
        "Bwd URG Flags": np.zeros(n, dtype=int),
        "Fwd Header Length": rng.normal(40, 10, n).clip(20),
        "Bwd Header Length": rng.normal(40, 10, n).clip(20),
        "Fwd Packets/s": rng.normal(30, 15, n).clip(0),
        "Bwd Packets/s": rng.normal(25, 12, n).clip(0),
        "Min Packet Length": rng.normal(40, 15, n).clip(0),
        "Max Packet Length": rng.normal(120, 40, n).clip(0),
        "Packet Length Mean": rng.normal(80, 25, n).clip(0),
        "Packet Length Std": rng.normal(30, 12, n).clip(0),
        "Packet Length Variance": rng.normal(900, 400, n).clip(0),
        "FIN Flag Count": rng.poisson(2, n),
        "SYN Flag Count": rng.poisson(3, n),
        "RST Flag Count": rng.poisson(1, n),
        "PSH Flag Count": rng.poisson(2, n),
        "ACK Flag Count": rng.poisson(5, n),
        "URG Flag Count": np.zeros(n, dtype=int),
        "CWE Flag Count": np.zeros(n, dtype=int),
        "ECE Flag Count": rng.poisson(1, n),
        "Down/Up Ratio": rng.uniform(0.5, 1.5, n),
        "Average Packet Size": rng.normal(80, 25, n).clip(0),
        "Avg Fwd Segment Size": rng.normal(70, 20, n).clip(0),
        "Avg Bwd Segment Size": rng.normal(60, 18, n).clip(0),
        "Fwd Header Length.1": rng.normal(40, 10, n).clip(20),
        "Fwd Avg Bytes/Bulk": rng.normal(500, 200, n).clip(0),
        "Fwd Avg Packets/Bulk": rng.normal(5, 2, n).clip(0),
        "Fwd Avg Bulk Rate": rng.normal(1000, 500, n).clip(0),
        "Bwd Avg Bytes/Bulk": rng.normal(400, 150, n).clip(0),
        "Bwd Avg Packets/Bulk": rng.normal(4, 2, n).clip(0),
        "Bwd Avg Bulk Rate": rng.normal(800, 400, n).clip(0),
        "Subflow Fwd Packets": rng.poisson(8, n),
        "Subflow Fwd Bytes": rng.normal(400, 150, n).clip(0),
        "Subflow Bwd Packets": rng.poisson(6, n),
        "Subflow Bwd Bytes": rng.normal(300, 120, n).clip(0),
        "Init_Win_bytes_forward": rng.choice([0, 29200, 65535], n),
        "Init_Win_bytes_backward": rng.choice([0, 29200, 65535], n),
        "act_data_pkt_fwd": rng.poisson(5, n),
        "min_seg_size_forward": rng.normal(40, 10, n).clip(20),
        "Active Mean": rng.exponential(1e5, n),
        "Active Std": rng.exponential(5e4, n),
        "Active Max": rng.exponential(3e5, n),
        "Active Min": rng.exponential(1e4, n),
        "Idle Mean": rng.exponential(2e5, n),
        "Idle Std": rng.exponential(1e5, n),
        "Idle Max": rng.exponential(5e5, n),
        "Idle Min": rng.exponential(5e4, n),
    }

    df = pd.DataFrame(data)
    df["Label"] = "BENIGN"
    return df


def generate_ddos_traffic(n: int, rng: np.random.RandomState) -> pd.DataFrame:
    """Generate DDoS attack traffic features."""
    target_ip = generate_ip(rng)
    target_ports = [80, 443]

    data = {
        "Flow ID": [f"DDoS-{i}" for i in range(n)],
        "Src IP": [generate_ip(rng) for _ in range(n)],
        "Src Port": rng.randint(1024, 65535, n),
        "Dst IP": [target_ip] * n,
        "Dst Port": rng.choice(target_ports, n),
        "Protocol": rng.choice([6, 17], n, p=[0.6, 0.4]),
        "Timestamp": [f"2024-01-{rng.randint(1,29):02d} {rng.randint(0,24):02d}:{rng.randint(0,60):02d}:{rng.randint(0,60):02d}" for _ in range(n)],
        "Flow Duration": rng.exponential(1e5, n),
        "Total Fwd Packets": rng.poisson(100, n),
        "Total Bwd Packets": rng.poisson(5, n),
        "Total Length of Fwd Packets": rng.normal(5000, 2000, n).clip(0),
        "Total Length of Bwd Packets": rng.normal(200, 100, n).clip(0),
        "Fwd Packet Length Max": rng.normal(150, 50, n).clip(0),
        "Fwd Packet Length Min": rng.normal(40, 15, n).clip(0),
        "Fwd Packet Length Mean": rng.normal(100, 30, n).clip(0),
        "Fwd Packet Length Std": rng.normal(40, 15, n).clip(0),
        "Bwd Packet Length Max": rng.normal(80, 20, n).clip(0),
        "Bwd Packet Length Min": rng.normal(30, 10, n).clip(0),
        "Bwd Packet Length Mean": rng.normal(50, 15, n).clip(0),
        "Bwd Packet Length Std": rng.normal(15, 8, n).clip(0),
        "Flow Bytes/s": rng.normal(50000, 20000, n).clip(0),
        "Flow Packets/s": rng.normal(500, 200, n).clip(0),
        "Flow IAT Mean": rng.exponential(1e3, n),
        "Flow IAT Std": rng.exponential(500, n),
        "Flow IAT Max": rng.exponential(1e4, n),
        "Flow IAT Min": rng.exponential(100, n),
        "Fwd IAT Total": rng.exponential(2e4, n),
        "Fwd IAT Mean": rng.exponential(1e3, n),
        "Fwd IAT Std": rng.exponential(500, n),
        "Fwd IAT Max": rng.exponential(5e3, n),
        "Fwd IAT Min": rng.exponential(100, n),
        "Bwd IAT Total": rng.exponential(1e5, n),
        "Bwd IAT Mean": rng.exponential(5e4, n),
        "Bwd IAT Std": rng.exponential(2e4, n),
        "Bwd IAT Max": rng.exponential(2e5, n),
        "Bwd IAT Min": rng.exponential(1e4, n),
        "Fwd PSH Flags": rng.poisson(5, n),
        "Bwd PSH Flags": rng.poisson(0, n),
        "Fwd URG Flags": rng.poisson(2, n),
        "Bwd URG Flags": np.zeros(n, dtype=int),
        "Fwd Header Length": rng.normal(60, 15, n).clip(20),
        "Bwd Header Length": rng.normal(20, 5, n).clip(20),
        "Fwd Packets/s": rng.normal(300, 100, n).clip(0),
        "Bwd Packets/s": rng.normal(10, 5, n).clip(0),
        "Min Packet Length": rng.normal(40, 15, n).clip(0),
        "Max Packet Length": rng.normal(150, 50, n).clip(0),
        "Packet Length Mean": rng.normal(100, 30, n).clip(0),
        "Packet Length Std": rng.normal(40, 15, n).clip(0),
        "Packet Length Variance": rng.normal(1600, 600, n).clip(0),
        "FIN Flag Count": rng.poisson(1, n),
        "SYN Flag Count": rng.poisson(10, n),
        "RST Flag Count": rng.poisson(5, n),
        "PSH Flag Count": rng.poisson(3, n),
        "ACK Flag Count": rng.poisson(2, n),
        "URG Flag Count": rng.poisson(1, n),
        "CWE Flag Count": np.zeros(n, dtype=int),
        "ECE Flag Count": np.zeros(n, dtype=int),
        "Down/Up Ratio": rng.uniform(0.01, 0.2, n),
        "Average Packet Size": rng.normal(100, 30, n).clip(0),
        "Avg Fwd Segment Size": rng.normal(100, 30, n).clip(0),
        "Avg Bwd Segment Size": rng.normal(40, 15, n).clip(0),
        "Fwd Header Length.1": rng.normal(60, 15, n).clip(20),
        "Fwd Avg Bytes/Bulk": rng.normal(2000, 800, n).clip(0),
        "Fwd Avg Packets/Bulk": rng.normal(20, 8, n).clip(0),
        "Fwd Avg Bulk Rate": rng.normal(5000, 2000, n).clip(0),
        "Bwd Avg Bytes/Bulk": rng.normal(100, 50, n).clip(0),
        "Bwd Avg Packets/Bulk": rng.normal(1, 1, n).clip(0),
        "Bwd Avg Bulk Rate": rng.normal(200, 100, n).clip(0),
        "Subflow Fwd Packets": rng.poisson(80, n),
        "Subflow Fwd Bytes": rng.normal(4000, 1500, n).clip(0),
        "Subflow Bwd Packets": rng.poisson(3, n),
        "Subflow Bwd Bytes": rng.normal(150, 80, n).clip(0),
        "Init_Win_bytes_forward": rng.choice([0, 29200, 65535], n),
        "Init_Win_bytes_backward": np.zeros(n, dtype=int),
        "act_data_pkt_fwd": rng.poisson(50, n),
        "min_seg_size_forward": rng.normal(40, 10, n).clip(20),
        "Active Mean": rng.exponential(5e4, n),
        "Active Std": rng.exponential(2e4, n),
        "Active Max": rng.exponential(2e5, n),
        "Active Min": rng.exponential(5e3, n),
        "Idle Mean": rng.exponential(1e4, n),
        "Idle Std": rng.exponential(5e3, n),
        "Idle Max": rng.exponential(5e4, n),
        "Idle Min": rng.exponential(1e3, n),
    }

    df = pd.DataFrame(data)
    df["Label"] = "DDoS"
    return df


def generate_dataset(
    n_samples: int = 10000,
    ddos_ratio: float = 0.3,
    seed: int = 42,
) -> pd.DataFrame:
    """Generate a complete dataset with normal and DDoS traffic."""
    rng = np.random.RandomState(seed)
    n_ddos = int(n_samples * ddos_ratio)
    n_normal = n_samples - n_ddos

    normal_df = generate_normal_traffic(n_normal, rng)
    ddos_df = generate_ddos_traffic(n_ddos, rng)

    df = pd.concat([normal_df, ddos_df], ignore_index=True)
    df = df.sample(frac=1, random_state=rng).reset_index(drop=True)

    return df


def main():
    parser = argparse.ArgumentParser(description="DRL DDoS Detection - Sample Data Generator")
    parser.add_argument("--output", type=str, required=True, help="Output CSV file or directory")
    parser.add_argument("--n", type=int, default=10000, help="Number of samples")
    parser.add_argument("--ddos-ratio", type=float, default=0.3, help="DDoS traffic ratio (0-1)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--split", nargs="+", help="Split data: e.g., --split train test")
    parser.add_argument("--train-ratio", type=float, default=0.8, help="Train split ratio")

    args = parser.parse_args()

    print(f"Generating {args.n} samples (DDoS ratio: {args.ddos_ratio}, seed: {args.seed})")
    df = generate_dataset(args.n, args.ddos_ratio, args.seed)

    if args.split:
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)

        n_train = int(len(df) * args.train_ratio)
        train_df = df.iloc[:n_train]
        test_df = df.iloc[n_train:]

        train_path = output_dir / "train.csv"
        test_path = output_dir / "test.csv"

        train_df.to_csv(train_path, index=False)
        test_df.to_csv(test_path, index=False)

        print(f"\nTrain set: {len(train_df)} samples -> {train_path}")
        print(f"Test set:  {len(test_df)} samples -> {test_path}")

        for name, data in [("Train", train_df), ("Test", test_df)]:
            ddos_count = (data["Label"] == "DDoS").sum()
            print(f"{name}: {len(data)} samples, {ddos_count} DDoS ({ddos_count/len(data):.1%})")
    else:
        output_path = Path(args.output)
        if output_path.suffix != ".csv":
            output_path.mkdir(parents=True, exist_ok=True)
            output_path = output_path / "sample_data.csv"
        else:
            output_path.parent.mkdir(parents=True, exist_ok=True)

        df.to_csv(output_path, index=False)
        ddos_count = (df["Label"] == "DDoS").sum()
        print(f"\nGenerated {len(df)} samples -> {output_path}")
        print(f"DDoS: {ddos_count} ({ddos_count/len(df):.1%}), Normal: {len(df) - ddos_count}")

    print(f"\nColumns: {len(df.columns)}")
    print(f"Feature columns: {len(FEATURE_COLUMNS)}")


if __name__ == "__main__":
    main()
