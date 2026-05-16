#!/usr/bin/env python3
"""
DRL DDoS Detection - Add Metadata to Existing Models

Scans all .pt model files and adds/enhances metadata for models that lack it.

Usage:
    python add_model_metadata.py
    python add_model_metadata.py --models models/final_drl1.pt models/final_drl.pt
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import torch

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from detection_module.detection import EnhancedPPOAgent, FLOW_FEATURE_DIM, ACTION_DIM, HIDDEN_DIM, LEARNING_RATE

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("AddMetadata")


def add_metadata_to_model(model_path: str) -> bool:
    """Add or enhance metadata for a model file."""
    p = Path(model_path)
    if not p.exists():
        logger.error(f"Model not found: {model_path}")
        return False

    try:
        checkpoint = torch.load(str(p), map_location="cpu", weights_only=False)
    except Exception as e:
        logger.error(f"Cannot load {p.name}: {e}")
        return False

    if "metadata" not in checkpoint:
        checkpoint["metadata"] = {}

    meta = checkpoint["metadata"]

    if "model_type" not in meta:
        meta["model_type"] = "PPO"
    if "version" not in meta:
        meta["version"] = "1.0"
    if "created_at" not in meta:
        meta["created_at"] = datetime.fromtimestamp(p.stat().st_ctime).isoformat()
    if "state_dim" not in meta:
        meta["state_dim"] = FLOW_FEATURE_DIM
    if "action_dim" not in meta:
        meta["action_dim"] = ACTION_DIM

    if "model_config" not in checkpoint:
        checkpoint["model_config"] = {
            "state_dim": FLOW_FEATURE_DIM,
            "action_dim": ACTION_DIM,
            "hidden_dim": HIDDEN_DIM,
            "learning_rate": LEARNING_RATE,
        }

    if "platform_info" not in checkpoint:
        import platform
        checkpoint["platform_info"] = {
            "platform": platform.system(),
            "python_version": platform.python_version(),
            "pytorch_version": torch.__version__,
            "saved_device": "cpu",
        }

    if "training_metrics" not in checkpoint:
        checkpoint["training_metrics"] = {}

    meta["last_modified"] = datetime.now().isoformat()
    meta["metadata_added_by"] = "add_model_metadata.py"

    torch.save(checkpoint, str(p), _use_new_zipfile_serialization=True)
    logger.info(f"Metadata added to {p.name}")
    return True


def main():
    models_dir = Path("detection_module/trained_models")
    if not models_dir.exists():
        logger.error("Models directory not found")
        sys.exit(1)

    model_files = sorted(models_dir.glob("*.pt"))
    if not model_files:
        logger.info("No model files found")
        return

    logger.info(f"Found {len(model_files)} models to process")

    success = 0
    for mf in model_files:
        if add_metadata_to_model(str(mf)):
            success += 1

    logger.info(f"Successfully updated {success}/{len(model_files)} models")


if __name__ == "__main__":
    main()
