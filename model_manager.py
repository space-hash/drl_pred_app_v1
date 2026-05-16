#!/usr/bin/env python3
"""
DRL DDoS Detection - Model Management Utility

Manage model lifecycle: info, metadata, export, validate, cleanup.

Usage:
    python model_manager.py info models/final_drl1.pt
    python model_manager.py metadata models/final_drl1.pt --set key=value
    python model_manager.py export models/final_drl1.pt --format onnx
    python model_manager.py validate models/final_drl1.pt
    python model_manager.py list models/
    python model_manager.py cleanup models/ --keep 3
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import torch

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from detection_module.detection import EnhancedPPOAgent, FLOW_FEATURE_DIM, ACTION_DIM, HIDDEN_DIM

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("ModelManager")


def get_model_info(model_path: str) -> dict:
    """Get comprehensive model information."""
    p = Path(model_path)
    if not p.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")

    stat = p.stat()
    info = {
        "path": str(p),
        "filename": p.name,
        "size_bytes": stat.st_size,
        "size_mb": round(stat.st_size / (1024 * 1024), 2),
        "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
    }

    try:
        checkpoint = torch.load(str(p), map_location="cpu", weights_only=False)

        if "model_config" in checkpoint:
            info["architecture"] = checkpoint["model_config"]

        if "metadata" in checkpoint:
            info["metadata"] = checkpoint["metadata"]

        if "training_metrics" in checkpoint:
            metrics = checkpoint["training_metrics"]
            info["training_summary"] = {
                "episode_rewards_count": len(metrics.get("episode_rewards", [])),
                "final_episode_reward": metrics.get("episode_rewards", [0])[-1] if metrics.get("episode_rewards") else 0,
                "policy_loss_count": len(metrics.get("policy_loss", [])),
            }

        if "platform_info" in checkpoint:
            info["platform_info"] = checkpoint["platform_info"]

        if "policy_state_dict" in checkpoint:
            state_dict = checkpoint["policy_state_dict"]
            info["parameters"] = {
                "total_keys": len(state_dict),
                "layers": list(state_dict.keys()),
            }

        info["valid"] = True
        info["loadable"] = True

    except Exception as e:
        info["valid"] = False
        info["loadable"] = False
        info["error"] = str(e)

    return info


def update_metadata(model_path: str, updates: dict) -> bool:
    """Update model metadata in-place."""
    p = Path(model_path)
    if not p.exists():
        logger.error(f"Model not found: {model_path}")
        return False

    try:
        checkpoint = torch.load(str(p), map_location="cpu", weights_only=False)

        if "metadata" not in checkpoint:
            checkpoint["metadata"] = {}

        checkpoint["metadata"].update(updates)
        checkpoint["metadata"]["last_modified"] = datetime.now().isoformat()

        torch.save(checkpoint, str(p), _use_new_zipfile_serialization=True)
        logger.info(f"Metadata updated for {p.name}")
        return True

    except Exception as e:
        logger.error(f"Failed to update metadata: {e}")
        return False


def validate_model(model_path: str) -> dict:
    """Validate model integrity and compatibility."""
    p = Path(model_path)
    result = {"path": str(p), "valid": True, "issues": [], "warnings": []}

    if not p.exists():
        result["valid"] = False
        result["issues"].append("File not found")
        return result

    if p.stat().st_size < 1000:
        result["valid"] = False
        result["issues"].append("File too small (< 1KB)")
        return result

    try:
        checkpoint = torch.load(str(p), map_location="cpu", weights_only=False)
    except Exception as e:
        result["valid"] = False
        result["issues"].append(f"Cannot load file: {e}")
        return result

    required_keys = ["policy_state_dict", "model_config"]
    for key in required_keys:
        if key not in checkpoint:
            result["valid"] = False
            result["issues"].append(f"Missing required key: {key}")

    if "model_config" in checkpoint:
        config = checkpoint["model_config"]
        if config.get("state_dim") != FLOW_FEATURE_DIM:
            result["warnings"].append(
                f"state_dim mismatch: {config.get('state_dim')} != {FLOW_FEATURE_DIM}"
            )
        if config.get("action_dim") != ACTION_DIM:
            result["warnings"].append(
                f"action_dim mismatch: {config.get('action_dim')} != {ACTION_DIM}"
            )

    if "metadata" not in checkpoint:
        result["warnings"].append("No metadata found")

    if "platform_info" not in checkpoint:
        result["warnings"].append("No platform info found")

    try:
        agent = EnhancedPPOAgent.load_model(str(p), map_location="cpu")
        test_input = torch.randn(1, FLOW_FEATURE_DIM)
        with torch.no_grad():
            agent.policy(test_input)
        result["inference_test"] = "passed"
    except Exception as e:
        result["inference_test"] = f"failed: {e}"
        result["warnings"].append(f"Inference test failed: {e}")

    return result


def export_model(model_path: str, output_path: str = None, format: str = "pt") -> bool:
    """Export model to different format."""
    p = Path(model_path)
    if not p.exists():
        logger.error(f"Model not found: {model_path}")
        return False

    if output_path is None:
        output_path = str(p.with_suffix(f".{format}"))

    try:
        agent = EnhancedPPOAgent.load_model(str(p), map_location="cpu")

        if format == "pt":
            metadata = {}
            try:
                checkpoint = torch.load(str(p), map_location="cpu", weights_only=False)
                metadata = checkpoint.get("metadata", {})
            except Exception:
                pass

            metadata["exported_at"] = datetime.now().isoformat()
            metadata["export_format"] = "pt_modern"

            agent.save_model(output_path, metadata=metadata)
            logger.info(f"Model exported to {output_path} (modern PyTorch format)")

        elif format == "state_dict":
            torch.save(agent.policy.state_dict(), output_path)
            logger.info(f"State dict exported to {output_path}")

        else:
            logger.error(f"Unsupported format: {format}")
            return False

        return True

    except Exception as e:
        logger.error(f"Export failed: {e}")
        return False


def list_models(models_dir: str, verbose: bool = False) -> list:
    """List all models with details."""
    p = Path(models_dir)
    if not p.exists():
        logger.error(f"Directory not found: {models_dir}")
        return []

    models = []
    for f in sorted(p.glob("*.pt")):
        info = {
            "name": f.name,
            "size_mb": round(f.stat().st_size / (1024 * 1024), 2),
            "modified": datetime.fromtimestamp(f.stat().st_mtime).isoformat()[:19],
        }

        try:
            checkpoint = torch.load(str(f), map_location="cpu", weights_only=False)
            meta = checkpoint.get("metadata", {})
            info["created"] = meta.get("created_at", "Unknown")[:19]
            info["epochs"] = meta.get("epochs", "N/A")
            info["best_reward"] = meta.get("best_reward", "N/A")
            info["version"] = meta.get("version", "N/A")
            info["valid"] = True
        except Exception:
            info["valid"] = False

        models.append(info)

    if verbose:
        print(f"\n{'Name':<25} {'Size':<8} {'Created':<22} {'Epochs':<8} {'Reward':<10} {'Valid':<6}")
        print("-" * 85)
        for m in models:
            reward = f"{m['best_reward']:.2f}" if isinstance(m["best_reward"], (int, float)) else str(m["best_reward"])
            print(
                f"{m['name']:<25} {m['size_mb']:<8} {m.get('created', m['modified']):<22} "
                f"{str(m['epochs']):<8} {str(reward):<10} {'Yes' if m['valid'] else 'No':<6}"
            )
        print()

    return models


def cleanup_models(models_dir: str, keep: int = 3, dry_run: bool = False) -> list:
    """Remove old models, keeping the N most recent."""
    models = list_models(models_dir)
    if len(models) <= keep:
        logger.info(f"Only {len(models)} models found, keeping all (threshold: {keep})")
        return []

    models.sort(key=lambda x: x["modified"], reverse=True)
    to_remove = models[keep:]
    removed = []

    for m in to_remove:
        path = Path(models_dir) / m["name"]
        if dry_run:
            logger.info(f"Would remove: {m['name']} ({m['size_mb']}MB)")
        else:
            path.unlink()
            logger.info(f"Removed: {m['name']}")
        removed.append(m["name"])

    return removed


def main():
    parser = argparse.ArgumentParser(description="DRL DDoS Detection - Model Manager")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    p_info = subparsers.add_parser("info", help="Show model information")
    p_info.add_argument("model", help="Model file path")

    p_meta = subparsers.add_parser("metadata", help="Update model metadata")
    p_meta.add_argument("model", help="Model file path")
    p_meta.add_argument("--set", nargs="+", help="Set metadata key=value pairs")

    p_validate = subparsers.add_parser("validate", help="Validate model integrity")
    p_validate.add_argument("model", help="Model file path")

    p_export = subparsers.add_parser("export", help="Export model to different format")
    p_export.add_argument("model", help="Model file path")
    p_export.add_argument("--output", help="Output file path")
    p_export.add_argument("--format", default="pt", choices=["pt", "state_dict"])

    p_list = subparsers.add_parser("list", help="List models in directory")
    p_list.add_argument("dir", help="Models directory")
    p_list.add_argument("-v", "--verbose", action="store_true")

    p_cleanup = subparsers.add_parser("cleanup", help="Remove old models")
    p_cleanup.add_argument("dir", help="Models directory")
    p_cleanup.add_argument("--keep", type=int, default=3, help="Number of models to keep")
    p_cleanup.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == "info":
        info = get_model_info(args.model)
        print(json.dumps(info, indent=2, default=str))

    elif args.command == "metadata":
        updates = {}
        if args.set:
            for kv in args.set:
                k, v = kv.split("=", 1)
                updates[k] = v
        if updates:
            update_metadata(args.model, updates)
        else:
            info = get_model_info(args.model)
            print(json.dumps(info.get("metadata", {}), indent=2))

    elif args.command == "validate":
        result = validate_model(args.model)
        print(json.dumps(result, indent=2))
        if result["valid"]:
            print("\nModel is VALID")
        else:
            print("\nModel is INVALID")
            sys.exit(1)

    elif args.command == "export":
        export_model(args.model, args.output, args.format)

    elif args.command == "list":
        list_models(args.dir, args.verbose)

    elif args.command == "cleanup":
        removed = cleanup_models(args.dir, args.keep, args.dry_run)
        if removed:
            print(f"Removed {len(removed)} models: {', '.join(removed)}")
        else:
            print("No models removed")


if __name__ == "__main__":
    main()
