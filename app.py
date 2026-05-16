from flask import Flask, render_template, request, redirect, jsonify
import os
import sys
import socket
import signal
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from core.controller import (
    start_pipeline,
    stop_pipeline,
    pipeline_status,
    is_pipeline_running,
    get_recent_detections,
    get_detection_details,
    controller,
)
from capapp.config.settings import config

app = Flask(__name__)

DEFAULT_DETECTION_LIMIT = 20
MAX_DETECTION_LIMIT = 100


def check_privileges() -> bool:
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        s.close()
        return True
    except PermissionError:
        return False


@app.route("/")
def index() -> str:
    return render_template(
        "index.html",
        has_privileges=check_privileges(),
        is_running=is_pipeline_running(),
        current_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


@app.route("/start", methods=["POST"])
def start() -> Any:
    if not check_privileges():
        return jsonify({"status": "error", "message": "Insufficient privileges"}), 403
    if is_pipeline_running():
        return jsonify({"status": "error", "message": "Pipeline already running"}), 400
    if start_pipeline():
        return redirect("/")
    return jsonify({"status": "error", "message": "Failed to start pipeline"}), 500


@app.route("/stop", methods=["POST"])
def stop() -> Any:
    if not is_pipeline_running():
        return jsonify({"status": "error", "message": "Pipeline not running"}), 400
    if stop_pipeline():
        return redirect("/")
    return jsonify({"status": "error", "message": "Failed to stop pipeline"}), 500


@app.route("/api/status")
def api_status() -> Dict[str, Any]:
    status = pipeline_status()
    status["detection_stats"] = {
        "ddos": status.get("ddos_detections", 0),
        "normal": status.get("normal_detections", 0),
        "suspicious": status.get("suspicious_detections", 0),
    }
    return jsonify(status)


@app.route("/api/detections")
def api_recent_detections() -> Dict[str, Any]:
    limit = min(int(request.args.get("limit", DEFAULT_DETECTION_LIMIT)), MAX_DETECTION_LIMIT)
    offset = int(request.args.get("offset", 0))
    detections = get_recent_detections(limit=limit)
    total_detections = len(detections)
    return jsonify(
        {
            "detections": detections[offset : offset + limit],
            "metadata": {
                "total": total_detections,
                "limit": limit,
                "offset": offset,
                "has_more": (offset + limit) < total_detections,
            },
        }
    )


@app.route("/api/detections/<detection_id>")
def api_detection_details(detection_id: str) -> Any:
    details = get_detection_details(detection_id)
    if details:
        return jsonify(details)
    return jsonify({"error": "Detection not found"}), 404


@app.route("/api/stats")
def detection_stats() -> Dict[str, Any]:
    status = pipeline_status()
    return jsonify(
        {
            "ddos_count": status.get("ddos_detections", 0),
            "normal_count": status.get("normal_detections", 0),
            "suspicious_count": status.get("suspicious_detections", 0),
            "throughput": {
                "files_processed": status.get("processed_files", 0),
                "files_failed": status.get("failed_files", 0),
                "processing_rate": calculate_processing_rate(status),
            },
        }
    )


def calculate_processing_rate(status: Dict[str, Any]) -> float:
    if "start_time" not in status or not status["start_time"]:
        return 0.0
    start_time = datetime.fromisoformat(status["start_time"])
    uptime_minutes = (datetime.now() - start_time).total_seconds() / 60
    if uptime_minutes <= 0:
        return 0.0
    return round(status.get("processed_files", 0) / uptime_minutes, 2)


@app.route("/api/model_status")
def api_model_status():
    last_update = None
    if controller.model_updater and controller.model_updater.last_update:
        last_update = controller.model_updater.last_update.isoformat()
    return jsonify({"status": "success", "data": {"last_update": last_update}})


@app.route("/api/update_model", methods=["POST"])
def trigger_model_update():
    try:
        success = controller.model_updater.update_model()
        if success:
            return jsonify(
                {
                    "status": "success",
                    "message": "Model updated successfully",
                    "timestamp": datetime.now().isoformat(),
                }
            )
        return jsonify({"status": "error", "message": "Model update failed"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/data", methods=["POST"])
def api_receive_predictions():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    logger.debug(f"Received prediction data for file: {data.get('filename', 'unknown')}")
    return jsonify({"status": "success", "received": True})


@app.route("/raw_data", methods=["POST"])
def api_receive_raw_data():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    logger.debug(f"Received raw data for file: {data.get('filename', 'unknown')}")
    return jsonify({"status": "success", "received": True})


# Mitigation API
@app.route("/api/mitigation/status")
def api_mitigation_status():
    if controller.mitigation_agent:
        return jsonify(controller.mitigation_agent.get_status())
    return jsonify({"enabled": False})

@app.route("/api/mitigation/block", methods=["POST"])
def api_mitigation_block():
    if not controller.mitigation_agent:
        return jsonify({"error": "Not enabled"}), 400
    ip = request.json.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP required"}), 400
    controller.mitigation_agent.block_ip(ip, "Manual block")
    return jsonify({"status": "blocked", "ip": ip})

@app.route("/api/mitigation/unblock", methods=["POST"])
def api_mitigation_unblock():
    if not controller.mitigation_agent:
        return jsonify({"error": "Not enabled"}), 400
    ip = request.json.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP required"}), 400
    if controller.mitigation_agent.unblock_ip(ip):
        return jsonify({"status": "unblocked", "ip": ip})
    return jsonify({"error": "Not blocked"}), 404

@app.route("/api/mitigation/toggle", methods=["POST"])
def api_mitigation_toggle():
    if not controller.mitigation_agent:
        return jsonify({"error": "Not enabled"}), 400
    enabled = request.json.get("enabled", False)
    controller.mitigation_agent.set_enabled(enabled)
    return jsonify({"status": "ok", "enabled": enabled})

@app.route("/api/mitigation/toggle_auto", methods=["POST"])
def api_mitigation_toggle_auto():
    if not controller.mitigation_agent:
        return jsonify({"error": "Not enabled"}), 400
    enabled = request.json.get("enabled", False)
    controller.mitigation_agent.set_auto_block(enabled)
    return jsonify({"status": "ok", "auto_block": enabled})

@app.route("/api/mitigation/toggle_ml_auto", methods=["POST"])
def api_mitigation_toggle_ml_auto():
    if not controller.mitigation_agent:
        return jsonify({"error": "Not enabled"}), 400
    enabled = request.json.get("enabled", False)
    controller.mitigation_agent.set_ml_auto_block(enabled)
    return jsonify({"status": "ok", "ml_auto_block": enabled})

@app.route("/api/mitigation/settings", methods=["POST"])
def api_mitigation_settings():
    if not controller.mitigation_agent:
        return jsonify({"error": "Not enabled"}), 400
    data = request.json
    if "rate_limit_ppm" in data:
        controller.mitigation_agent.set_rate_limit_ppm(int(data["rate_limit_ppm"]))
    if "confidence" in data:
        controller.mitigation_agent.set_confidence(float(data["confidence"]))
    if "count" in data:
        controller.mitigation_agent.set_detection_count(int(data["count"]))
    if "duration" in data:
        controller.mitigation_agent.set_block_duration(int(data["duration"]))
    return jsonify({"status": "ok"})

@app.route("/api/mitigation/whitelist", methods=["POST"])
def api_mitigation_whitelist():
    if not controller.mitigation_agent:
        return jsonify({"error": "Not enabled"}), 400
    ip = request.json.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP required"}), 400
    controller.mitigation_agent.add_whitelist(ip)
    return jsonify({"status": "whitelisted", "ip": ip})

@app.route("/api/mitigation/unwhitelist", methods=["POST"])
def api_mitigation_unwhitelist():
    if not controller.mitigation_agent:
        return jsonify({"error": "Not enabled"}), 400
    ip = request.json.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP required"}), 400
    controller.mitigation_agent.remove_whitelist(ip)
    return jsonify({"status": "removed", "ip": ip})

@app.route("/api/mitigation/blacklist", methods=["POST"])
def api_mitigation_blacklist():
    if not controller.mitigation_agent:
        return jsonify({"error": "Not enabled"}), 400
    ip = request.json.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP required"}), 400
    controller.mitigation_agent.add_blacklist(ip)
    return jsonify({"status": "blacklisted", "ip": ip})

@app.route("/api/mitigation/unblacklist", methods=["POST"])
def api_mitigation_unblacklist():
    if not controller.mitigation_agent:
        return jsonify({"error": "Not enabled"}), 400
    ip = request.json.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP required"}), 400
    controller.mitigation_agent.remove_blacklist(ip)
    return jsonify({"status": "removed", "ip": ip})

@app.route("/api/mitigation/clear_counts", methods=["POST"])
def api_mitigation_clear_counts():
    if not controller.mitigation_agent:
        return jsonify({"error": "Not enabled"}), 400
    controller.mitigation_agent.clear_detection_counts()
    return jsonify({"status": "cleared"})


def graceful_shutdown(signum, frame):
    logger = logging.getLogger(__name__)
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    if is_pipeline_running():
        stop_pipeline()
    sys.exit(0)


signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)


if __name__ == "__main__":
    if not check_privileges():
        print("\nWARNING: Missing packet capture privileges. Try:")
        print(f"  sudo setcap cap_net_raw,cap_net_admin+eip {sys.executable}")
        print(f"Or run with: sudo {sys.executable} {__file__}\n")
    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.FLASK_DEBUG)
