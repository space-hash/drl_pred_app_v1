# app.py
"""
Flask web application for DDoS detection dashboard.
Provides pipeline control, detection visualization, and mitigation management.
"""
import logging
import signal
import sys
import socket
from datetime import datetime
from typing import Dict, Any, Optional
from flask import Flask, render_template, request, jsonify
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

logger = logging.getLogger(__name__)

app = Flask(__name__)

DEFAULT_DETECTION_LIMIT = 20
MAX_DETECTION_LIMIT = 100


def check_privileges():
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        s.close()
        return True
    except PermissionError:
        return False


@app.route("/")
def index():
    return render_template(
        "index.html",
        has_privileges=check_privileges(),
        is_running=is_pipeline_running(),
        current_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


@app.route("/start", methods=["POST"])
def start():
    if not check_privileges():
        return jsonify({"status": "error", "message": "Insufficient privileges"}), 403
    if is_pipeline_running():
        return jsonify({"status": "error", "message": "Pipeline already running"}), 400
    if start_pipeline():
        return jsonify({"status": "success", "message": "Pipeline started"})
    return jsonify({"status": "error", "message": "Failed to start pipeline"}), 500


@app.route("/stop", methods=["POST"])
def stop():
    if not is_pipeline_running():
        return jsonify({"status": "error", "message": "Pipeline not running"}), 400
    if stop_pipeline():
        return jsonify({"status": "success", "message": "Pipeline stopped"})
    return jsonify({"status": "error", "message": "Failed to stop pipeline"}), 500


@app.route("/api/status")
def api_status():
    try:
        status = pipeline_status()
        status["detection_stats"] = {
            "ddos": status.get("ddos_detections", 0),
            "normal": status.get("normal_detections", 0),
            "suspicious": status.get("suspicious_detections", 0),
        }
        return jsonify(status)
    except Exception as e:
        logger.error("Error in /api/status: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/detections")
def api_recent_detections():
    try:
        limit = min(int(request.args.get("limit", DEFAULT_DETECTION_LIMIT)), MAX_DETECTION_LIMIT)
        offset = int(request.args.get("offset", 0))
        detections = get_recent_detections(limit=limit)
        total_detections = len(detections)
        return jsonify({
            "detections": detections[offset : offset + limit],
            "metadata": {
                "total": total_detections,
                "limit": limit,
                "offset": offset,
                "has_more": (offset + limit) < total_detections,
            },
        })
    except Exception as e:
        logger.error("Error in /api/detections: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/detections/<detection_id>")
def api_detection_details(detection_id):
    try:
        details = get_detection_details(detection_id)
        if details:
            return jsonify(details)
        return jsonify({"error": "Detection not found"}), 404
    except Exception as e:
        logger.error("Error in /api/detections/<id>: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/stats")
def detection_stats():
    try:
        status = pipeline_status()
        return jsonify({
            "ddos_count": status.get("ddos_detections", 0),
            "normal_count": status.get("normal_detections", 0),
            "suspicious_count": status.get("suspicious_detections", 0),
            "throughput": {
                "files_processed": status.get("processed_files", 0),
                "files_failed": status.get("failed_files", 0),
                "processing_rate": _calculate_processing_rate(status),
            },
        })
    except Exception as e:
        logger.error("Error in /api/stats: %s", e)
        return jsonify({"error": str(e)}), 500


def _calculate_processing_rate(status):
    if "start_time" not in status or not status["start_time"]:
        return 0.0
    start_time = datetime.fromisoformat(status["start_time"])
    uptime_minutes = (datetime.now() - start_time).total_seconds() / 60
    if uptime_minutes <= 0:
        return 0.0
    return round(status.get("processed_files", 0) / uptime_minutes, 2)


@app.route("/api/model_status")
def api_model_status():
    try:
        last_update = None
        if controller.model_updater and controller.model_updater.last_update:
            last_update = controller.model_updater.last_update.isoformat()
        return jsonify({"status": "success", "data": {"last_update": last_update}})
    except Exception as e:
        logger.error("Error in /api/model_status: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/update_model", methods=["POST"])
def trigger_model_update():
    try:
        success = controller.model_updater.update_model()
        if success:
            return jsonify({
                "status": "success",
                "message": "Model updated successfully",
                "timestamp": datetime.now().isoformat(),
            })
        return jsonify({"status": "error", "message": "Model update failed"}), 400
    except Exception as e:
        logger.error("Error in /api/update_model: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/data", methods=["POST"])
def api_receive_predictions():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    logger.debug("Received prediction data for file: %s", data.get("filename", "unknown"))
    return jsonify({"status": "success", "received": True})


@app.route("/raw_data", methods=["POST"])
def api_receive_raw_data():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    logger.debug("Received raw data for file: %s", data.get("filename", "unknown"))
    return jsonify({"status": "success", "received": True})


# --- Mitigation API ---

@app.route("/api/mitigation/status")
def api_mitigation_status():
    try:
        if controller.mitigation_agent:
            return jsonify(controller.mitigation_agent.get_status())
        return jsonify({"enabled": False})
    except Exception as e:
        logger.error("Error in /api/mitigation/status: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/mitigation/toggle", methods=["POST"])
def api_mitigation_toggle():
    if not controller.mitigation_agent:
        return jsonify({"error": "Mitigation not enabled"}), 400
    try:
        enabled = request.json.get("enabled", False)
        controller.mitigation_agent.set_enabled(enabled)
        return jsonify({"status": "ok", "enabled": enabled})
    except Exception as e:
        logger.error("Error in /api/mitigation/toggle: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/mitigation/toggle_auto", methods=["POST"])
def api_mitigation_toggle_auto():
    if not controller.mitigation_agent:
        return jsonify({"error": "Mitigation not enabled"}), 400
    try:
        enabled = request.json.get("enabled", False)
        controller.mitigation_agent.set_auto_block(enabled)
        return jsonify({"status": "ok", "auto_block": enabled})
    except Exception as e:
        logger.error("Error in /api/mitigation/toggle_auto: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/mitigation/toggle_ml_auto", methods=["POST"])
def api_mitigation_toggle_ml_auto():
    if not controller.mitigation_agent:
        return jsonify({"error": "Mitigation not enabled"}), 400
    try:
        enabled = request.json.get("enabled", False)
        controller.mitigation_agent.set_ml_auto_block(enabled)
        return jsonify({"status": "ok", "ml_auto_block": enabled})
    except Exception as e:
        logger.error("Error in /api/mitigation/toggle_ml_auto: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/mitigation/settings", methods=["POST"])
def api_mitigation_settings():
    if not controller.mitigation_agent:
        return jsonify({"error": "Mitigation not enabled"}), 400
    try:
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
    except Exception as e:
        logger.error("Error in /api/mitigation/settings: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/mitigation/block", methods=["POST"])
def api_mitigation_block():
    if not controller.mitigation_agent:
        return jsonify({"error": "Mitigation not enabled"}), 400
    try:
        ip = request.json.get("ip", "").strip()
        if not ip:
            return jsonify({"error": "IP required"}), 400
        controller.mitigation_agent.block_ip(ip, "Manual block")
        return jsonify({"status": "blocked", "ip": ip})
    except Exception as e:
        logger.error("Error in /api/mitigation/block: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/mitigation/unblock", methods=["POST"])
def api_mitigation_unblock():
    if not controller.mitigation_agent:
        return jsonify({"error": "Mitigation not enabled"}), 400
    try:
        ip = request.json.get("ip", "").strip()
        if not ip:
            return jsonify({"error": "IP required"}), 400
        if controller.mitigation_agent.unblock_ip(ip):
            return jsonify({"status": "unblocked", "ip": ip})
        return jsonify({"error": "Not blocked"}), 404
    except Exception as e:
        logger.error("Error in /api/mitigation/unblock: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/mitigation/whitelist", methods=["POST"])
def api_mitigation_whitelist():
    if not controller.mitigation_agent:
        return jsonify({"error": "Mitigation not enabled"}), 400
    try:
        ip = request.json.get("ip", "").strip()
        if not ip:
            return jsonify({"error": "IP required"}), 400
        controller.mitigation_agent.add_whitelist(ip)
        return jsonify({"status": "whitelisted", "ip": ip})
    except Exception as e:
        logger.error("Error in /api/mitigation/whitelist: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/mitigation/unwhitelist", methods=["POST"])
def api_mitigation_unwhitelist():
    if not controller.mitigation_agent:
        return jsonify({"error": "Mitigation not enabled"}), 400
    try:
        ip = request.json.get("ip", "").strip()
        if not ip:
            return jsonify({"error": "IP required"}), 400
        controller.mitigation_agent.remove_whitelist(ip)
        return jsonify({"status": "removed", "ip": ip})
    except Exception as e:
        logger.error("Error in /api/mitigation/unwhitelist: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/mitigation/blacklist", methods=["POST"])
def api_mitigation_blacklist():
    if not controller.mitigation_agent:
        return jsonify({"error": "Mitigation not enabled"}), 400
    try:
        ip = request.json.get("ip", "").strip()
        if not ip:
            return jsonify({"error": "IP required"}), 400
        controller.mitigation_agent.add_blacklist(ip)
        return jsonify({"status": "blacklisted", "ip": ip})
    except Exception as e:
        logger.error("Error in /api/mitigation/blacklist: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/mitigation/unblacklist", methods=["POST"])
def api_mitigation_unblacklist():
    if not controller.mitigation_agent:
        return jsonify({"error": "Mitigation not enabled"}), 400
    try:
        ip = request.json.get("ip", "").strip()
        if not ip:
            return jsonify({"error": "IP required"}), 400
        controller.mitigation_agent.remove_blacklist(ip)
        return jsonify({"status": "removed", "ip": ip})
    except Exception as e:
        logger.error("Error in /api/mitigation/unblacklist: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/mitigation/clear_counts", methods=["POST"])
def api_mitigation_clear_counts():
    if not controller.mitigation_agent:
        return jsonify({"error": "Mitigation not enabled"}), 400
    try:
        controller.mitigation_agent.clear_detection_counts()
        return jsonify({"status": "cleared"})
    except Exception as e:
        logger.error("Error in /api/mitigation/clear_counts: %s", e)
        return jsonify({"error": str(e)}), 500


def graceful_shutdown(signum, frame):
    logger.info("Received signal %s, shutting down...", signum)
    if is_pipeline_running():
        stop_pipeline()
    sys.exit(0)


signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)


if __name__ == "__main__":
    if not check_privileges():
        print("\nWARNING: Missing packet capture privileges. Run with:")
        print(f"  sudo {sys.executable} {__file__}\n")
    app.run(host=config.FLASK_HOST, port=config.FLASK_PORT, debug=config.FLASK_DEBUG)
