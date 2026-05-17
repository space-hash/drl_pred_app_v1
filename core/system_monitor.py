# core/system_monitor.py
"""
System Performance Monitor for DRL DDoS Detection Dashboard.

Collects hardware, application, and security metrics safely using psutil.
Designed to work across Linux, Windows, and macOS without causing errors.
"""
import time
import logging
import psutil
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger("SystemMonitor")


class SystemMonitor:
    """
    Collects system and application metrics safely.
    All methods use try/except to ensure failures don't crash the app.
    """

    def __init__(self):
        self._last_net_io = psutil.net_io_counters()
        self._last_net_io_time = time.time()
        self._last_disk_io = psutil.disk_io_counters()
        self._last_disk_io_time = time.time()

    def get_hardware_metrics(self) -> Dict[str, Any]:
        """Collect CPU, Memory, Disk, and Network metrics."""
        metrics = {}

        try:
            # CPU Usage
            metrics["cpu_percent"] = psutil.cpu_percent(interval=0.1)
            metrics["cpu_count"] = psutil.cpu_count(logical=True)
            metrics["cpu_freq"] = psutil.cpu_freq().current if psutil.cpu_freq() else 0
        except Exception as e:
            logger.debug(f"Failed to get CPU metrics: {e}")
            metrics["cpu_percent"] = 0
            metrics["cpu_count"] = 0
            metrics["cpu_freq"] = 0

        try:
            # Memory Usage
            mem = psutil.virtual_memory()
            metrics["memory_total_gb"] = round(mem.total / (1024**3), 2)
            metrics["memory_used_gb"] = round(mem.used / (1024**3), 2)
            metrics["memory_percent"] = mem.percent
        except Exception as e:
            logger.debug(f"Failed to get Memory metrics: {e}")
            metrics["memory_total_gb"] = 0
            metrics["memory_used_gb"] = 0
            metrics["memory_percent"] = 0

        try:
            # Disk Usage
            disk = psutil.disk_usage('/')
            metrics["disk_total_gb"] = round(disk.total / (1024**3), 2)
            metrics["disk_used_gb"] = round(disk.used / (1024**3), 2)
            metrics["disk_percent"] = disk.percent
        except Exception as e:
            logger.debug(f"Failed to get Disk metrics: {e}")
            metrics["disk_total_gb"] = 0
            metrics["disk_used_gb"] = 0
            metrics["disk_percent"] = 0

        try:
            # Network I/O Rate
            net_io = psutil.net_io_counters()
            now = time.time()
            dt = now - self._last_net_io_time
            if dt > 0:
                metrics["net_rx_mbps"] = round((net_io.bytes_recv - self._last_net_io.bytes_recv) * 8 / (1024**2) / dt, 2)
                metrics["net_tx_mbps"] = round((net_io.bytes_sent - self._last_net_io.bytes_sent) * 8 / (1024**2) / dt, 2)
                metrics["net_rx_pps"] = round((net_io.packets_recv - self._last_net_io.packets_recv) / dt, 0)
                metrics["net_tx_pps"] = round((net_io.packets_sent - self._last_net_io.packets_sent) / dt, 0)
            else:
                metrics["net_rx_mbps"] = metrics["net_tx_mbps"] = metrics["net_rx_pps"] = metrics["net_tx_pps"] = 0

            self._last_net_io = net_io
            self._last_net_io_time = now
        except Exception as e:
            logger.debug(f"Failed to get Network I/O metrics: {e}")
            metrics["net_rx_mbps"] = metrics["net_tx_mbps"] = metrics["net_rx_pps"] = metrics["net_tx_pps"] = 0

        try:
            # Disk I/O Rate
            disk_io = psutil.disk_io_counters()
            if disk_io:
                now = time.time()
                dt = now - self._last_disk_io_time
                if dt > 0 and self._last_disk_io:
                    metrics["disk_read_mbps"] = round((disk_io.read_bytes - self._last_disk_io.read_bytes) / (1024**2) / dt, 2)
                    metrics["disk_write_mbps"] = round((disk_io.write_bytes - self._last_disk_io.write_bytes) / (1024**2) / dt, 2)
                else:
                    metrics["disk_read_mbps"] = metrics["disk_write_mbps"] = 0
                self._last_disk_io = disk_io
                self._last_disk_io_time = now
            else:
                metrics["disk_read_mbps"] = metrics["disk_write_mbps"] = 0
        except Exception as e:
            logger.debug(f"Failed to get Disk I/O metrics: {e}")
            metrics["disk_read_mbps"] = metrics["disk_write_mbps"] = 0

        return metrics

    def get_app_metrics(self, controller) -> Dict[str, Any]:
        """Collect application-specific metrics from the pipeline controller."""
        metrics = {
            "pipeline_running": False,
            "queue_size": 0,
            "processed_files": 0,
            "failed_files": 0,
            "detections_per_min": 0,
            "model_loaded": False,
            "uptime_hours": 0,
        }

        try:
            if controller:
                status = controller.get_status()
                metrics["pipeline_running"] = status.get("running", False)
                metrics["queue_size"] = status.get("queue_size", 0)
                metrics["processed_files"] = status.get("processed_files", 0)
                metrics["failed_files"] = status.get("failed_files", 0)
                metrics["model_loaded"] = status.get("model_loaded", False)

                uptime = status.get("uptime", 0)
                metrics["uptime_hours"] = round(uptime / 3600, 2)

                # Calculate detections per minute
                total_detections = status.get("ddos_detections", 0) + status.get("suspicious_detections", 0)
                if uptime > 60:
                    metrics["detections_per_min"] = round(total_detections / (uptime / 60), 2)
                else:
                    metrics["detections_per_min"] = total_detections
        except Exception as e:
            logger.debug(f"Failed to get App metrics: {e}")

        return metrics

    def get_security_metrics(self, controller) -> Dict[str, Any]:
        """Collect security and mitigation metrics."""
        metrics = {
            "active_blocks": 0,
            "total_blocked_today": 0,
            "firewall_enabled": False,
            "ebpf_enabled": False,
            "alerts_triggered": 0,
        }

        try:
            if controller and controller.mitigation_agent:
                status = controller.mitigation_agent.get_status()
                metrics["active_blocks"] = status.get("total_blocked", 0)
                metrics["firewall_enabled"] = status.get("use_iptables", False)

                # Estimate total blocked today from log
                log = status.get("log", [])
                metrics["total_blocked_today"] = len([l for l in log if l.get("action") == "block"])

            if controller and controller.ebpf_manager:
                ebpf_status = controller.ebpf_manager.get_stats()
                metrics["ebpf_enabled"] = ebpf_status.get("use_xdp", False)

            if controller and controller.alert_manager:
                alert_stats = controller.alert_manager.get_stats()
                metrics["alerts_triggered"] = alert_stats.get("total_alerts", 0)
        except Exception as e:
            logger.debug(f"Failed to get Security metrics: {e}")

        return metrics

    def get_all_metrics(self, controller) -> Dict[str, Any]:
        """Return a combined dictionary of all metrics."""
        return {
            "timestamp": datetime.now().isoformat(),
            "hardware": self.get_hardware_metrics(),
            "application": self.get_app_metrics(controller),
            "security": self.get_security_metrics(controller),
        }
