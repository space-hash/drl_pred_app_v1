# core/ebpf_manager.py
"""
eBPF/XDP Manager for line-rate packet filtering.

Provides kernel-level packet dropping using eBPF/XDP programs.
Falls back to iptables if eBPF is not available.

Features:
- XDP_DROP for line-rate filtering (millions of pps)
- Automatic fallback to iptables if eBPF unavailable
- IP block/unblock via eBPF map updates
- Statistics tracking (packets dropped, bytes dropped)
- Persistent blocking with disk storage
"""
import threading
import logging
import subprocess
import json
import ipaddress
from pathlib import Path
from typing import Dict, Any, Optional, Set, List
from datetime import datetime, timedelta

logger = logging.getLogger("eBPFManager")

EBPF_BLOCKS_FILE = Path(__file__).parent.parent / "data" / "ebpf_blocked_ips.json"

# Try to import bcc/pyroute2 for eBPF, fall back to subprocess-based approach
try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False
    logger.warning("bcc library not available, using subprocess-based eBPF management")

try:
    import pyroute2
    PYROUTE2_AVAILABLE = True
except ImportError:
    PYROUTE2_AVAILABLE = False


class XDPProgram:
    """Manages XDP program for line-rate packet filtering."""

    XDP_CODE = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <bpf/bpf_helpers.h>

BPF_HASH(blocked_ipv4, u32, u8);
BPF_HASH(blocked_ipv6, struct in6_addr, u8);
BPF_HASH(stats, u32, u64);

static inline int is_blocked_ipv4(u32 ip) {
    u8 *val = blocked_ipv4.lookup(&ip);
    return val != NULL;
}

static inline int is_blocked_ipv6(struct in6_addr *ip) {
    u8 *val = blocked_ipv6.lookup(ip);
    return val != NULL;
}

static inline void increment_drop_stats() {
    u32 key = 0;
    u64 *val = stats.lookup(&key);
    if (val) {
        (*val)++;
    } else {
        u64 initial = 1;
        stats.update(&key, &initial);
    }
}

int xdp_drop_blocked(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *iph = data + sizeof(*eth);
        if ((void *)iph + sizeof(*iph) > data_end)
            return XDP_PASS;

        u32 src_ip = iph->saddr;
        if (is_blocked_ipv4(src_ip)) {
            increment_drop_stats();
            return XDP_DROP;
        }
    } else if (eth->h_proto == htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = data + sizeof(*eth);
        if ((void *)ip6h + sizeof(*ip6h) > data_end)
            return XDP_PASS;

        struct in6_addr src_ip6;
        __builtin_memcpy(&src_ip6, &ip6h->saddr, sizeof(src_ip6));
        if (is_blocked_ipv6(&src_ip6)) {
            increment_drop_stats();
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}
"""

    def __init__(self, interface: str = ""):
        self.interface = interface
        self.bpf = None
        self.attached = False
        self._lock = threading.RLock()

    def load(self) -> bool:
        """Load XDP program into kernel."""
        if not BCC_AVAILABLE:
            logger.warning("BCC not available, cannot load XDP program")
            return False

        try:
            self.bpf = BPF(text=self.XDP_CODE)
            fn = self.bpf.load_func("xdp_drop_blocked", BPF.XDP)
            if self.interface:
                self.bpf.attach_xdp(self.interface, fn, 0)
                self.attached = True
                logger.info(f"XDP program loaded on {self.interface}")
                return True
            else:
                logger.warning("No interface specified for XDP attachment")
                return False
        except Exception as e:
            logger.error(f"Failed to load XDP program: {e}")
            return False

    def unload(self) -> bool:
        """Remove XDP program from interface."""
        if not self.bpf or not self.attached:
            return True

        try:
            if self.interface:
                self.bpf.remove_xdp(self.interface, 0)
                self.attached = False
                logger.info(f"XDP program removed from {self.interface}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to remove XDP program: {e}")
            return False

    def block_ip(self, ip: str) -> bool:
        """Add IP to XDP block list."""
        if not self.bpf:
            return False

        try:
            import ctypes
            with self._lock:
                if ipaddress.ip_address(ip).version == 4:
                    ip_bytes = ipaddress.ip_address(ip).packed
                    ip_int = int.from_bytes(ip_bytes, byteorder='big')
                    self.bpf["blocked_ipv4"][ctypes.c_uint32(ip_int)] = ctypes.c_uint8(1)
                else:
                    addr = ipaddress.ip_address(ip)
                    # For IPv6, we need to use a different approach with bcc
                    # This is a simplified version - full implementation requires custom BPF map handling
                    logger.warning(f"XDP IPv6 blocking requires custom BPF map handling for {ip}")
                    return False
                logger.info(f"XDP: Blocked {ip}")
                return True
        except Exception as e:
            logger.error(f"XDP: Failed to block {ip}: {e}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Remove IP from XDP block list."""
        if not self.bpf:
            return False

        try:
            import ctypes
            with self._lock:
                if ipaddress.ip_address(ip).version == 4:
                    ip_bytes = ipaddress.ip_address(ip).packed
                    ip_int = int.from_bytes(ip_bytes, byteorder='big')
                    if ctypes.c_uint32(ip_int) in self.bpf["blocked_ipv4"]:
                        del self.bpf["blocked_ipv4"][ctypes.c_uint32(ip_int)]
                else:
                    logger.warning(f"XDP IPv6 unblocking requires custom BPF map handling for {ip}")
                    return False
                logger.info(f"XDP: Unblocked {ip}")
                return True
        except Exception as e:
            logger.error(f"XDP: Failed to unblock {ip}: {e}")
            return False

    def get_stats(self) -> Dict[str, int]:
        """Get XDP drop statistics."""
        if not self.bpf:
            return {"packets_dropped": 0, "bytes_dropped": 0}

        try:
            stats_map = self.bpf["stats"]
            for k, v in stats_map.items():
                return {"packets_dropped": v.value, "bytes_dropped": v.value * 1500}  # Approximate
            return {"packets_dropped": 0, "bytes_dropped": 0}
        except Exception:
            return {"packets_dropped": 0, "bytes_dropped": 0}


class EbpfManager:
    """
    Manages eBPF/XDP-based packet filtering with iptables fallback.

    Usage:
        manager = EbpfManager(interface="eth0", use_xdp=True)
        manager.initialize()
        manager.block_ip("192.168.1.100")
    """

    def __init__(
        self,
        interface: str = "",
        use_xdp: bool = True,
        fallback_to_iptables: bool = True,
    ):
        self.interface = interface
        self.use_xdp = use_xdp
        self.fallback_to_iptables = fallback_to_iptables
        self.xdp_program = None
        self.use_iptables_fallback = False
        self._lock = threading.RLock()
        self._blocked_ips: Dict[str, Dict[str, Any]] = {}
        self._stats = {"packets_dropped": 0, "bytes_dropped": 0, "blocks_added": 0, "blocks_removed": 0}

    def initialize(self) -> bool:
        """Initialize eBPF/XDP or fall back to iptables."""
        if self.use_xdp and BCC_AVAILABLE:
            self.xdp_program = XDPProgram(self.interface)
            if self.xdp_program.load():
                logger.info("eBPF/XDP initialized successfully")
                self._restore_blocks()
                return True
            else:
                logger.warning("XDP program failed to load")

        if self.fallback_to_iptables:
            logger.info("Falling back to iptables for packet filtering")
            self.use_iptables_fallback = True
            from core.mitigation_agent import FirewallManager
            FirewallManager.init_firewall()
            self._restore_blocks()
            return True

        logger.error("No packet filtering method available")
        return False

    def shutdown(self):
        """Clean up eBPF/XDP resources."""
        if self.xdp_program:
            self.xdp_program.unload()
        logger.info("eBPF/XDP manager shut down")

    def block_ip(self, ip: str, reason: str = "eBPF block") -> bool:
        """Block an IP using XDP or iptables fallback."""
        with self._lock:
            now = datetime.now()
            self._blocked_ips[ip] = {
                "reason": reason,
                "timestamp": now,
            }
            self._stats["blocks_added"] += 1
            self._save_blocks()

        if self.xdp_program and self.xdp_program.attached:
            return self.xdp_program.block_ip(ip)
        elif self.use_iptables_fallback:
            from core.mitigation_agent import FirewallManager
            return FirewallManager.block_ip(ip)

        logger.warning(f"No filtering method available to block {ip}")
        return False

    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP."""
        with self._lock:
            if ip in self._blocked_ips:
                del self._blocked_ips[ip]
                self._stats["blocks_removed"] += 1
                self._save_blocks()
            else:
                return False

        if self.xdp_program and self.xdp_program.attached:
            return self.xdp_program.unblock_ip(ip)
        elif self.use_iptables_fallback:
            from core.mitigation_agent import FirewallManager
            return FirewallManager.unblock_ip(ip)

        return False

    def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked."""
        with self._lock:
            return ip in self._blocked_ips

    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """Get list of blocked IPs."""
        with self._lock:
            return [
                {"ip": ip, "reason": info["reason"], "timestamp": info["timestamp"].isoformat()}
                for ip, info in self._blocked_ips.items()
            ]

    def get_stats(self) -> Dict[str, Any]:
        """Get eBPF/XDP statistics."""
        xdp_stats = self.xdp_program.get_stats() if self.xdp_program else {"packets_dropped": 0, "bytes_dropped": 0}
        return {
            **self._stats,
            "xdp_packets_dropped": xdp_stats["packets_dropped"],
            "xdp_bytes_dropped": xdp_stats["bytes_dropped"],
            "use_xdp": self.xdp_program is not None and self.xdp_program.attached,
            "use_iptables_fallback": self.use_iptables_fallback,
            "interface": self.interface,
            "bcc_available": BCC_AVAILABLE,
        }

    def _save_blocks(self):
        """Persist blocked IPs to disk."""
        try:
            data = {
                ip: {
                    "reason": info["reason"],
                    "timestamp": info["timestamp"].isoformat(),
                }
                for ip, info in self._blocked_ips.items()
            }
            EBPF_BLOCKS_FILE.parent.mkdir(parents=True, exist_ok=True)
            EBPF_BLOCKS_FILE.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.error(f"Failed to save eBPF blocks: {e}")

    def _restore_blocks(self):
        """Restore blocked IPs from disk."""
        if not EBPF_BLOCKS_FILE.exists():
            return
        try:
            data = json.loads(EBPF_BLOCKS_FILE.read_text())
            for ip, info in data.items():
                self._blocked_ips[ip] = {
                    "reason": info["reason"],
                    "timestamp": datetime.fromisoformat(info["timestamp"]),
                }
                if self.xdp_program and self.xdp_program.attached:
                    self.xdp_program.block_ip(ip)
                elif self.use_iptables_fallback:
                    from core.mitigation_agent import FirewallManager
                    FirewallManager.block_ip(ip)
            logger.info(f"eBPF: Restored {len(self._blocked_ips)} blocked IPs")
        except Exception as e:
            logger.error(f"Failed to restore eBPF blocks: {e}")
