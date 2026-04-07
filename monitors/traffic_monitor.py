import asyncio
import socket
import struct
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.config import Config
from core.logger import get_logger
from detection.engine import DetectionEngine

logger = get_logger("traffic")

_TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT",  "03": "SYN_RECV",
    "04": "FIN_WAIT1",   "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE",       "08": "CLOSE_WAIT","09": "LAST_ACK",
    "0A": "LISTEN",      "0B": "CLOSING",
}

_SUSPICIOUS_PORTS = {
    1337, 4444, 4445, 5555, 6666, 6667, 6668, 6669,
    7777, 8888, 9999, 31337,
    3333, 4444, 5555, 7777, 8888, 9999,
    14444, 14433, 45700,
    1080, 9050, 9150,
}

def _hex_to_ip4(hex_str: str) -> str:
    try:
        return socket.inet_ntoa(struct.pack("<I", int(hex_str, 16)))
    except Exception:
        return "?"

def _hex_to_ip6(hex_str: str) -> str:
    try:
        parts = [hex_str[i:i+8] for i in range(0, 32, 8)]
        raw = b"".join(struct.pack("<I", int(p, 16)) for p in parts)
        return socket.inet_ntop(socket.AF_INET6, raw)
    except Exception:
        return "?"

def _parse_addr4(hex_addr: str) -> Tuple[str, int]:
    ip_hex, port_hex = hex_addr.split(":")
    return _hex_to_ip4(ip_hex), int(port_hex, 16)

def _parse_addr6(hex_addr: str) -> Tuple[str, int]:
    ip_hex, port_hex = hex_addr.split(":")
    return _hex_to_ip6(ip_hex), int(port_hex, 16)

def _is_local(ip: str) -> bool:
    return ip.startswith(("127.", "10.", "192.168.", "::1", "fe80")) or ip == "0.0.0.0"

class TrafficMonitor:

    HISTORY_POINTS = 60

    def __init__(self, config: Config, detection: DetectionEngine):
        self._config    = config
        self._detection = detection
        self._interval  = float(config.detection("traffic_poll_interval", 2.0))

        self._prev_iface: Dict[str, Tuple[int, int, float]] = {}
        self._bandwidth:  Dict[str, Tuple[float, float]]    = {}
        self._history:    List[dict] = []

        self._connections: List[dict] = []
        self._prev_conn_keys: set     = set()

        self._suspicious: List[dict] = []

    async def run(self):
        logger.info("Traffic monitor started",
                    extra={"interval": self._interval})
        loop = asyncio.get_event_loop()
        while True:
            try:
                await loop.run_in_executor(None, self._poll)
            except Exception as exc:
                logger.error("Traffic poll error", extra={"error": str(exc)})
            await asyncio.sleep(self._interval)

    def _poll(self):
        self._update_bandwidth()
        self._update_connections()

    def _update_bandwidth(self):
        try:
            now   = time.time()
            lines = Path("/proc/net/dev").read_text().splitlines()[2:]
            total_rx = total_tx = 0.0

            for line in lines:
                parts = line.split()
                if len(parts) < 10:
                    continue
                iface   = parts[0].rstrip(":")
                if iface == "lo":
                    continue
                rx_bytes = int(parts[1])
                tx_bytes = int(parts[9])

                if iface in self._prev_iface:
                    prev_rx, prev_tx, prev_ts = self._prev_iface[iface]
                    dt = now - prev_ts
                    if dt > 0:
                        rx_bps = max(0.0, (rx_bytes - prev_rx) / dt)
                        tx_bps = max(0.0, (tx_bytes - prev_tx) / dt)
                        self._bandwidth[iface] = (rx_bps, tx_bps)
                        total_rx += rx_bps
                        total_tx += tx_bps

                self._prev_iface[iface] = (rx_bytes, tx_bytes, now)

            self._history.append({"ts": now, "rx": total_rx, "tx": total_tx})
            if len(self._history) > self.HISTORY_POINTS:
                self._history.pop(0)

        except Exception as exc:
            logger.debug("Bandwidth read error", extra={"error": str(exc)})

    def _update_connections(self):
        conns: List[dict] = []
        new_keys: set     = set()

        for path, parser, proto in (
            ("/proc/net/tcp",  _parse_addr4, "TCP"),
            ("/proc/net/tcp6", _parse_addr6, "TCP6"),
            ("/proc/net/udp",  _parse_addr4, "UDP"),
            ("/proc/net/udp6", _parse_addr6, "UDP6"),
        ):
            try:
                lines = Path(path).read_text().splitlines()[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    local_ip,  local_port  = parser(parts[1])
                    remote_ip, remote_port = parser(parts[2])
                    state_hex = parts[3].upper()
                    state = _TCP_STATES.get(state_hex, state_hex)

                    if remote_ip in ("0.0.0.0", "::", "?") and remote_port == 0:
                        continue

                    entry = {
                        "local":       f"{local_ip}:{local_port}",
                        "remote":      f"{remote_ip}:{remote_port}",
                        "remote_ip":   remote_ip,
                        "remote_port": remote_port,
                        "state":       state,
                        "proto":       proto,
                        "suspicious":  remote_port in _SUSPICIOUS_PORTS and not _is_local(remote_ip),
                    }
                    conns.append(entry)

                    key = f"{proto}:{local_ip}:{local_port}:{remote_ip}:{remote_port}"
                    new_keys.add(key)

                    if entry["suspicious"] and key not in self._prev_conn_keys:
                        self._suspicious.insert(0, {
                            **entry,
                            "ts":  time.time(),
                            "new": True,
                        })
                        if len(self._suspicious) > 200:
                            self._suspicious.pop()
                        logger.warning(
                            "Suspicious outbound connection",
                            extra={"remote": entry["remote"], "port": remote_port, "proto": proto},
                        )
                        asyncio.ensure_future(
                            self._detection.emit_system_alert(
                                "suspicious_outbound",
                                ip=remote_ip,
                                detail=f"{proto} → {remote_ip}:{remote_port}",
                            )
                        )

            except Exception as exc:
                logger.debug("Connection read error",
                             extra={"path": path, "error": str(exc)})

        self._connections   = conns
        self._prev_conn_keys = new_keys

    def get_bandwidth(self) -> dict:
        return {
            iface: {"rx_bps": round(rx, 1), "tx_bps": round(tx, 1)}
            for iface, (rx, tx) in self._bandwidth.items()
        }

    def get_connections(self, limit: int = 200) -> list:
        return self._connections[:limit]

    def get_history(self) -> list:
        return self._history

    def get_suspicious(self, limit: int = 50) -> list:
        return self._suspicious[:limit]

    def get_top_remote_ips(self, n: int = 10) -> list:
        counts: Dict[str, int] = defaultdict(int)
        for c in self._connections:
            ip = c["remote_ip"]
            if not _is_local(ip) and ip != "?":
                counts[ip] += 1
        return sorted(
            [{"ip": ip, "connections": cnt} for ip, cnt in counts.items()],
            key=lambda x: x["connections"], reverse=True,
        )[:n]

    def get_stats(self) -> dict:
        established = sum(1 for c in self._connections if c["state"] == "ESTABLISHED")
        outbound    = sum(1 for c in self._connections if not _is_local(c["remote_ip"]))
        suspicious  = sum(1 for c in self._connections if c.get("suspicious"))
        total_rx    = sum(v[0] for v in self._bandwidth.values())
        total_tx    = sum(v[1] for v in self._bandwidth.values())
        return {
            "total_connections":   len(self._connections),
            "established":         established,
            "outbound":            outbound,
            "suspicious_active":   suspicious,
            "total_rx_bps":        round(total_rx, 1),
            "total_tx_bps":        round(total_tx, 1),
        }
