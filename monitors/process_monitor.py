import asyncio
import os
from pathlib import Path
from typing import Set
from core.config import Config
from core.logger import get_logger
from detection.engine import DetectionEngine
logger = get_logger("proc_monitor")
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not installed — using /proc fallback")

_KNOWN_SAFE_PREFIXES = {
    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
    "/lib/", "/usr/lib/", "/usr/local/bin/", "/usr/local/sbin/", "/opt/",
}

def _is_suspicious_path(exe: str, suspicious_paths: list) -> bool:
    return any(exe.startswith(p.rstrip("/") + "/") or exe == p for p in suspicious_paths)

class ProcessMonitor:
    def __init__(self, config: Config, engine: DetectionEngine):
        self._config   = config
        self._engine   = engine
        self._enabled  = config.process_monitor("enabled", True)
        self._interval = int(config.process_monitor("scan_interval", 15))
        self._suspicious_paths = config.process_monitor("suspicious_exec_paths", ["/tmp","/var/tmp","/dev/shm"])
        self._suspicious_ports = set(config.process_monitor("suspicious_outbound_ports", [4444,1337,9999,31337]))
        self._seen_pids:  Set[int] = set()
        self._seen_ports: Set[int] = set()

    async def run(self):
        if not self._enabled:
            logger.info("Process monitor disabled"); return
        logger.info("Process monitor started", extra={"interval": self._interval})
        await self._scan()
        while True:
            await asyncio.sleep(self._interval)
            try:
                await self._scan()
            except Exception as exc:
                logger.error("Process scan error", extra={"error": str(exc)})

    async def _scan(self):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._scan_sync)

    def _scan_sync(self):
        if PSUTIL_AVAILABLE: self._scan_with_psutil()
        else:                self._scan_with_proc()

    def _scan_with_psutil(self):
        for proc in psutil.process_iter(["pid", "exe", "username", "connections"]):
            try:
                info = proc.info
                pid  = info["pid"]
                exe  = info.get("exe") or ""
                user = info.get("username") or ""
                if exe and _is_suspicious_path(exe, self._suspicious_paths):
                    if pid not in self._seen_pids:
                        self._seen_pids.add(pid)
                        asyncio.ensure_future(self._engine.emit_system_alert(
                            "suspicious_exec", path=exe, pid=pid, user=user))
                if user == "root" and exe:
                    if not any(exe.startswith(p) for p in _KNOWN_SAFE_PREFIXES):
                        if pid not in self._seen_pids:
                            self._seen_pids.add(pid)
                            asyncio.ensure_future(self._engine.emit_system_alert(
                                "unknown_root_process", path=exe, pid=pid))
                for conn in (info.get("connections") or []):
                    if conn.status == "ESTABLISHED" and conn.raddr:
                        if conn.raddr.port in self._suspicious_ports:
                            asyncio.ensure_future(self._engine.emit_system_alert(
                                "suspicious_outbound", pid=pid, exe=exe,
                                remote_ip=conn.raddr.ip, remote_port=conn.raddr.port))
            except (psutil.NoSuchProcess, psutil.AccessDenied): pass
        self._check_listeners_psutil()

    def _check_listeners_psutil(self):
        current: Set[int] = set()
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN" and conn.laddr:
                current.add(conn.laddr.port)
        new_ports = current - self._seen_ports
        if new_ports and self._seen_ports:
            for port in new_ports:
                asyncio.ensure_future(self._engine.emit_system_alert("new_listener", port=port))
        self._seen_ports = current

    def _scan_with_proc(self):
        proc_dir = Path("/proc")
        if not proc_dir.exists(): return
        for pid_dir in proc_dir.iterdir():
            if not pid_dir.name.isdigit(): continue
            pid = int(pid_dir.name)
            try:
                exe_link = pid_dir / "exe"
                if not exe_link.exists(): continue
                exe = str(exe_link.resolve())
                if _is_suspicious_path(exe, self._suspicious_paths):
                    if pid not in self._seen_pids:
                        self._seen_pids.add(pid)
                        cmdline = ""
                        try:
                            cmdline = (pid_dir / "cmdline").read_bytes().replace(b"\x00", b" ").decode()[:200]
                        except Exception: pass
                        asyncio.ensure_future(self._engine.emit_system_alert(
                            "suspicious_exec", path=exe, pid=pid, cmdline=cmdline))
            except (PermissionError, FileNotFoundError, OSError): pass
