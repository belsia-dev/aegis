import asyncio
import hashlib
import os
from pathlib import Path
from typing import Dict, List, Optional, Set
from core.config import Config
from core.logger import get_logger
from detection.engine import DetectionEngine
logger = get_logger("persist_monitor")
try:
    import inotify_simple
    INOTIFY_AVAILABLE = True
except ImportError:
    INOTIFY_AVAILABLE = False

def _sha256(path: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError): return None

class PersistenceMonitor:
    def __init__(self, config: Config, engine: DetectionEngine):
        self._config   = config
        self._engine   = engine
        self._enabled  = config.persistence_monitor("enabled", True)
        self._interval = int(config.persistence_monitor("scan_interval", 30))
        self._watch_dirs: List[str] = (
            (config.persistence_monitor("watch_cron_dirs", []) or []) +
            (config.persistence_monitor("watch_systemd_dirs", []) or [])
        )
        self._watch_files: List[str] = config.persistence_monitor("watch_startup_files", []) or []
        self._baseline: Dict[str, Optional[str]] = {}
        self._known_files: Set[str] = set()

    async def run(self):
        if not self._enabled:
            logger.info("Persistence monitor disabled"); return
        logger.info("Persistence monitor started")
        self._build_baseline()
        if INOTIFY_AVAILABLE:
            await self._inotify_watch()
        else:
            await self._poll_loop()

    def _build_baseline(self):
        self._baseline = {}
        self._known_files = set()
        for dir_path in self._watch_dirs:
            p = Path(dir_path)
            if p.is_dir():
                for child in p.rglob("*"):
                    if child.is_file():
                        key = str(child)
                        self._baseline[key] = _sha256(child)
                        self._known_files.add(key)
        for file_path in self._watch_files:
            p = Path(file_path)
            if p.is_file():
                key = str(p)
                self._baseline[key] = _sha256(p)
                self._known_files.add(key)
            elif p.is_dir():
                for child in p.rglob("*"):
                    if child.is_file():
                        key = str(child)
                        self._baseline[key] = _sha256(child)
                        self._known_files.add(key)
        logger.info("Baseline built", extra={"files": len(self._known_files)})

    async def _inotify_watch(self):
        inotify = inotify_simple.INotify()
        flags = (inotify_simple.flags.CREATE | inotify_simple.flags.MODIFY |
                 inotify_simple.flags.MOVED_TO | inotify_simple.flags.DELETE)
        wd_map: Dict[int, str] = {}
        def _add_watch(dir_path: str):
            p = Path(dir_path)
            if p.is_dir():
                wd = inotify.add_watch(str(p), flags)
                wd_map[wd] = str(p)
        for d in self._watch_dirs: _add_watch(d)
        parents: Set[str] = set()
        for f in self._watch_files:
            p = Path(f)
            parents.add(str(p.parent if p.is_file() else p))
        for parent in parents: _add_watch(parent)
        loop = asyncio.get_running_loop()
        logger.info("inotify persistence watch active", extra={"watchers": len(wd_map)})
        while True:
            events = await loop.run_in_executor(None, lambda: inotify.read(timeout=60000))
            for ev in events:
                dir_path  = wd_map.get(ev.wd, "")
                file_path = os.path.join(dir_path, ev.name) if ev.name else dir_path
                await self._check_file_event(file_path, ev)

    async def _poll_loop(self):
        while True:
            await asyncio.sleep(self._interval)
            try:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, self._poll_sync)
            except Exception as exc:
                logger.error("Persistence poll error", extra={"error": str(exc)})

    def _poll_sync(self):
        current_files: Set[str] = set()
        def _scan_dir(d):
            p = Path(d)
            if not p.is_dir(): return
            for child in p.rglob("*"):
                if child.is_file(): current_files.add(str(child))
        for d in self._watch_dirs: _scan_dir(d)
        for f in self._watch_files:
            p = Path(f)
            if p.is_file(): current_files.add(str(p))
            elif p.is_dir(): _scan_dir(f)
        for fp in current_files - self._known_files:
            asyncio.ensure_future(self._engine.emit_system_alert(
                "persistence_new_file", path=fp, reason="New file in watched directory"))
            self._known_files.add(fp)
            self._baseline[fp] = _sha256(Path(fp))
        for fp in current_files & self._known_files:
            new_hash = _sha256(Path(fp))
            if new_hash and new_hash != self._baseline.get(fp):
                asyncio.ensure_future(self._engine.emit_system_alert(
                    "persistence_modified_file", path=fp, reason="Watched file modified"))
                self._baseline[fp] = new_hash

    async def _check_file_event(self, file_path: str, ev):
        in_watched = (
            any(file_path.startswith(d.rstrip("/") + "/") for d in self._watch_dirs) or
            file_path in self._watch_files or
            any(file_path.startswith(str(Path(f).parent) + "/") for f in self._watch_files)
        )
        if not in_watched: return
        is_new = any(name in str(ev.mask) for name in ("CREATE", "MOVED_TO"))
        await self._engine.emit_system_alert(
            "persistence_new_file" if is_new else "persistence_modified_file",
            path=file_path, reason="New/modified file in persistence watchlist")
