import asyncio
import os
from pathlib import Path
from typing import Dict, List
from core.config import Config
from core.logger import get_logger
from detection.engine import DetectionEngine
logger = get_logger("log_monitor")
try:
    import inotify_simple
    INOTIFY_AVAILABLE = True
except ImportError:
    INOTIFY_AVAILABLE = False
    logger.warning("inotify_simple not installed — using async polling fallback")

_BATCH_SIZE    = 64
_POLL_INTERVAL = 0.25

class LogMonitor:
    def __init__(self, config: Config, engine: DetectionEngine):
        self._config  = config
        self._engine  = engine
        self._sources: Dict[str, str] = {
            src["path"]: src["type"]
            for src in config.log_sources
            if src.get("path") and src.get("type")
        }

    async def run(self):
        tasks = [
            asyncio.create_task(self._tail(path, log_type), name=f"tail:{Path(path).name}")
            for path, log_type in self._sources.items()
        ]
        if not tasks:
            logger.warning("No log sources configured")
            return
        logger.info("Log monitor started", extra={"sources": len(tasks)})
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _tail(self, path: str, log_type: str):
        while True:
            try:
                await self._tail_once(path, log_type)
            except FileNotFoundError:
                logger.debug("Waiting for log file", extra={"path": path})
                await asyncio.sleep(5)
            except Exception as exc:
                logger.error("Tail error", extra={"path": path, "error": str(exc)})
                await asyncio.sleep(5)

    async def _tail_once(self, path: str, log_type: str):
        p = Path(path)
        if not p.exists(): raise FileNotFoundError(path)
        logger.info("Tailing log", extra={"path": path, "type": log_type})
        with p.open("r", errors="replace") as fh:
            fh.seek(0, 2)
            inode = p.stat().st_ino
            if INOTIFY_AVAILABLE:
                await self._inotify_loop(fh, p, log_type, inode)
            else:
                await self._poll_loop(fh, p, log_type, inode)

    async def _inotify_loop(self, fh, path: Path, log_type: str, start_inode: int):
        inotify = inotify_simple.INotify()
        wd = inotify.add_watch(str(path.parent),
            inotify_simple.flags.MODIFY | inotify_simple.flags.MOVED_TO | inotify_simple.flags.CREATE)
        loop = asyncio.get_running_loop()
        try:
            while True:
                await loop.run_in_executor(None, lambda: inotify.read(timeout=5000))
                try:
                    if path.stat().st_ino != start_inode:
                        logger.info("Log rotated, reopening", extra={"path": str(path)})
                        return
                except FileNotFoundError: return
                lines = self._read_lines(fh)
                self._dispatch(lines, log_type)
        finally:
            try: inotify.rm_watch(wd)
            except Exception: pass

    async def _poll_loop(self, fh, path: Path, log_type: str, start_inode: int):
        while True:
            await asyncio.sleep(_POLL_INTERVAL)
            try:
                if path.stat().st_ino != start_inode: return
            except FileNotFoundError: return
            lines = self._read_lines(fh)
            if lines: self._dispatch(lines, log_type)

    @staticmethod
    def _read_lines(fh) -> List[str]:
        lines = []
        for _ in range(4096):
            line = fh.readline()
            if not line: break
            line = line.rstrip("\n")
            if line: lines.append(line)
        return lines

    def _dispatch(self, lines: List[str], log_type: str):
        for line in lines:
            self._engine.process_line(line, log_type)
