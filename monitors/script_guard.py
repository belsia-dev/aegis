import asyncio
import os
import signal
import time
from pathlib import Path
from typing import Dict, Optional, Set

from core.config import Config
from core.logger import get_logger, audit
from detection.engine import DetectionEngine
from detection.script_analyzer import ScriptAnalyzer, AnalysisResult

logger = get_logger("script_guard")

_WATCHED_NAMES = {"bash", "sh", "dash", "python", "python3", "python2", "perl"}
_PIPE_PARENTS  = {"curl", "wget", "fetch", "aria2c"}

_MAX_RESULTS = 500

def _read_proc_str(path: str) -> str:
    try:
        return Path(path).read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    except Exception:
        return ""

def _proc_name(pid: int) -> str:
    return _read_proc_str(f"/proc/{pid}/comm")

def _proc_cmdline(pid: int) -> str:
    return _read_proc_str(f"/proc/{pid}/cmdline")

def _parent_pid(pid: int) -> Optional[int]:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()

        parts = stat.split(")")[-1].split()
        return int(parts[1])
    except Exception:
        return None

def _stdin_is_pipe(pid: int) -> bool:

    try:
        fd0 = Path(f"/proc/{pid}/fd/0")
        if fd0.is_symlink():
            target = os.readlink(str(fd0))
            return "pipe:" in target
        return False
    except Exception:
        return False

def _read_stdin_script(pid: int, max_bytes: int = 512 * 1024) -> str:

    try:
        fd_path = f"/proc/{pid}/fd/0"
        with open(fd_path, "rb") as fh:
            return fh.read(max_bytes).decode("utf-8", errors="replace")
    except Exception:
        return ""

class ScriptGuard:

    def __init__(self, config: Config, detection: DetectionEngine):
        self._config    = config
        self._detection = detection
        self._analyzer  = ScriptAnalyzer()
        self._interval  = float(config.detection("script_guard_interval", 0.5))
        self._enabled   = bool(config.detection("script_guard_enabled", True))
        self._block     = bool(config.detection("script_guard_block", True))

        self._seen_pids: Set[int] = set()
        self._results:   list    = []

    async def run(self):
        if not self._enabled:
            logger.info("Script guard disabled in config")
            return
        logger.info("Script guard started",
                    extra={"interval": self._interval, "block": self._block})
        loop = asyncio.get_event_loop()
        while True:
            try:
                new_pids = await loop.run_in_executor(None, self._scan_procs)
                for pid in new_pids:
                    asyncio.ensure_future(self._inspect(pid))
            except Exception as exc:
                logger.error("Script guard scan error", extra={"error": str(exc)})
            await asyncio.sleep(self._interval)

    def _scan_procs(self) -> list:

        new_interesting = []
        try:
            current_pids = {int(p.name) for p in Path("/proc").iterdir()
                            if p.name.isdigit()}
        except Exception:
            return []

        fresh = current_pids - self._seen_pids
        self._seen_pids = current_pids

        for pid in fresh:
            try:
                name = _proc_name(pid)
                if name not in _WATCHED_NAMES:
                    continue

                if not _stdin_is_pipe(pid):
                    continue

                ppid   = _parent_pid(pid)
                parent = _proc_name(ppid) if ppid else ""
                if parent not in _PIPE_PARENTS and not _stdin_is_pipe(pid):
                    continue
                new_interesting.append(pid)
            except Exception:
                pass

        return new_interesting

    async def _inspect(self, pid: int):
        loop = asyncio.get_event_loop()

        if self._block:
            try:
                os.kill(pid, signal.SIGSTOP)
            except ProcessLookupError:
                return
            except PermissionError:
                logger.warning("Script guard: no permission to SIGSTOP",
                               extra={"pid": pid})

        script = await loop.run_in_executor(None, _read_stdin_script, pid)

        cmdline = _proc_cmdline(pid)
        ppid    = _parent_pid(pid)
        parent  = _proc_name(ppid) if ppid else "?"

        source = f"pipe from {parent} (pid {pid})"

        result: AnalysisResult = await loop.run_in_executor(
            None, self._analyzer.analyze, script or cmdline, source
        )

        rd = result.to_dict()
        rd["pid"]    = pid
        rd["parent"] = parent
        self._results.insert(0, rd)
        if len(self._results) > _MAX_RESULTS:
            self._results.pop()

        if not result.safe:
            logger.warning(
                "Unsafe script intercepted",
                extra={
                    "pid":      pid,
                    "parent":   parent,
                    "score":    result.score,
                    "findings": len(result.findings),
                    "sha256":   result.sha256,
                },
            )
            audit("script_blocked",
                  pid=pid, parent=parent,
                  score=result.score, sha256=result.sha256,
                  findings=[f["category"] for f in result.findings[:5]])

            asyncio.ensure_future(
                self._detection.emit_system_alert(
                    "script_blocked",
                    detail=f"Unsafe script from {parent} blocked (score {result.score})",
                    score=result.score,
                    sha256=result.sha256,
                )
            )

            if self._block:
                logger.info("Script process left SIGSTOP'd (blocked)",
                            extra={"pid": pid})

                await asyncio.sleep(2)
                try:
                    os.kill(pid, signal.SIGKILL)
                except Exception:
                    pass
        else:
            logger.info("Script analyzed — safe",
                        extra={"pid": pid, "parent": parent, "score": result.score})
            audit("script_allowed",
                  pid=pid, parent=parent,
                  score=result.score, sha256=result.sha256)

            if self._block:
                try:
                    os.kill(pid, signal.SIGCONT)
                except Exception:
                    pass

    def recent_results(self, limit: int = 50) -> list:
        return self._results[:limit]
