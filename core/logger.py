import json
import logging
import sys
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Optional

class _JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        doc = {
            "ts":     datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "level":  record.levelname,
            "module": record.name,
            "msg":    record.getMessage(),
        }
        for key in ("ip", "subnet", "reason", "action", "score", "country",
                    "pid", "path", "rule", "ban_until", "event_type"):
            val = record.__dict__.get(key)
            if val is not None:
                doc[key] = val
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)
        return json.dumps(doc, default=str)

class _AuditLogger:
    def __init__(self, path: str):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
    def write(self, event: dict):
        event.setdefault("ts", datetime.now(timezone.utc).isoformat(timespec="seconds"))
        with self._path.open("a") as fh:
            fh.write(json.dumps(event, default=str) + "\n")

_audit: Optional[_AuditLogger] = None

def init_logging(log_file: str, audit_file: str, level: str = "INFO"):
    global _audit
    _audit = _AuditLogger(audit_file)
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(getattr(logging, level, logging.INFO))
    fmt = _JSONFormatter()
    fh = logging.FileHandler(log_path)
    fh.setFormatter(fmt)
    root.addHandler(fh)
    sh = logging.StreamHandler(sys.stderr)
    sh.setFormatter(fmt)
    root.addHandler(sh)

@lru_cache(maxsize=128)
def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"aegis.{name}")

def audit(event_type: str, **kwargs):
    if _audit:
        _audit.write({"event": event_type, **kwargs})
    else:
        logging.getLogger("aegis.audit").info(
            json.dumps({"event": event_type, **kwargs}, default=str)
        )
