import signal
import threading
from pathlib import Path
from typing import Any, List, Optional
import yaml

class Config:
    def __init__(self, path: str):
        self._path = Path(path)
        self._lock = threading.RLock()
        self._data: dict = {}
        self._load()
        try:
            signal.signal(signal.SIGHUP, self._sighup_handler)
        except (AttributeError, OSError):
            pass

    def _load(self):
        with self._path.open() as fh:
            data = yaml.safe_load(fh)
        with self._lock:
            self._data = data or {}

    def _sighup_handler(self, *_):
        self._load()

    def _get(self, *keys, default=None) -> Any:
        with self._lock:
            node = self._data
            for k in keys:
                if not isinstance(node, dict):
                    return default
                node = node.get(k, default)
                if node is None:
                    return default
            return node

    @property
    def log_level(self) -> str:
        return self._get("general", "log_level", default="INFO").upper()

    @property
    def log_file(self) -> str:
        return self._get("general", "log_file", default="/var/log/aegis/aegis.json")

    @property
    def audit_file(self) -> str:
        return self._get("general", "audit_file", default="/var/log/aegis/audit.json")

    @property
    def dry_run(self) -> bool:
        import os
        return bool(self._get("general", "dry_run", default=False)) or bool(os.environ.get("AEGIS_DRY_RUN"))

    @property
    def log_sources(self) -> List[dict]:
        return self._get("log_sources", default=[])

    def general(self, key: str, default=None):
        return self._get("general", key, default=default)

    def detection(self, key: str, default=None):
        return self._get("detection", key, default=default)

    @property
    def adaptive_enabled(self) -> bool:
        return bool(self.detection("adaptive_enabled", default=True))

    def response(self, key: str, default=None):
        return self._get("response", key, default=default)

    @property
    def firewall_backend(self) -> str:
        return self.response("firewall_backend", default="iptables")

    @property
    def ban_duration(self) -> int:
        return int(self.response("ban_duration_seconds", default=3600))

    @property
    def privilege_mode(self) -> str:
        return self.response("privilege_mode", default="direct")

    @property
    def whitelist_ips(self) -> List[str]:
        return self._get("whitelist", "ips", default=[]) or []

    @property
    def whitelist_cidrs(self) -> List[str]:
        return self._get("whitelist", "cidrs", default=[]) or []

    @property
    def protect_self(self) -> bool:
        return bool(self._get("whitelist", "protect_self", default=True))

    def process_monitor(self, key: str, default=None):
        return self._get("process_monitor", key, default=default)

    def persistence_monitor(self, key: str, default=None):
        return self._get("persistence_monitor", key, default=default)

    def abuseipdb(self, key: str, default=None):
        return self._get("integrations", "abuseipdb", key, default=default)

    def ipinfo(self, key: str, default=None):
        return self._get("integrations", "ipinfo", key, default=default)

    def api(self, key: str, default=None):
        return self._get("api", key, default=default)
