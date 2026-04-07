import asyncio
import json
import os
import time
from collections import deque
from pathlib import Path
from typing import Callable, Deque, Dict, List, Optional

from core.config import Config
from core.logger import get_logger, audit
from core.whitelist import Whitelist
from detection.patterns import PATTERNS_BY_TYPE, LogPattern
from detection.scoring import ScoringEngine

logger = get_logger("engine")

_DEFAULT_EVENT_LOG  = "/var/log/aegis/events.jsonl"
_DEFAULT_MAX_MB     = 50
_WRITE_BATCH        = 20
_PRELOAD_LINES      = 2000

class Alert:
    __slots__ = (
        "ts", "event_type", "ip", "user", "score", "severity",
        "country", "abuse_score", "log_type", "raw_line",
        "is_hosting", "ipinfo_org", "ipinfo_city",
    )
    def __init__(self, **kw):
        for s in self.__slots__: setattr(self, s, kw.get(s))
        if self.ts is None: self.ts = time.time()
    def to_dict(self) -> dict: return {s: getattr(self, s) for s in self.__slots__}

class DetectionEngine:
    def __init__(self, config: Config, abuseipdb, ipinfo):
        self._config    = config
        self._abuseipdb = abuseipdb
        self._ipinfo    = ipinfo
        self._scoring   = ScoringEngine(config)
        self._whitelist = Whitelist(config)
        self._response_cb: Optional[Callable] = None

        buf_size = config.api("event_buffer_size", 500)
        self._event_buffer: Deque[dict] = deque(maxlen=buf_size)
        self._banned_ips: set = set()
        self._sse_queues: List[asyncio.Queue] = []
        self._warn_threshold = config.detection("score_warn_threshold", 40)
        self._ban_threshold  = config.detection("score_ban_threshold", 70)

        try:
            self._event_log_path = Path(
                config.general("event_log_path", _DEFAULT_EVENT_LOG)
            )
        except Exception:
            self._event_log_path = Path(_DEFAULT_EVENT_LOG)

        self._event_log_max_bytes = int(
            config.detection("event_log_max_mb", _DEFAULT_MAX_MB)
        ) * 1024 * 1024

        self._write_queue: List[dict] = []
        self._load_events()

    def process_line(self, line: str, log_type: str):
        patterns: List[LogPattern] = PATTERNS_BY_TYPE.get(log_type, [])
        for pat in patterns:
            m = pat.pattern.search(line)
            if not m: continue
            fields = {}
            try: fields = pat.extract(m)
            except Exception: pass
            ip   = fields.get("ip")
            user = fields.get("user")
            if ip and self._whitelist.is_whitelisted(ip): return
            score = self._scoring.record_event(
                ip or "__no_ip__", pat.name, pat.severity, user=user
            )
            alert = Alert(
                event_type=pat.name, ip=ip, user=user, score=int(score),
                severity=pat.severity, log_type=log_type, raw_line=line[:300],
            )
            self._push_event(alert.to_dict())
            if ip and ip not in self._banned_ips:
                if score >= self._ban_threshold:
                    asyncio.ensure_future(self._async_ban_pipeline(ip, alert))
                elif score >= self._warn_threshold:
                    logger.warning("Threat warning",
                        extra={"ip": ip, "score": int(score), "event_type": pat.name})
            elif ip and ip not in self._banned_ips and int(score) >= 100:
                asyncio.ensure_future(self._async_ban_pipeline(ip, alert))
            break

    async def _async_ban_pipeline(self, ip: str, alert: Alert):
        country    = None
        ipinfo_org = None
        ipinfo_city = None
        is_hosting  = False

        if self._config.ipinfo("enabled", False):
            try:
                info        = await self._ipinfo.lookup(ip)
                country     = info.get("country")
                ipinfo_org  = info.get("org", "")
                ipinfo_city = info.get("city", "")
                alert.country = country
                if country:
                    self._scoring.record_event(ip, "geo_lookup", 0, country=country)
                org_lower = (ipinfo_org or "").lower()
                _HOSTING_KEYWORDS = (
                    "hosting", "datacenter", "data center", "cloud", "vps",
                    "server", "colocation", "colo", "hetzner", "ovh", "linode",
                    "digitalocean", "vultr", "amazon", "google", "microsoft",
                    "azure", "ec2", "as14061", "as16276", "as24940",
                )
                is_hosting = any(kw in org_lower for kw in _HOSTING_KEYWORDS)
            except Exception:
                pass

        score_after_ipinfo = self._scoring.get_score(ip)
        if score_after_ipinfo >= 100 and ip not in self._banned_ips:
            self._do_ban(ip, alert, country, ipinfo_org, ipinfo_city, is_hosting)
            asyncio.ensure_future(self._run_abuseipdb(ip, alert))
            return

        await self._run_abuseipdb(ip, alert)

        final_score = self._scoring.get_score(ip)
        alert.score = int(final_score)
        if final_score >= self._ban_threshold and ip not in self._banned_ips:
            self._do_ban(ip, alert, country, ipinfo_org, ipinfo_city, is_hosting)

    async def _run_abuseipdb(self, ip: str, alert: Alert):
        if not self._config.abuseipdb("enabled", False):
            return
        try:
            abuse       = await self._abuseipdb.check(ip)
            abuse_score = abuse.get("abuseConfidenceScore", 0)
            alert.abuse_score = abuse_score
            if abuse_score >= self._config.detection("abuseipdb_instant_ban_score", 90):
                self._scoring.record_event(ip, "abuseipdb_high", 50)
        except Exception:
            pass

    def _do_ban(self, ip, alert, country, ipinfo_org, ipinfo_city, is_hosting):
        self._banned_ips.add(ip)
        self._scoring.notify_ban()
        final_score = self._scoring.get_score(ip)
        alert.score = int(final_score)
        audit("ban_triggered", ip=ip, score=int(final_score),
              triggered_by=alert.event_type, country=country,
              org=ipinfo_org, is_hosting=is_hosting)
        event_dict = alert.to_dict()
        event_dict["is_hosting"]  = is_hosting
        event_dict["ipinfo_org"]  = ipinfo_org
        event_dict["ipinfo_city"] = ipinfo_city
        self._push_event(event_dict)
        if self._response_cb:
            asyncio.ensure_future(self._response_cb(alert))

    async def emit_system_alert(self, event_type: str, **kwargs):
        alert = Alert(event_type=event_type, **kwargs)
        alert.score = 0
        self._push_event(alert.to_dict())
        audit("system_alert", event_type=event_type, **kwargs)
        logger.warning("System alert", extra={"event_type": event_type, **kwargs})
        if self._response_cb: await self._response_cb(alert)

    def _push_event(self, event: dict):

        self._event_buffer.append(event)

        self._write_queue.append(event)
        if len(self._write_queue) >= _WRITE_BATCH:
            self._flush_events()

        for q in self._sse_queues:
            try: q.put_nowait(event)
            except asyncio.QueueFull: pass

    def flush(self):

        self._flush_events()

    def _flush_events(self):

        if not self._write_queue:
            return
        pending = self._write_queue[:]
        self._write_queue.clear()
        try:
            path = self._event_log_path
            path.parent.mkdir(parents=True, exist_ok=True)

            try:
                if path.exists() and path.stat().st_size > self._event_log_max_bytes:
                    rotated = path.with_suffix(".jsonl.1")
                    if rotated.exists():
                        rotated.unlink()
                    path.rename(rotated)
                    logger.info("Event log rotated",
                                extra={"rotated_to": str(rotated)})
            except Exception:
                pass

            with path.open("a", encoding="utf-8") as fh:
                for ev in pending:
                    fh.write(json.dumps(ev, default=str) + "\n")
        except Exception as exc:
            logger.warning("Event log write failed", extra={"error": str(exc)})

    def _load_events(self):

        lines: List[str] = []

        for candidate in (
            self._event_log_path,
            self._event_log_path.with_suffix(".jsonl.1"),
        ):
            if not candidate.exists():
                continue
            try:

                with candidate.open("rb") as fh:

                    fh.seek(0, 2)
                    remaining = fh.tell()
                    chunk_size = min(65536, remaining)
                    buf = b""
                    while remaining > 0 and len(lines) < _PRELOAD_LINES:
                        chunk_size = min(chunk_size, remaining)
                        remaining -= chunk_size
                        fh.seek(remaining)
                        buf = fh.read(chunk_size) + buf
                        lines = buf.split(b"\n")

                        lines = [l for l in lines if l.strip()]
                    lines = lines[-_PRELOAD_LINES:]
            except Exception:
                pass
            if len(lines) >= _PRELOAD_LINES:
                break

        loaded = 0
        for raw in lines:
            try:
                ev = json.loads(raw)
                self._event_buffer.append(ev)
                loaded += 1
            except Exception:
                pass

        if loaded:
            logger.info("Event history loaded from disk",
                        extra={"events": loaded, "path": str(self._event_log_path)})

    def subscribe_sse(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._sse_queues.append(q)
        return q

    def unsubscribe_sse(self, q: asyncio.Queue):
        try: self._sse_queues.remove(q)
        except ValueError: pass

    def recent_events(self, limit: int = 100, offset: int = 0) -> list:
        events = list(self._event_buffer)
        events.reverse()
        return events[offset: offset + limit]

    def set_response_callback(self, cb: Callable): self._response_cb = cb

    def mark_unbanned(self, ip: str):
        self._banned_ips.discard(ip)
        self._scoring.reset_ip(ip)

    def top_offenders(self, n: int = 50) -> list: return self._scoring.top_offenders(n)
    def banned_ips(self) -> list: return list(self._banned_ips)
    def adaptive_multiplier(self) -> float: return self._scoring.adaptive_multiplier
