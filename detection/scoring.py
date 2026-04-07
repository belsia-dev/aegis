import json
import time
from collections import defaultdict, deque
from pathlib import Path
from threading import RLock
from typing import Deque, Dict, Optional, Tuple

_DEFAULT_PERSIST_PATH = "/var/log/aegis/scores.json"
_SAVE_INTERVAL = 30.0

class _SlidingWindow:
    def __init__(self, window_seconds: int):
        self._window = window_seconds
        self._buf: Deque[Tuple[float, str]] = deque()

    def add(self, value: str = ""):
        now = time.monotonic()
        self._buf.append((now, value))
        self._evict(now)

    def _evict(self, now: float):
        cutoff = now - self._window
        while self._buf and self._buf[0][0] < cutoff:
            self._buf.popleft()

    def count(self) -> int:
        self._evict(time.monotonic())
        return len(self._buf)

    def unique_values(self) -> set:
        self._evict(time.monotonic())
        return {v for _, v in self._buf}

    def clear(self): self._buf.clear()

class IPScore:
    __slots__ = ("score", "last_event_ts", "hit_count", "countries", "usernames", "_lock")

    def __init__(self):
        self.score          = 0.0
        self.last_event_ts  = time.monotonic()
        self.hit_count      = 0
        self.countries: set = set()
        self.usernames: set = set()
        self._lock          = RLock()

    def add(self, points: float):
        with self._lock:
            self.score = min(100.0, self.score + points)
            self.last_event_ts = time.monotonic()
            self.hit_count += 1

    def decay(self, half_life: float):
        with self._lock:
            age = time.monotonic() - self.last_event_ts
            factor = 0.5 ** (age / half_life) if half_life > 0 else 1.0
            self.score *= factor

    @property
    def int_score(self) -> int: return int(self.score)

class ScoringEngine:
    MAX_IPS = 50_000
    _SSH_EVENTS = {"ssh_failed_password", "ssh_invalid_user", "ssh_too_many"}

    def __init__(self, config):
        self._config        = config
        self._lock          = RLock()
        self._scores: Dict[str, IPScore]                     = {}
        self._windows: Dict[str, Dict[str, _SlidingWindow]]  = defaultdict(dict)
        self._username_windows: Dict[str, _SlidingWindow]   = {}
        self._country_windows:  Dict[str, _SlidingWindow]   = {}
        self._adaptive_multiplier: float = 1.0
        self._bans_last_minute: Deque[float] = deque()
        self._last_save_ts: float = 0.0

        try:
            self._persist_path = Path(config.general("score_persist_path", _DEFAULT_PERSIST_PATH))
        except Exception:
            self._persist_path = Path(_DEFAULT_PERSIST_PATH)

        self._load()

    def record_event(self, ip: str, event_type: str, base_score: float,
                     user: Optional[str] = None, country: Optional[str] = None) -> float:
        self._ensure_ip(ip)
        score_obj = self._scores[ip]
        effective = base_score * self._adaptive_multiplier

        if event_type in self._SSH_EVENTS:
            ssh_win = self._get_event_window(ip, "_ssh_total", window_seconds=3600)
            ssh_win.add()
            if ssh_win.count() >= 3:
                effective += 15

        score_obj.add(effective)

        if user:
            win = self._get_window(
                self._username_windows, ip,
                self._config.detection("credential_stuffing_window_seconds", 120),
            )
            win.add(user)
            if len(win.unique_values()) >= self._config.detection("credential_stuffing_usernames", 5):
                score_obj.add(30)

        if country:
            win = self._get_window(
                self._country_windows, ip,
                self._config.detection("geo_velocity_window_seconds", 300),
            )
            win.add(country)
            if len(win.unique_values()) >= self._config.detection("geo_velocity_countries", 2):
                score_obj.add(20)

        self._get_event_window(ip, event_type).add()

        now = time.monotonic()
        if now - self._last_save_ts >= _SAVE_INTERVAL:
            self._save()
            self._last_save_ts = now

        return score_obj.score

    def get_score(self, ip: str) -> float:
        with self._lock:
            obj = self._scores.get(ip)
            return obj.score if obj else 0.0

    def event_count(self, ip: str, event_type: str, window_seconds: int) -> int:
        return self._get_event_window(ip, event_type, window_seconds).count()

    def reset_ip(self, ip: str):
        with self._lock:
            self._scores.pop(ip, None)
            self._windows.pop(ip, None)
            self._username_windows.pop(ip, None)
            self._country_windows.pop(ip, None)
        self._save()

    def notify_ban(self):
        now = time.monotonic()
        self._bans_last_minute.append(now)
        while self._bans_last_minute and self._bans_last_minute[0] < now - 60:
            self._bans_last_minute.popleft()
        if not self._config.adaptive_enabled:
            return
        threshold = self._config.detection("adaptive_trigger_bans_per_minute", 3)
        rate = len(self._bans_last_minute)
        if rate >= threshold * 3:   self._adaptive_multiplier = 2.0
        elif rate >= threshold:     self._adaptive_multiplier = 1.5
        else:                       self._adaptive_multiplier = 1.0

    @property
    def adaptive_multiplier(self) -> float:
        return self._adaptive_multiplier

    def run_decay(self):

        half_life = int(self._config.detection(
            "score_decay_half_life_seconds", 14400
        ))
        with self._lock:
            for obj in self._scores.values():
                obj.decay(half_life)
        self._save()

    def top_offenders(self, n: int = 50) -> list:
        with self._lock:
            items = sorted(
                ((ip, obj.int_score) for ip, obj in self._scores.items()),
                key=lambda x: x[1], reverse=True,
            )
        return [{"ip": ip, "score": score} for ip, score in items[:n]]

    def _save(self):
        try:
            self._persist_path.parent.mkdir(parents=True, exist_ok=True)
            wall_now = time.time()
            mono_now = time.monotonic()
            data = {}
            with self._lock:
                for ip, obj in self._scores.items():
                    if obj.score < 1.0:
                        continue

                    wall_ts = wall_now - (mono_now - obj.last_event_ts)
                    data[ip] = {
                        "score":         obj.score,
                        "last_event_ts": wall_ts,
                        "hit_count":     obj.hit_count,
                    }
            tmp = self._persist_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2))
            tmp.replace(self._persist_path)
        except Exception:
            pass

    def _load(self):
        if not self._persist_path.exists():
            return
        try:
            raw      = json.loads(self._persist_path.read_text())
            mono_now = time.monotonic()
            wall_now = time.time()
            for ip, entry in raw.items():
                score   = float(entry.get("score", 0))
                wall_ts = float(entry.get("last_event_ts", wall_now))
                hit_cnt = int(entry.get("hit_count", 0))
                if score < 1.0:
                    continue
                obj               = IPScore()
                obj.score         = score
                obj.last_event_ts = mono_now - (wall_now - wall_ts)
                obj.hit_count     = hit_cnt
                self._scores[ip]  = obj
        except Exception:
            pass

    def _ensure_ip(self, ip: str):
        with self._lock:
            if ip not in self._scores:
                if len(self._scores) >= self.MAX_IPS:
                    self._evict_lowest()
                self._scores[ip] = IPScore()

    def _evict_lowest(self):
        sorted_ips = sorted(self._scores, key=lambda k: self._scores[k].score)
        for ip in sorted_ips[:10]:
            self._scores.pop(ip, None)
            self._windows.pop(ip, None)

    def _get_window(self, store, ip, window_seconds):
        if ip not in store:
            store[ip] = _SlidingWindow(window_seconds)
        return store[ip]

    def _get_event_window(self, ip, event_type, window_seconds=300):
        with self._lock:
            if ip not in self._windows:
                self._windows[ip] = {}
            if event_type not in self._windows[ip]:
                self._windows[ip][event_type] = _SlidingWindow(window_seconds)
            return self._windows[ip][event_type]
