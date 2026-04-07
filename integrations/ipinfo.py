import asyncio
import time
from typing import Dict, Optional, Tuple

import aiohttp

from core.config import Config
from core.logger import get_logger

logger = get_logger("ipinfo")

_BASE_URL = "https://ipinfo.io/{ip}/json"

class IPInfoClient:

    def __init__(self, config: Config):
        self._config  = config
        self._api_key = config.ipinfo("api_key", "") or ""
        self._ttl     = int(config.ipinfo("ttl_seconds", 86400))
        self._timeout = float(config.ipinfo("timeout_seconds", 5))
        self._enabled = bool(config.ipinfo("enabled", False))

        self._cache: Dict[str, Tuple[float, dict]] = {}
        self._sem   = asyncio.Semaphore(5)
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            headers = {"Accept": "application/json"}
            if self._api_key:

                headers["Authorization"] = f"Bearer {self._api_key}"
            self._session = aiohttp.ClientSession(headers=headers)
        return self._session

    async def close(self):

        if self._session and not self._session.closed:
            await self._session.close()

    async def lookup(self, ip: str) -> dict:

        if not self._enabled:
            return {}

        if _is_bogon(ip):
            return {}

        cached = self._cache.get(ip)
        if cached and time.monotonic() < cached[0]:
            return cached[1]

        async with self._sem:

            cached = self._cache.get(ip)
            if cached and time.monotonic() < cached[0]:
                return cached[1]

            try:
                session  = await self._get_session()
                url      = _BASE_URL.format(ip=ip)
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self._timeout),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)

                        data.pop("readme", None)
                        self._cache[ip] = (time.monotonic() + self._ttl, data)
                        logger.debug(
                            "IPInfo lookup",
                            extra={
                                "ip":      ip,
                                "country": data.get("country", "?"),
                                "org":     data.get("org", "?")[:40],
                            },
                        )
                        return data

                    elif resp.status == 429:
                        logger.warning(
                            "IPInfo rate-limited",
                            extra={"ip": ip},
                        )
                    else:
                        logger.debug(
                            "IPInfo unexpected status",
                            extra={"ip": ip, "status": resp.status},
                        )

            except asyncio.TimeoutError:
                logger.debug("IPInfo timeout", extra={"ip": ip})
            except Exception as exc:
                logger.debug("IPInfo error", extra={"ip": ip, "error": str(exc)})

        return {}

    def cache_size(self) -> int:
        return len(self._cache)

    def evict_expired(self):

        now = time.monotonic()
        stale = [ip for ip, (exp, _) in self._cache.items() if now >= exp]
        for ip in stale:
            del self._cache[ip]
        return len(stale)

_BOGON_PREFIXES = (
    "127.", "10.", "0.", "169.254.",
    "192.168.", "198.18.", "198.19.", "100.64.",
    "::1", "fc", "fd",
)

def _is_bogon(ip: str) -> bool:

    return any(ip.startswith(p) for p in _BOGON_PREFIXES) or ip.startswith("172.")
