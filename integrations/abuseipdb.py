import asyncio
import time
from typing import Dict, Optional, Tuple
import aiohttp
from core.config import Config
from core.logger import get_logger
logger = get_logger("abuseipdb")
_BASE_URL = "https://api.abuseipdb.com/api/v2/check"

class AbuseIPDBClient:
    def __init__(self, config: Config):
        self._config  = config
        self._api_key = config.abuseipdb("api_key", "")
        self._ttl     = int(config.abuseipdb("ttl_seconds", 3600))
        self._max_age = int(config.abuseipdb("max_age_days", 30))
        self._timeout = float(config.abuseipdb("timeout_seconds", 5))
        self._enabled = bool(config.abuseipdb("enabled", False))
        self._cache: Dict[str, Tuple[float, dict]] = {}
        self._lock  = asyncio.Lock()
        self._sem   = asyncio.Semaphore(5)
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                headers={"Key": self._api_key, "Accept": "application/json"}
            )
        return self._session

    async def check(self, ip: str) -> dict:
        if not self._enabled or not self._api_key:
            return {}
        cached = self._cache.get(ip)
        if cached and time.monotonic() < cached[0]:
            return cached[1]
        async with self._sem:
            cached = self._cache.get(ip)
            if cached and time.monotonic() < cached[0]:
                return cached[1]
            try:
                session = await self._get_session()
                async with session.get(
                    _BASE_URL,
                    params={"ipAddress": ip, "maxAgeInDays": self._max_age},
                    timeout=aiohttp.ClientTimeout(total=self._timeout),
                ) as resp:
                    if resp.status == 200:
                        body = await resp.json()
                        data = body.get("data", {})
                        self._cache[ip] = (time.monotonic() + self._ttl, data)
                        logger.debug("AbuseIPDB lookup", extra={"ip": ip, "score": data.get("abuseConfidenceScore", 0)})
                        return data
                    elif resp.status == 429:
                        logger.warning("AbuseIPDB rate-limited")
            except Exception as exc:
                logger.debug("AbuseIPDB error", extra={"ip": ip, "error": str(exc)})
        return {}

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
