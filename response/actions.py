import asyncio
import time
from typing import Dict, Optional

from core.config import Config
from core.logger import get_logger, audit
from detection.engine import Alert, DetectionEngine
from response.firewall import FirewallManager

logger = get_logger("response")

class BanRecord:
    __slots__ = ("ip", "ban_time", "ban_until", "reason", "permanent")

    def __init__(self, ip: str, duration: Optional[int], reason: str):
        self.ip        = ip
        self.ban_time  = time.time()
        self.ban_until = (self.ban_time + duration) if duration is not None else None
        self.reason    = reason
        self.permanent = duration is None

    def is_expired(self) -> bool:
        if self.permanent or self.ban_until is None:
            return False
        return time.time() >= self.ban_until

    def remaining_seconds(self) -> Optional[int]:
        if self.permanent or self.ban_until is None:
            return None
        return max(0, int(self.ban_until - time.time()))

    def to_dict(self) -> dict:
        return {
            "ip":               self.ip,
            "ban_time":         self.ban_time,
            "ban_until":        self.ban_until,
            "reason":           self.reason,
            "permanent":        self.permanent,
            "remaining_seconds": self.remaining_seconds(),
        }

class ResponseEngine:

    _NO_BAN_EVENTS = {
        "persistence_new_file", "persistence_modified_file",
        "new_listener", "oom_kill", "seg_fault",
    }

    def __init__(self, config: Config, detection: DetectionEngine):
        self._config    = config
        self._detection = detection
        self._firewall  = FirewallManager(config)
        self._ban_duration        = config.ban_duration
        self._permanent_threshold = int(config.response("permanent_ban_score", 95))
        self._unban_interval      = int(config.response("unban_interval", 60))
        self._bans: Dict[str, BanRecord] = {}

    async def handle_alert(self, alert: Alert):
        if alert.event_type in self._NO_BAN_EVENTS or not alert.ip:
            logger.warning(
                "System alert — no network ban",
                extra={
                    "event_type": alert.event_type,
                    "path": getattr(alert, "path", None),
                    "pid":  getattr(alert, "pid",  None),
                },
            )
            return

        ip    = alert.ip
        score = alert.score or 0

        if ip in self._bans and not self._bans[ip].is_expired():

            if score >= self._permanent_threshold and not self._bans[ip].permanent:
                logger.info(
                    "Upgrading temporary ban to permanent",
                    extra={"ip": ip, "score": score},
                )
                await self._ban_ip(ip, duration=None, reason=f"score_upgrade:{alert.event_type}")
            return

        duration = None if score >= self._permanent_threshold else self._ban_duration
        await self._ban_ip(ip, duration=duration, reason=alert.event_type)

    async def _ban_ip(self, ip: str, duration: Optional[int], reason: str):
        if not self._firewall._initialized:
            await self._firewall.start()
        record = BanRecord(ip, duration, reason)
        self._bans[ip] = record
        await self._firewall.ban(ip, duration=duration, reason=reason)
        logger.info(
            "IP banned",
            extra={"ip": ip, "duration": duration or "permanent", "reason": reason},
        )
        audit("ban", ip=ip, duration=duration or "permanent", reason=reason)

    async def unban_ip(self, ip: str):
        if not self._firewall._initialized:
            await self._firewall.start()
        self._bans.pop(ip, None)
        self._detection.mark_unbanned(ip)
        await self._firewall.unban(ip)
        audit("manual_unban", ip=ip)
        logger.info("IP manually unbanned", extra={"ip": ip})

    async def manual_ban_ip(self, ip: str, duration: Optional[int] = None):

        if not self._firewall._initialized:
            await self._firewall.start()
        if ip in self._bans and not self._bans[ip].is_expired():
            return
        await self._ban_ip(ip, duration=duration, reason="manual_ban")
        self._detection._banned_ips.add(ip)
        logger.info("IP manually banned via UI", extra={"ip": ip})

    async def sync_bans_from_iptables(self) -> int:

        if not self._firewall._initialized:
            await self._firewall.start()

        loop = asyncio.get_running_loop()

        try:

            found_ips = await loop.run_in_executor(
                None, self._firewall.list_chain_ips
            )
        except Exception as exc:
            logger.error("sync_bans_from_iptables failed",
                         extra={"error": str(exc)})
            return 0

        if not found_ips:
            logger.info("sync_bans_from_iptables: no IPs found in chain")

        synced = 0
        for ip in found_ips:
            if ip not in self._bans or self._bans[ip].is_expired():
                record = BanRecord(ip, duration=None, reason="iptables_sync")
                self._bans[ip] = record
                self._detection._banned_ips.add(ip)
                synced += 1
                logger.info("Synced ban from iptables", extra={"ip": ip})

        audit(
            "bans_refreshed_from_iptables",
            synced=synced,
            total_found=len(found_ips),
        )
        logger.info(
            "iptables sync complete",
            extra={"synced": synced, "total_found": len(found_ips)},
        )
        return synced

    async def unban_loop(self):
        if not self._firewall._initialized:
            await self._firewall.start()
        logger.info("Unban loop started", extra={"interval": self._unban_interval})
        while True:
            await asyncio.sleep(self._unban_interval)
            try:
                await self._process_expirations()
            except Exception as exc:
                logger.error("Unban loop error", extra={"error": str(exc)})

    async def _process_expirations(self):
        expired = [ip for ip, rec in self._bans.items() if rec.is_expired()]
        for ip in expired:
            del self._bans[ip]
            self._detection.mark_unbanned(ip)
            await self._firewall.unban(ip)
            audit("auto_unban", ip=ip)
            logger.info("Temporary ban expired, unbanned", extra={"ip": ip})
        if expired:
            logger.info("Expiration sweep", extra={"expired": len(expired)})
        self._detection._scoring.run_decay()

    def active_bans(self) -> list:
        return [rec.to_dict() for rec in self._bans.values() if not rec.is_expired()]

    def ban_count(self) -> int:
        return sum(1 for rec in self._bans.values() if not rec.is_expired())
