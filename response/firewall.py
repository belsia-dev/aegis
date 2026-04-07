import asyncio
import re
import subprocess
from dataclasses import dataclass
from enum import Enum, auto
from typing import List, Optional, Set

from core.config import Config
from core.logger import get_logger, audit

logger = get_logger("firewall")

class FwAction(Enum):
    BAN   = auto()
    UNBAN = auto()
    RATE  = auto()

@dataclass
class FwCommand:
    action: FwAction
    ip: str
    duration: Optional[int] = None
    reason: str = ""

class FirewallManager:

    _CHAIN       = "AEGIS"
    _BATCH_DELAY = 0.02

    def __init__(self, config: Config):
        self._config      = config
        self._backend     = config.firewall_backend
        self._dry_run     = config.dry_run
        self._privilege   = config.privilege_mode
        self._queue: asyncio.Queue = asyncio.Queue()
        self._initialized = False

    async def start(self):
        await self._init_chain()
        asyncio.ensure_future(self._worker())

    async def ban(self, ip: str, duration: Optional[int] = None, reason: str = ""):
        await self._queue.put(FwCommand(FwAction.BAN, ip, duration, reason))

    async def unban(self, ip: str):
        await self._queue.put(FwCommand(FwAction.UNBAN, ip))

    async def rate_limit(self, ip: str):
        await self._queue.put(FwCommand(FwAction.RATE, ip))

    def list_chain_ips(self) -> Set[str]:

        if self._backend == "nftables":
            return self._list_chain_nftables()

        ips: Set[str] = set()
        _ip_pat = re.compile(r"^(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)(?:/\d+)?$")

        for proto in ("iptables", "ip6tables"):
            cmd = self._build_cmd([proto, "-S", self._CHAIN])
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode != 0:

                    logger.debug(
                        "list_chain_ips: command failed",
                        extra={"proto": proto, "stderr": result.stderr.strip()[:200]},
                    )
                    continue

                for line in result.stdout.splitlines():
                    if "-j DROP" not in line:
                        continue
                    for part in line.split():
                        if _ip_pat.match(part):
                            bare = part.split("/")[0]
                            if bare not in ("0.0.0.0", "::"):
                                ips.add(bare)
                            break
            except FileNotFoundError:
                logger.debug("list_chain_ips: binary not found", extra={"proto": proto})
            except subprocess.TimeoutExpired:
                logger.warning("list_chain_ips: timeout", extra={"proto": proto})
            except Exception as exc:
                logger.warning(
                    "list_chain_ips: unexpected error",
                    extra={"proto": proto, "error": str(exc)},
                )
        return ips

    def _list_chain_nftables(self) -> Set[str]:
        ips: Set[str] = set()
        _ip_pat = re.compile(r"\b(\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]{3,})\b")
        for family in ("ip", "ip6"):
            cmd = self._build_cmd(
                ["nft", "list", "chain", family, "filter", self._CHAIN.lower()]
            )
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode != 0:
                    continue
                for line in result.stdout.splitlines():
                    if "drop" in line.lower():
                        m = _ip_pat.search(line)
                        if m:
                            ips.add(m.group(1))
            except Exception as exc:
                logger.debug("list_chain_nftables error", extra={"error": str(exc)})
        return ips

    async def _worker(self):
        loop = asyncio.get_running_loop()
        while True:
            cmd   = await self._queue.get()
            batch = [cmd]
            deadline = loop.time() + self._BATCH_DELAY
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    extra = await asyncio.wait_for(self._queue.get(), timeout=remaining)
                    batch.append(extra)
                except asyncio.TimeoutError:
                    break
            await loop.run_in_executor(None, self._execute_batch, batch)

    def _execute_batch(self, batch: List[FwCommand]):
        for cmd in batch:
            try:
                if self._backend == "nftables":
                    self._nftables(cmd)
                else:
                    self._iptables(cmd)
            except Exception as exc:
                logger.error(
                    "Firewall command failed",
                    extra={"action": cmd.action.name, "ip": cmd.ip, "error": str(exc)},
                )

    def _iptables(self, cmd: FwCommand):
        ip = cmd.ip
        is_v6 = ":" in ip

        families = (["ip6tables"] if is_v6 else ["iptables", "ip6tables"]) \
                   if cmd.action == FwAction.BAN else \
                   (["ip6tables"] if is_v6 else ["iptables", "ip6tables"])

        if cmd.action == FwAction.BAN:
            binaries = ["ip6tables"] if is_v6 else ["iptables"]
            for binary in binaries:
                args = [binary, "-I", self._CHAIN, "1", "-s", ip, "-j", "DROP",
                        "-m", "comment", "--comment", f"aegis:{cmd.reason[:40]}"]
                self._run(args)

            audit("firewall_ban", ip=ip, backend="iptables",
                  duration=cmd.duration, reason=cmd.reason)
            logger.info("Banned", extra={"ip": ip, "reason": cmd.reason})

        elif cmd.action == FwAction.UNBAN:
            for binary in ("iptables", "ip6tables"):
                self._run([binary, "-D", self._CHAIN, "-s", ip, "-j", "DROP"],
                          ignore_error=True)
            audit("firewall_unban", ip=ip, backend="iptables")
            logger.info("Unbanned", extra={"ip": ip})

        elif cmd.action == FwAction.RATE:
            rate = self._config.response("rate_limit_requests", 30)
            safe_name = f"aegis_{ip.replace('.', '_').replace(':', '_')}"
            self._run([
                "iptables", "-I", self._CHAIN, "1", "-s", ip,
                "-m", "hashlimit",
                "--hashlimit-above", f"{rate}/minute",
                "--hashlimit-mode",  "srcip",
                "--hashlimit-name",  safe_name,
                "-j", "DROP",
            ], ignore_error=True)

    def _nftables(self, cmd: FwCommand):
        ip     = cmd.ip
        family = "ip6" if ":" in ip else "ip"
        table  = f"{family} filter"
        chain  = self._CHAIN.lower()

        if cmd.action == FwAction.BAN:
            self._run([
                "nft", "add", "rule", table, chain,
                family, "saddr", ip, "drop",
                "comment", f'"aegis:{cmd.reason[:40]}"',
            ])
            audit("firewall_ban", ip=ip, backend="nftables",
                  duration=cmd.duration, reason=cmd.reason)
            logger.info("Banned (nftables)", extra={"ip": ip})

        elif cmd.action == FwAction.UNBAN:

            try:
                result = subprocess.run(
                    self._build_cmd(["nft", "-a", "list", "chain", table.split()[0],
                                     table.split()[1], chain]),
                    capture_output=True, text=True, timeout=10,
                )
                for line in result.stdout.splitlines():
                    if ip in line and "drop" in line.lower():
                        m = re.search(r"# handle (\d+)", line)
                        if m:
                            self._run(["nft", "delete", "rule", table, chain,
                                       "handle", m.group(1)], ignore_error=True)
            except Exception:
                pass
            audit("firewall_unban", ip=ip, backend="nftables")

    async def _init_chain(self):
        if self._initialized:
            return
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._init_chain_sync)
        self._initialized = True

    def _init_chain_sync(self):
        if self._backend == "nftables":
            for cmd in [
                ["nft", "add", "table", "ip",  "filter"],
                ["nft", "add", "chain", "ip",  "filter", self._CHAIN.lower(),
                 "{ type filter hook input priority -1; policy accept; }"],
                ["nft", "add", "table", "ip6", "filter"],
                ["nft", "add", "chain", "ip6", "filter", self._CHAIN.lower(),
                 "{ type filter hook input priority -1; policy accept; }"],
            ]:
                self._run(cmd, ignore_error=True)
        else:
            for cmd in [
                ["iptables",  "-N", self._CHAIN],
                ["iptables",  "-I", "INPUT", "1", "-j", self._CHAIN],
                ["ip6tables", "-N", self._CHAIN],
                ["ip6tables", "-I", "INPUT", "1", "-j", self._CHAIN],
            ]:
                self._run(cmd, ignore_error=True)
        logger.info("Firewall chain initialised", extra={"backend": self._backend})

    async def flush_chain(self):
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._flush_sync)

    def _flush_sync(self):
        if self._backend == "iptables":
            for cmd in [
                ["iptables",  "-D", "INPUT", "-j", self._CHAIN],
                ["iptables",  "-F", self._CHAIN],
                ["iptables",  "-X", self._CHAIN],
                ["ip6tables", "-D", "INPUT", "-j", self._CHAIN],
                ["ip6tables", "-F", self._CHAIN],
                ["ip6tables", "-X", self._CHAIN],
            ]:
                self._run(cmd, ignore_error=True)
        else:
            for family in ("ip", "ip6"):
                self._run(["nft", "flush", "chain", family, "filter",
                            self._CHAIN.lower()], ignore_error=True)

    def _build_cmd(self, args: List[str]) -> List[str]:

        if self._privilege == "sudo":
            return ["sudo", "-n"] + args
        return args

    def _run(self, args: List[str], ignore_error: bool = False):
        full = self._build_cmd(args)
        if self._dry_run:
            logger.debug("DRY-RUN", extra={"cmd": " ".join(full)})
            return
        logger.debug("FW cmd", extra={"cmd": " ".join(full)})
        result = subprocess.run(full, capture_output=True, text=True, timeout=10)
        if result.returncode != 0 and not ignore_error:
            raise RuntimeError(
                f"{' '.join(full)} → exit {result.returncode}: {result.stderr.strip()}"
            )
