import ipaddress
import socket
from typing import List, Set
from core.config import Config
from core.logger import get_logger
logger = get_logger("whitelist")

def _own_ips() -> Set[str]:
    ips: Set[str] = {"127.0.0.1", "::1"}
    try:
        hostname = socket.gethostname()
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            ips.add(info[4][0])
    except Exception:
        pass
    return ips

class Whitelist:
    def __init__(self, config: Config):
        self._config = config
        self._ips: Set[str] = set()
        self._networks: List = []
        self._build()

    def _build(self):
        self._ips = set(self._config.whitelist_ips)
        if self._config.protect_self:
            self._ips |= _own_ips()
        self._networks = []
        for cidr in self._config.whitelist_cidrs:
            try:
                self._networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                logger.warning("Invalid CIDR in whitelist", extra={"cidr": cidr})
        logger.info("Whitelist loaded", extra={"ips": len(self._ips), "cidrs": len(self._networks)})

    def is_whitelisted(self, ip: str) -> bool:
        if ip in self._ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._networks)

    def reload(self):
        self._build()
