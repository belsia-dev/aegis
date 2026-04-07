import base64
import gzip
import hashlib
import re
import time
from typing import List, Optional, Tuple

_DANGER = [

    (r"bash\s+-i\s+>&?\s*/dev/(tcp|udp)/",               "reverse_shell",       80),
    (r"/dev/(tcp|udp)/[\d.]+/\d+",                        "reverse_shell",       80),
    (r"nc\b.*-[el].*\d{2,5}",                             "netcat_shell",        70),
    (r"ncat\b.*--exec|ncat\b.*-e\s+/bin",                 "netcat_shell",        70),
    (r"socat\b.*exec:",                                    "socat_shell",         70),
    (r"python[23]?\s+-c\s+['\"].*socket.*connect",        "python_shell",        75),
    (r"perl\s+-e\s+['\"]use\s+Socket",                    "perl_shell",          75),
    (r"php\s+-r\s+['\"].*fsockopen|stream_socket_client", "php_shell",           75),
    (r"ruby\s+-rsocket\s+-e",                              "ruby_shell",          75),
    (r"lua.*socket\.connect",                              "lua_shell",           70),

    (r"(curl|wget)\s+.*\|\s*(ba)?sh",                     "download_execute",    85),
    (r"(curl|wget)\s+.*\|\s*python",                      "download_execute",    85),
    (r"(curl|wget)\s+.*\|\s*perl",                        "download_execute",    85),
    (r"base64\s+(--decode|-d).*\|\s*(ba)?sh",             "base64_execute",      80),

    (r"xmrig|cpuminer|minerd|ethminer",                   "crypto_miner",        70),
    (r"stratum\+tcp://|stratum\+ssl://",                  "crypto_miner",        70),
    (r"(monero|xmr|cryptonight)",                         "crypto_miner",        50),

    (r"crontab\s+-[li]|\(crontab.*\*.*\*",               "persistence_cron",    60),
    (r">\s*~?/\.ssh/authorized_keys",                     "persistence_ssh",     70),
    (r"cp\s+.*\s+/etc/init\.d/|update-rc\.d",            "persistence_initd",   65),
    (r"systemctl\s+enable\s+\S+\.service",                "persistence_systemd", 55),
    (r"/etc/rc\.local",                                   "persistence_rc",      50),
    (r"~/.bashrc|~/.bash_profile|~/.profile",             "persistence_shell",   45),

    (r"useradd\s+-[og]\s+root|usermod\s+-G\s+sudo",       "priv_esc",            65),
    (r"chmod\s+(u\+s|4[0-7]{3})\s",                      "setuid",              60),
    (r"sudo\s+-s\s*$|sudo\s+-i\s*$",                     "priv_esc",            55),
    (r"pkexec\b|dbus-send.*PolicyKit",                    "priv_esc",            60),

    (r"cat\s+/etc/shadow|unshadow\b",                     "credential_shadow",   75),
    (r"cat\s+/etc/passwd.*>",                             "credential_passwd",   55),
    (r"mimikatz|LaZagne|secretsdump",                     "credential_tool",     80),

    (r"iptables\s+-F\s*$|iptables\s+--flush",             "fw_disable",          70),
    (r"ufw\s+disable|systemctl\s+stop\s+ufw",             "fw_disable",          70),
    (r"setenforce\s+0|getenforce",                         "selinux_disable",     60),
    (r"(pkill|killall)\s+(aegis|fail2ban|ufw|auditd)",     "kill_security",       80),

    (r"rm\s+-rf\s+/\s*$|rm\s+-rf\s+/\*",                  "destructive",         90),
    (r"dd\s+if=/dev/zero\s+of=/dev/[sh]d",                "destructive_disk",    90),
    (r"mkfs\.\w+\s+/dev/",                                 "destructive_disk",    90),
    (r"shred\s+-[uzn].*\s+/",                              "destructive",         70),

    (r"history\s+-[cw]|unset\s+HISTFILE|HISTSIZE=0",       "cover_tracks",        50),
    (r"shred.*\.bash_history|rm.*\.bash_history",          "cover_tracks",        55),

    (r"chmod\s+[+x7].*\/tmp\/",                            "tmp_execute",         50),
    (r"\/tmp\/\.[a-z0-9_-]{4,}\s+&",                       "hidden_tmp_bg",       60),

    (r"\/proc\/\d+\/mem|ptrace|\/dev\/kmem",               "mem_injection",       75),
]

_OBFUSCATION = [
    (r"eval\s*[\(\"\`]",                                   "eval_chain"),
    (r"\$\(\s*base64|base64\s+(--decode|-d)",              "base64"),
    (r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){3,}",        "hex_encoding"),
    (r"printf\s+'(?:\\\\[0-9]|\\x)",                       "printf_encoding"),
    (r"IFS=[^;]+;.*for\b",                                  "ifs_obfuscation"),
    (r"tr\s+'[A-Za-z0-9+/=]{10,}'",                        "tr_substitution"),
    (r"\$\{[^}]{60,}\}",                                   "long_variable_expansion"),
    (r"rev\s*\|",                                           "string_reversal"),
    (r"gunzip\s*\||\bzcat\b.*\|",                           "gzip_decode"),
]

_BOTNET = [
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{4,5}",      "hardcoded_ip_port",   30),
    (r"irc\b.*PRIVMSG|JOIN\s+#\w+",                        "irc_botnet",          75),
    (r"\.onion\b",                                          "tor_hidden_service",  50),
    (r"(curl|wget).*-s\b.*\|.*(sh|bash|python)",           "silent_pipe_exec",    80),
    (r"curl.*-o\s*/tmp/[^ ]+\s*&&\s*chmod",               "download_chmod_run",  75),
    (r"(zombie|botnet|c2|c&c|cnc)[\s_-]",                  "botnet_keyword",      60),
    (r"(dropper|stager|implant|beacon)\b",                  "malware_keyword",     55),
    (r"DISCORD_WEBHOOK|TELEGRAM_BOT_TOKEN",                 "exfil_webhook",       65),
    (r"(sleep\s+\d+\s*&&\s*){2,}",                         "time_delay_evasion",  35),
    (r"while\s*true.*sleep\s+\d+.*curl",                   "beacon_loop",         70),
    (r"sshpass\s+-p",                                       "ssh_bruteforce",      60),
    (r"masscan\b|zmap\b|shodan\b",                          "scanner_tool",        50),
]

class AnalysisResult:
    def __init__(self):
        self.safe             = True
        self.score            = 0
        self.findings:  List[dict] = []
        self.deobfuscated: Optional[str] = None
        self.layers           = 0
        self.ts               = time.time()
        self.sha256           = ""
        self.source           = "unknown"

    def add(self, category: str, detail: str, severity: int):
        self.findings.append({
            "category": category,
            "detail":   detail,
            "severity": severity,
        })
        self.score = min(100, self.score + severity)
        if severity >= 30:
            self.safe = False

    def to_dict(self) -> dict:
        return {
            "safe":         self.safe,
            "score":        self.score,
            "findings":     self.findings,
            "layers":       self.layers,
            "deobfuscated": (self.deobfuscated or "")[:3000],
            "sha256":       self.sha256,
            "source":       self.source,
            "ts":           self.ts,
        }

class ScriptAnalyzer:
    MAX_SIZE   = 5 * 1024 * 1024
    MAX_LAYERS = 12

    def analyze(self, script: str, source: str = "unknown") -> AnalysisResult:
        r = AnalysisResult()
        r.source = source
        r.sha256 = hashlib.sha256(script.encode("utf-8", errors="replace")).hexdigest()

        if len(script) > self.MAX_SIZE:
            r.add("size", "Script exceeds 5 MB — truncated for analysis", 15)
            script = script[:self.MAX_SIZE]

        current = script
        for i in range(self.MAX_LAYERS):
            decoded = self._peel(current)
            if decoded is None or decoded == current or len(decoded) < 4:
                break
            r.layers += 1
            r.add("obfuscation",
                  f"Encoding layer {i+1} removed ({len(current)} → {len(decoded)} bytes)",
                  12)
            current = decoded

        if r.layers > 0:
            r.deobfuscated = current
            if r.layers >= 3:
                r.add("obfuscation", f"{r.layers} encoding layers — heavily obfuscated", 25)

        for text, label in ((script, "script"), (current, "decoded")):
            if label == "decoded" and current == script:
                continue
            self._scan(text, label, r)

        return r

    def _peel(self, text: str) -> Optional[str]:

        s = text.strip()

        m = re.search(r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/])', s)
        if m:
            decoded = self._try_b64(m.group(1))
            if decoded and self._looks_scripty(decoded):
                return decoded

        m = re.search(r'echo\s+["\']?([A-Za-z0-9+/=]+)["\']?\s*\|\s*base64\s+(?:--decode|-d)', s)
        if m:
            decoded = self._try_b64(m.group(1))
            if decoded:
                return decoded

        m = re.search(r'base64\s+(?:--decode|-d)\s+<<<\s*["\']([A-Za-z0-9+/=]+)["\']', s)
        if m:
            decoded = self._try_b64(m.group(1))
            if decoded:
                return decoded

        m = re.search(r'["\']([A-Za-z0-9+/=]{60,})["\']', s)
        if m:
            decoded = self._try_gzip_b64(m.group(1))
            if decoded and self._looks_scripty(decoded):
                return decoded

        m = re.search(r'((?:\\x[0-9a-fA-F]{2}){6,})', s)
        if m:
            try:
                raw = bytes.fromhex(m.group(1).replace("\\x", ""))
                decoded = raw.decode("utf-8", errors="replace")
                if self._looks_scripty(decoded):
                    return decoded
            except Exception:
                pass

        m = re.search(r"printf\s+'((?:\\x[0-9a-fA-F]{2})+)'", s)
        if m:
            try:
                raw = bytes.fromhex(m.group(1).replace("\\x", ""))
                return raw.decode("utf-8", errors="replace")
            except Exception:
                pass

        if "rev" in s and "base64" in s:
            m = re.search(r'["\']([A-Za-z0-9+/=]{20,})["\']', s)
            if m:
                decoded = self._try_b64(m.group(1)[::-1])
                if decoded and self._looks_scripty(decoded):
                    return decoded

        m = re.search(r'((?:\\[0-7]{3}){5,})', s)
        if m:
            try:
                chars = re.findall(r'\\([0-7]{3})', m.group(1))
                decoded = "".join(chr(int(c, 8)) for c in chars)
                if self._looks_scripty(decoded):
                    return decoded
            except Exception:
                pass

        return None

    def _try_b64(self, s: str) -> Optional[str]:
        for pad in ("", "=", "=="):
            try:
                raw = base64.b64decode(s + pad)
                return raw.decode("utf-8", errors="strict")
            except Exception:
                pass
        try:
            raw = base64.b64decode(s + "==")
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return None

    def _try_gzip_b64(self, s: str) -> Optional[str]:
        try:
            raw = base64.b64decode(s + "==")
            return gzip.decompress(raw).decode("utf-8", errors="replace")
        except Exception:
            return None

    def _looks_scripty(self, text: str) -> bool:
        indicators = ["#!/", "bash", " sh ", "python", "perl", "curl",
                      "wget", "echo ", "export ", "chmod", "if [",
                      "for ", "while ", "eval", "exec"]
        lower = text.lower()
        return sum(1 for i in indicators if i in lower) >= 2

    def _scan(self, text: str, label: str, r: AnalysisResult):
        for pattern, category, severity in _DANGER:
            if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                r.add(category, f"{category} detected in {label}", severity)

        for pattern, category in _OBFUSCATION:
            if re.search(pattern, text, re.IGNORECASE):
                r.add("obfuscation", f"{category} in {label}", 10)

        for pattern, category, severity in _BOTNET:
            if re.search(pattern, text, re.IGNORECASE):
                r.add(category, f"Botnet indicator [{category}] in {label}", severity)
