import re
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

@dataclass
class LogPattern:
    name: str
    pattern: re.Pattern
    log_types: list
    extract: Callable
    severity: int = 30

def _ip(m, group="ip"):
    try:
        return m.group(group)
    except (IndexError, AttributeError):
        return None

_SSH_FAIL        = re.compile(r"Failed (?:password|publickey|keyboard-interactive|hostbased) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port \d+")
_SSH_INVALID     = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+)")
_SSH_DISCONNECT  = re.compile(r"Disconnected from (?:authenticating |invalid )?user \S+ (?P<ip>[\d.:a-fA-F]+)")
_SSH_ROOT        = re.compile(r"ROOT LOGIN REFUSED from (?P<ip>[\d.:a-fA-F]+)")
_SSH_TOO_MANY    = re.compile(r"error: maximum authentication attempts exceeded.*from (?P<ip>[\d.:a-fA-F]+)")
_SSH_PREAUTH     = re.compile(r"Disconnected.*preauth.*from (?P<ip>[\d.:a-fA-F]+)")
_SSH_BAD_VERSION = re.compile(r"Bad protocol version identification .* from (?P<ip>[\d.:a-fA-F]+)")
_SSH_NOLOGIN     = re.compile(r"User (?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) not allowed because not listed in AllowUsers")
_SSH_MAP_FAIL    = re.compile(r"pam_unix\(sshd:auth\): authentication failure.*rhost=(?P<ip>[\d.:a-fA-F]+)")

_SUDO_FAIL       = re.compile(r"sudo:.*?(?P<user>\S+)\s*:.*FAILED")
_SUDO_WRONG      = re.compile(r"sudo:.*?(?P<user>\S+).*incorrect password attempts")
_PAM_FAIL        = re.compile(r"pam_unix\(\S+:auth\): authentication failure.*rhost=(?P<ip>[\d.:a-fA-F]+).*user=(?P<user>\S+)")
_PAM_UNIX_FAIL   = re.compile(r"pam_unix\([^)]+\): check pass; user unknown")
_PAM_TALLY       = re.compile(r"pam_tally2.*user (?P<user>\S+).*denied.*(?P<ip>[\d.:a-fA-F]+)")

_NEW_USER        = re.compile(r"new user: name=(?P<user>\S+)")
_USERMOD_ROOT    = re.compile(r"usermod.*-G.*(?:sudo|wheel|admin).*(?P<user>\S+)")
_PASSWD_CHANGE   = re.compile(r"password changed for (?P<user>\S+)")
_CHAGE_EXPIRE    = re.compile(r"chage.*-E.*0.*(?P<user>\S+)")

_SMTP_AUTH       = re.compile(r"warning: (?P<ip>[\d.:a-fA-F]+): SASL (?:LOGIN|PLAIN|DIGEST-MD5|CRAM-MD5) authentication failed")
_SMTP_RELAY      = re.compile(r"NOQUEUE: reject.*from (?P<hostname>\S+)\[(?P<ip>[\d.:a-fA-F]+)\].*Relay access denied")
_SMTP_LIMIT      = re.compile(r"too many errors after (?:AUTH|RCPT|DATA|MAIL) from (?P<hostname>\S+)\[(?P<ip>[\d.:a-fA-F]+)\]")
_SMTP_VRFY       = re.compile(r"VRFY command.*from (?P<hostname>\S+)\[(?P<ip>[\d.:a-fA-F]+)\]")
_DOVECOT_FAIL    = re.compile(r"(?:imap|pop3|submission)-login: Aborted login.*rip=(?P<ip>[\d.:a-fA-F]+)")
_DOVECOT_NOAUTH  = re.compile(r"(?:imap|pop3|submission)-login: Disconnected.*\(no auth attempts\).*rip=(?P<ip>[\d.:a-fA-F]+)")
_DOVECOT_BRUTE   = re.compile(r"(?:imap|pop3)-login: .*Aborted.*\(tried to use disabled plaintext auth\).*rip=(?P<ip>[\d.:a-fA-F]+)")

_HTTP_LOGIN      = re.compile(r'^(?P<ip>[\d.:a-fA-F]+).*"POST (?P<path>/(?:login|signin|wp-login\.php|admin(?:/index\.php)?|auth|xmlrpc\.php|wp-json/jwt-auth)[^"]*)".*(?P<status>40[13])')
_HTTP_SCAN       = re.compile(r'"(?:GET|POST|HEAD) /(?:\.env|\.git(?:/config|/HEAD)?|phpinfo|\.aws|\.ssh|wp-config(?:\.php)?|config\.php|backup|\.DS_Store|\.htaccess|web\.config|server-status|\.svn|\.hg|Makefile|Dockerfile|docker-compose\.yml)[^"]*"', re.IGNORECASE)
_HTTP_UA         = re.compile(r'"(?:sqlmap|nikto|nmap|masscan|ZGrab|python-requests|Go-http-client|zgrab|dirsearch|gobuster|wfuzz|curl|nuclei|acunetix|nessus|openvas|burpsuite|havij|w3af|zaproxy|hydra)[^"]*"', re.IGNORECASE)
_HTTP_LFI        = re.compile(r'"(?:GET|POST) [^"]*(?:\.\./\.\./|%2[Ee]%2[Ee]%2[Ff]|%252[Ee]|%c0%af|\.\.%2[Ff]){2,}[^"]*"', re.IGNORECASE)
_HTTP_RFI        = re.compile(r'"(?:GET|POST) [^"]*(?:include|require|file)=(?:https?|ftp)://', re.IGNORECASE)
_HTTP_SQLI       = re.compile(r'"(?:GET|POST) [^"]*(?:\bUNION\b.*\bSELECT\b|\'.*\bOR\b.*\'=\'|%27|%3D|1=1|1%3D1)[^"]*"', re.IGNORECASE)
_HTTP_XSS        = re.compile(r'"(?:GET|POST) [^"]*(?:%3[Cc]script|<script|alert\(|onerror=|onload=|javascript:)[^"]*"', re.IGNORECASE)
_HTTP_WEBSHELL   = re.compile(r'"(?:GET|POST) [^"]*(?:eval\(\$_|passthru|shell_exec|system\(\$_|base64_decode\(\$_|cmd=|exec=|command=)[^"]*"', re.IGNORECASE)
_HTTP_4XX_FLOOD  = re.compile(r'^(?P<ip>[\d.:a-fA-F]+).*" (?:400|404|405|406|410|429) ')
_HTTP_500_ERR    = re.compile(r'^(?P<ip>[\d.:a-fA-F]+).*" 500 ')

_LOG4SHELL       = re.compile(r'\$\{(?:lower:|upper:)*j(?:lower:|upper:)*n(?:lower:|upper:)*d(?:lower:|upper:)*i(?:lower:|upper:)*:', re.IGNORECASE)
_LOG4SHELL_ALT   = re.compile(r'\$\{(?:\S*:)*(?:ldap|rmi|dns|ldaps|corba|iiop|http)s?://', re.IGNORECASE)
_SPRING4SHELL    = re.compile(r'class\.module\.classLoader|class\.module\.class\.classLoader', re.IGNORECASE)
_SHELLSHOCK      = re.compile(r'\(\)\s*\{[^}]{0,100}\}\s*;', re.IGNORECASE)
_HEARTBLEED      = re.compile(r'"\\x18\\x03[\x00-\x03]|heartbeat', re.IGNORECASE)
_STRUTS_RCE      = re.compile(r'Content-Type:.*%\{|#cmd=|ognl\.|OGNL', re.IGNORECASE)
_WORDPRESS_XMLRPC= re.compile(r'"POST /xmlrpc\.php".*200', re.IGNORECASE)
_WORDPRESS_ENUM  = re.compile(r'"GET /\?author=\d+"', re.IGNORECASE)
_PHPMYADMIN      = re.compile(r'"(?:GET|POST) /(?:phpmyadmin|pma|myadmin|phpMyAdmin)[^"]*"', re.IGNORECASE)

_MYSQL_FAIL      = re.compile(r"Access denied for user '(?P<user>[^']+)'@'(?P<ip>[\d.a-fA-F:]+)'")
_PGSQL_FAIL      = re.compile(r"FATAL:\s+password authentication failed for user \"(?P<user>[^\"]+)\".*host=(?P<ip>[\d.:a-fA-F]+)")
_PGSQL_CONN      = re.compile(r"connection received: host=(?P<ip>[\d.:a-fA-F]+).*user=(?P<user>\S+).*auth failed")
_MONGODB_FAIL    = re.compile(r"Unauthorized.*from client (?P<ip>[\d.:a-fA-F]+)|Authentication failed.*client: (?P<ip2>[\d.:a-fA-F]+)")
_REDIS_NOAUTH    = re.compile(r"Client (?P<ip>[\d.:a-fA-F]+).*NOAUTH|WRONGPASS.*(?P<ip2>[\d.:a-fA-F]+)")

_FTP_FAIL_VSFTPD = re.compile(r"FAIL LOGIN: Client \"(?P<ip>[\d.:a-fA-F]+)\"")
_FTP_FAIL_PURE   = re.compile(r"\((?P<ip>[\d.:a-fA-F]+)\) \[ERROR\] Bad sequence of commands")
_FTP_FAIL_PROFTPD= re.compile(r"USER (?P<user>\S+) \(Login failed\): (?P<ip>[\d.:a-fA-F]+)")
_FTP_ANON_ABUSE  = re.compile(r"ANON (?P<ip>[\d.:a-fA-F]+).*(?:STOR|DELE|RMD|MKD)")

_UFW_BLOCK       = re.compile(r"kernel:.*\[UFW BLOCK\].*SRC=(?P<ip>[\d.:a-fA-F]+)")
_IPTABLES_DROP   = re.compile(r"kernel:.*IN=\S+.*SRC=(?P<ip>[\d.:a-fA-F]+).*DPT=(?P<port>\d+)")
_NFTABLES_DROP   = re.compile(r"nft.*drop.*ip saddr (?P<ip>[\d.:a-fA-F]+)")

_DOCKER_API      = re.compile(r'"(?:GET|POST|DELETE) /v\d+\.\d+/(?:containers|images|volumes|networks|secrets)[^"]*".*(?:200|201|204)', re.IGNORECASE)
_DOCKER_EXEC     = re.compile(r'"POST /v\d+\.\d+/containers/[^/]+/exec[^"]*"', re.IGNORECASE)
_K8S_API         = re.compile(r'"(?:GET|POST|PUT|PATCH|DELETE) /api/v1/(?:pods|secrets|configmaps|serviceaccounts|namespaces)[^"]*"', re.IGNORECASE)
_K8S_UNAUTH      = re.compile(r'"(?:GET|POST) /api[^"]*" (?:401|403)', re.IGNORECASE)

_CLOUD_METADATA  = re.compile(r'(?:169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2|fd00:ec2::254)', re.IGNORECASE)
_AWS_META        = re.compile(r'(?:GET|POST).*169\.254\.169\.254/latest/(?:meta-data|user-data|dynamic)', re.IGNORECASE)

_PORT_SCAN_SYN   = re.compile(r"kernel.*SYN.*SRC=(?P<ip>[\d.:a-fA-F]+)")
_NMAP_OS         = re.compile(r'"(?:GET|HEAD) / HTTP/1\.0" 400|"XXXXXXXXXXX" -')
_MASSCAN_SIG     = re.compile(r'User-Agent: masscan/\d|"MASSCAN"', re.IGNORECASE)

_TMP_EXEC        = re.compile(r'(?:execve|execveat)\("(?P<path>/(?:tmp|var/tmp|dev/shm)/[^"]+)"')
_AUDITD_EXEC     = re.compile(r'type=EXECVE.*a0="(?P<path>/(?:tmp|var/tmp|dev/shm)/[^"]+)"')

_LDAP_FAIL       = re.compile(r"LDAP.*bind.*failed.*from (?P<ip>[\d.:a-fA-F]+)|Invalid credentials.*(?P<ip2>[\d.:a-fA-F]+).*LDAP")
_VNC_FAIL        = re.compile(r"LibVNCServer.*connection.*(?P<ip>[\d.:a-fA-F]+)|VNC.*authentication.*(?P<ip2>[\d.:a-fA-F]+)")
_RDP_FAIL        = re.compile(r"RDP.*Authentication.*Failure.*from (?P<ip>[\d.:a-fA-F]+)|rdp.*login fail.*(?P<ip2>[\d.:a-fA-F]+)", re.IGNORECASE)
_HAPROXY_BLOCK   = re.compile(r"haproxy.*backend .* has no server available.*(?P<ip>[\d.:a-fA-F]+)", re.IGNORECASE)

PATTERNS = [

    LogPattern("ssh_failed_password",  _SSH_FAIL,        ["auth","syslog"],  lambda m: {"ip": m.group("ip"), "user": m.group("user")},     25),
    LogPattern("ssh_invalid_user",     _SSH_INVALID,     ["auth","syslog"],  lambda m: {"ip": m.group("ip"), "user": m.group("user")},     22),
    LogPattern("ssh_disconnect",       _SSH_DISCONNECT,  ["auth","syslog"],  lambda m: {"ip": _ip(m)},                                      8),
    LogPattern("ssh_root_refused",     _SSH_ROOT,        ["auth","syslog"],  lambda m: {"ip": m.group("ip")},                              45),
    LogPattern("ssh_too_many",         _SSH_TOO_MANY,    ["auth","syslog"],  lambda m: {"ip": m.group("ip")},                              55),
    LogPattern("ssh_preauth",          _SSH_PREAUTH,     ["auth","syslog"],  lambda m: {"ip": _ip(m)},                                     12),
    LogPattern("ssh_bad_version",      _SSH_BAD_VERSION, ["auth","syslog"],  lambda m: {"ip": m.group("ip")},                              30),
    LogPattern("ssh_not_allowed",      _SSH_NOLOGIN,     ["auth","syslog"],  lambda m: {"ip": m.group("ip"), "user": m.group("user")},     35),
    LogPattern("ssh_pam_failure",      _SSH_MAP_FAIL,    ["auth","syslog"],  lambda m: {"ip": m.group("ip")},                              20),

    LogPattern("sudo_failure",         _SUDO_FAIL,       ["auth","syslog"],  lambda m: {"user": m.group("user")},                          35),
    LogPattern("sudo_wrong_password",  _SUDO_WRONG,      ["auth","syslog"],  lambda m: {"user": m.group("user")},                          30),
    LogPattern("pam_auth_failure",     _PAM_FAIL,        ["auth","syslog"],  lambda m: {"ip": m.group("ip"), "user": m.group("user")},     20),
    LogPattern("pam_unknown_user",     _PAM_UNIX_FAIL,   ["auth","syslog"],  lambda m: {},                                                 15),
    LogPattern("pam_tally_denied",     _PAM_TALLY,       ["auth","syslog"],  lambda m: {"ip": m.group("ip"), "user": m.group("user")},     40),

    LogPattern("new_user_created",     _NEW_USER,        ["auth","syslog"],  lambda m: {"user": m.group("user")},                          60),
    LogPattern("user_added_to_sudo",   _USERMOD_ROOT,    ["auth","syslog"],  lambda m: {"user": m.group("user")},                          85),
    LogPattern("password_changed",     _PASSWD_CHANGE,   ["auth","syslog"],  lambda m: {"user": m.group("user")},                          40),

    LogPattern("smtp_auth_failure",    _SMTP_AUTH,       ["mail"],           lambda m: {"ip": m.group("ip")},                              25),
    LogPattern("smtp_relay_denied",    _SMTP_RELAY,      ["mail"],           lambda m: {"ip": m.group("ip")},                              20),
    LogPattern("smtp_client_limit",    _SMTP_LIMIT,      ["mail"],           lambda m: {"ip": m.group("ip")},                              30),
    LogPattern("smtp_vrfy_scan",       _SMTP_VRFY,       ["mail"],           lambda m: {"ip": m.group("ip")},                              25),
    LogPattern("imap_aborted_login",   _DOVECOT_FAIL,    ["mail"],           lambda m: {"ip": m.group("ip")},                              20),
    LogPattern("imap_no_auth",         _DOVECOT_NOAUTH,  ["mail"],           lambda m: {"ip": m.group("ip")},                              10),
    LogPattern("imap_plaintext_abuse", _DOVECOT_BRUTE,   ["mail"],           lambda m: {"ip": m.group("ip")},                              28),

    LogPattern("http_login_failure",   _HTTP_LOGIN,      ["nginx_access","apache_access"], lambda m: {"ip": m.group("ip"), "path": m.group("path")}, 22),
    LogPattern("http_path_scan",       _HTTP_SCAN,       ["nginx_access","apache_access"], lambda m: {},                                   35),
    LogPattern("http_scanner_ua",      _HTTP_UA,         ["nginx_access","apache_access"], lambda m: {},                                   55),
    LogPattern("http_lfi_attempt",     _HTTP_LFI,        ["nginx_access","apache_access"], lambda m: {"ip": _ip(m)},                      50),
    LogPattern("http_rfi_attempt",     _HTTP_RFI,        ["nginx_access","apache_access"], lambda m: {},                                   55),
    LogPattern("http_sqli_attempt",    _HTTP_SQLI,       ["nginx_access","apache_access"], lambda m: {},                                   60),
    LogPattern("http_xss_attempt",     _HTTP_XSS,        ["nginx_access","apache_access"], lambda m: {},                                   40),
    LogPattern("http_webshell_probe",  _HTTP_WEBSHELL,   ["nginx_access","apache_access"], lambda m: {},                                   65),
    LogPattern("http_4xx_flood",       _HTTP_4XX_FLOOD,  ["nginx_access","apache_access"], lambda m: {"ip": m.group("ip")},               15),

    LogPattern("log4shell_attempt",    _LOG4SHELL,       ["nginx_access","apache_access","custom"], lambda m: {},                          90),
    LogPattern("log4shell_alt",        _LOG4SHELL_ALT,   ["nginx_access","apache_access","custom"], lambda m: {},                          90),
    LogPattern("spring4shell",         _SPRING4SHELL,    ["nginx_access","apache_access"],           lambda m: {},                          80),
    LogPattern("shellshock",           _SHELLSHOCK,      ["nginx_access","apache_access","syslog"],  lambda m: {},                          80),
    LogPattern("struts_rce",           _STRUTS_RCE,      ["nginx_access","apache_access"],           lambda m: {},                          75),
    LogPattern("wordpress_xmlrpc",     _WORDPRESS_XMLRPC,["nginx_access","apache_access"],           lambda m: {},                          45),
    LogPattern("wordpress_user_enum",  _WORDPRESS_ENUM,  ["nginx_access","apache_access"],           lambda m: {},                          30),
    LogPattern("phpmyadmin_probe",     _PHPMYADMIN,      ["nginx_access","apache_access"],           lambda m: {},                          40),

    LogPattern("mysql_auth_failure",   _MYSQL_FAIL,      ["mysql","syslog","custom"], lambda m: {"ip": m.group("ip"), "user": m.group("user")}, 30),
    LogPattern("pgsql_auth_failure",   _PGSQL_FAIL,      ["postgresql","syslog","custom"], lambda m: {"ip": _ip(m,"ip"), "user": m.group("user")}, 30),
    LogPattern("mongodb_auth_failure", _MONGODB_FAIL,    ["mongodb","syslog","custom"], lambda m: {"ip": m.group("ip") or m.group("ip2")}, 35),
    LogPattern("redis_noauth",         _REDIS_NOAUTH,    ["redis","syslog","custom"], lambda m: {"ip": m.group("ip") or m.group("ip2")},  35),

    LogPattern("ftp_fail_vsftpd",      _FTP_FAIL_VSFTPD, ["ftp","syslog"],  lambda m: {"ip": m.group("ip")},                              22),
    LogPattern("ftp_fail_pureftpd",    _FTP_FAIL_PURE,   ["ftp","syslog"],  lambda m: {"ip": m.group("ip")},                              22),
    LogPattern("ftp_fail_proftpd",     _FTP_FAIL_PROFTPD,["ftp","syslog"],  lambda m: {"ip": m.group("ip"), "user": m.group("user")},     22),
    LogPattern("ftp_anon_write",       _FTP_ANON_ABUSE,  ["ftp","syslog"],  lambda m: {"ip": m.group("ip")},                              55),

    LogPattern("ufw_block",            _UFW_BLOCK,       ["kernel","syslog"], lambda m: {"ip": m.group("ip")},                            15),
    LogPattern("iptables_drop",        _IPTABLES_DROP,   ["kernel","syslog"], lambda m: {"ip": m.group("ip")},                            12),

    LogPattern("docker_api_access",    _DOCKER_API,      ["nginx_access","apache_access","docker","custom"], lambda m: {},                 50),
    LogPattern("docker_exec_attempt",  _DOCKER_EXEC,     ["nginx_access","apache_access","docker","custom"], lambda m: {},                 75),
    LogPattern("k8s_api_probe",        _K8S_API,         ["nginx_access","apache_access","k8s","custom"],    lambda m: {},                 55),
    LogPattern("k8s_unauth",           _K8S_UNAUTH,      ["nginx_access","apache_access","k8s","custom"],    lambda m: {},                 40),

    LogPattern("cloud_metadata_ssrf",  _CLOUD_METADATA,  ["nginx_access","apache_access","custom"],          lambda m: {},                 70),

    LogPattern("tmp_execution",        _TMP_EXEC,        ["syslog","kernel","custom"],  lambda m: {"path": m.group("path")},               75),
    LogPattern("auditd_tmp_exec",      _AUDITD_EXEC,     ["audit","custom"],            lambda m: {"path": m.group("path")},               75),

    LogPattern("ldap_auth_failure",    _LDAP_FAIL,       ["syslog","ldap","custom"],    lambda m: {"ip": m.group("ip") or m.group("ip2")}, 30),
    LogPattern("vnc_auth_failure",     _VNC_FAIL,        ["syslog","vnc","custom"],     lambda m: {"ip": m.group("ip") or m.group("ip2")}, 30),
    LogPattern("rdp_auth_failure",     _RDP_FAIL,        ["syslog","rdp","custom"],     lambda m: {"ip": m.group("ip") or m.group("ip2")}, 30),
]

PATTERNS_BY_TYPE: Dict[str, List[LogPattern]] = {}
for _p in PATTERNS:
    for _t in _p.log_types:
        PATTERNS_BY_TYPE.setdefault(_t, []).append(_p)
PATTERNS_BY_TYPE.setdefault("custom", PATTERNS)
