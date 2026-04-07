#!/usr/bin/env bash

_AEGIS_API="${AEGIS_API:-http://127.0.0.1:8731}"
_AEGIS_USER="${AEGIS_USER:-admin}"
_AEGIS_PASS="${AEGIS_PASS:-changeme}"
_REAL_BASH="$(command -p which bash 2>/dev/null || echo /bin/bash)"
_REAL_SH="$(command -p which sh 2>/dev/null || echo /bin/sh)"
_REAL_CURL="$(command -p which curl 2>/dev/null || echo /usr/bin/curl)"
_REAL_WGET="$(command -p which wget 2>/dev/null || echo /usr/bin/wget)"

_aegis_analyze() {
    local script="$1"
    local source="${2:-interactive}"

    if ! command -v "$_REAL_CURL" &>/dev/null; then
        echo "[AEGIS] WARNING: Cannot reach analysis API — allowing (curl not found)" >&2
        return 0
    fi

    local response
    response=$("$_REAL_CURL" -s -m 5 \
        -X POST "${_AEGIS_API}/api/analyze" \
        -u "${_AEGIS_USER}:${_AEGIS_PASS}" \
        -H "Content-Type: text/plain" \
        -H "X-Source: ${source}" \
        --data-binary "$script" 2>/dev/null)

    if [ -z "$response" ]; then
        echo "[AEGIS] WARNING: Analysis API unreachable — allowing" >&2
        return 0
    fi

    local safe score findings
    safe=$(echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print('yes' if d.get('safe', True) else 'no')
except:
    print('yes')
" 2>/dev/null)

    if [ "$safe" = "no" ]; then
        echo "" >&2
        echo "╔══════════════════════════════════════════════════════╗" >&2
        echo "║  ⚔  AEGIS — SCRIPT BLOCKED                          ║" >&2
        echo "╚══════════════════════════════════════════════════════╝" >&2
        echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(f'  Score  : {d[\"score\"]}/100', file=sys.stderr)
    print(f'  Layers : {d[\"layers\"]} obfuscation layers decoded', file=sys.stderr)
    for f in d.get('findings', [])[:8]:
        sev = f['severity']
        icon = '🔴' if sev >= 60 else '🟡' if sev >= 30 else '🟠'
        print(f'  {icon} [{f[\"category\"]}] {f[\"detail\"]}', file=sys.stderr)
except:
    pass
" 2>&1
        echo "" >&2
        return 1
    else
        echo "$response" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    if d.get('score', 0) > 0 or d.get('layers', 0) > 0:
        print(f'[AEGIS] Script analyzed — score {d[\"score\"]}/100, {d[\"layers\"]} obfuscation layers', file=sys.stderr)
    else:
        print('[AEGIS] Script analyzed — clean ✓', file=sys.stderr)
except:
    pass
" 2>&1
        return 0
    fi
}

bash() {
    if [ ! -t 0 ]; then
        local script
        script=$(cat)
        if ! _aegis_analyze "$script" "bash_pipe"; then
            return 1
        fi
        echo "$script" | command "$_REAL_BASH" "$@"
    else
        command "$_REAL_BASH" "$@"
    fi
}

sh() {
    if [ ! -t 0 ]; then
        local script
        script=$(cat)
        if ! _aegis_analyze "$script" "sh_pipe"; then
            return 1
        fi
        echo "$script" | command "$_REAL_SH" "$@"
    else
        command "$_REAL_SH" "$@"
    fi
}

curl() {
    command "$_REAL_CURL" "$@"
}

wget() {
    command "$_REAL_WGET" "$@"
}

export -f bash sh curl wget _aegis_analyze 2>/dev/null || true
