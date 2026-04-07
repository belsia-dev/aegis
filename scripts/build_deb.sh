#!/usr/bin/env bash
set -euo pipefail

if ! command -v dpkg-buildpackage >/dev/null 2>&1; then
    echo "dpkg-buildpackage is required. Install Debian packaging tools first." >&2
    exit 1
fi

repo_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

dpkg-buildpackage -us -uc -b
