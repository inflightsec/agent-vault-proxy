#!/usr/bin/env bash
# Re-compile both lockfiles into tempfiles with the 7-day supply-chain cooldown
# and diff against committed. Mirrors the verify-lockfile CI job so drift gets
# caught locally before it ever hits a PR.
#
# Requires uv on PATH. If uv is missing, exits 0 with a warning rather than
# blocking the commit — the CI job is the enforcement gate. This script is the
# fast-feedback loop for operators who have uv installed.
set -euo pipefail

if ! command -v uv >/dev/null 2>&1; then
    echo "uv not on PATH — skipping lockfile drift check (CI will catch it)."
    echo "Install: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 0
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Portable cooldown cutoff (7 days ago in UTC). `date -d` is GNU-only; BSD
# date on macOS doesn't accept it. Python's datetime is in every supported
# Python version and produces identical ISO-8601 output across platforms.
CUTOFF=$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ"))')
echo "Cooldown cutoff: $CUTOFF"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

uv pip compile --generate-hashes --exclude-newer "$CUTOFF" \
    pyproject.toml -o "$TMP/requirements.lock.fresh" >/dev/null 2>&1
uv pip compile --generate-hashes --exclude-newer "$CUTOFF" --extra dev \
    pyproject.toml -o "$TMP/requirements-dev.lock.fresh" >/dev/null 2>&1

fail=0
for lock in requirements.lock requirements-dev.lock; do
    sed '/^#/d' "$lock" >"$TMP/${lock}.committed.stripped"
    sed '/^#/d' "$TMP/${lock}.fresh" >"$TMP/${lock}.fresh.stripped"
    if ! diff -q "$TMP/${lock}.committed.stripped" "$TMP/${lock}.fresh.stripped" >/dev/null; then
        echo "DRIFT in $lock:"
        diff -u "$TMP/${lock}.committed.stripped" "$TMP/${lock}.fresh.stripped" | head -50
        fail=1
    fi
done

if [ "$fail" -ne 0 ]; then
    cat >&2 <<EOF

Lockfile drift detected. Either:
  (a) pyproject.toml changed without regenerating the lockfile, or
  (b) the lockfile pins a version younger than the 7-day cooldown.

Regenerate:
  CUTOFF=\$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ"))')
  uv pip compile --generate-hashes --exclude-newer "\$CUTOFF" \\
      pyproject.toml -o requirements.lock
  uv pip compile --generate-hashes --exclude-newer "\$CUTOFF" --extra dev \\
      pyproject.toml -o requirements-dev.lock
EOF
    exit 1
fi
echo "Lockfiles in sync."
