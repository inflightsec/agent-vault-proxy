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

# Cooldown cutoff: midnight UTC of 7 days ago. The time portion is
# rounded to 00:00:00 so the cutoff is stable for ~24h — a regen at
# 20:07 and a pre-commit re-run at 20:09 produce identical resolutions.
# The per-second variant flapped on any commit that crossed a package's
# release minute. Security property ("don't install anything younger
# than ~7 days") unchanged; rounding down to midnight only ever makes
# the cutoff stricter, never weaker.
# `date -d` is GNU-only; BSD date on macOS doesn't accept it. Python's
# datetime is in every supported Python version and produces identical
# ISO-8601 output across platforms.
CUTOFF=$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT00:00:00Z"))')
echo "Cooldown cutoff: $CUTOFF"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Suppress stdout (each line of the resolved tree, noisy), but let stderr
# through — if uv fails, the operator needs to see the reason (e.g. older
# uv missing `--exclude-newer`, or a transient network error).
uv pip compile --generate-hashes --exclude-newer "$CUTOFF" \
    pyproject.toml -o "$TMP/requirements.lock.fresh" >/dev/null
uv pip compile --generate-hashes --exclude-newer "$CUTOFF" --extra dev \
    pyproject.toml -o "$TMP/requirements-dev.lock.fresh" >/dev/null

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
  CUTOFF=\$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT00:00:00Z"))')
  uv pip compile --generate-hashes --exclude-newer "\$CUTOFF" \\
      pyproject.toml -o requirements.lock
  uv pip compile --generate-hashes --exclude-newer "\$CUTOFF" --extra dev \\
      pyproject.toml -o requirements-dev.lock
EOF
    exit 1
fi
echo "Lockfiles in sync."
