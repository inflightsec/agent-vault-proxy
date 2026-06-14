#!/usr/bin/env bash
# Regenerate both lockfiles in place against the 7-day supply-chain cooldown,
# verify they changed on disk, and stage them. The write-side counterpart to
# check-lockfile-drift.sh. After this runs you can go straight to `git commit`
# without needing to remember `git add`.
#
# Does not commit or push.
set -euo pipefail

if ! command -v uv >/dev/null 2>&1; then
    echo "uv not on PATH — install with: curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

CUTOFF=$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT00:00:00Z"))')
echo "Cooldown cutoff: $CUTOFF"

# Hash before to detect whether uv actually changed anything on disk. Avoids
# the silent-no-op failure mode where uv runs but writes the same bytes.
hash_before_prod=$(sha256sum requirements.lock | awk '{print $1}')
hash_before_dev=$(sha256sum requirements-dev.lock | awk '{print $1}')

# Write to fresh tempfiles, NOT directly to requirements.lock /
# requirements-dev.lock. Critical reason: when `uv pip compile -o <path>` finds
# an existing file at <path>, it reads version pins from it and prefers them
# where compatible — preserving stale versions across a rollforward. The drift
# checker writes to a tempfile (true clean resolution), so the two would
# disagree forever. Writing to tempfiles here matches the drift checker's
# semantics; the atomic move puts the truly-fresh resolution in place.
#
# --refresh also forces uv to re-fetch PyPI metadata rather than trust its
# local cache. Belt-and-suspenders alongside the tempfile pattern.
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
uv pip compile --universal --refresh --generate-hashes --exclude-newer "$CUTOFF" \
    pyproject.toml -o "$TMP/requirements.lock" >/dev/null
uv pip compile --universal --refresh --generate-hashes --exclude-newer "$CUTOFF" --extra dev \
    pyproject.toml -o "$TMP/requirements-dev.lock" >/dev/null
mv "$TMP/requirements.lock"     requirements.lock
mv "$TMP/requirements-dev.lock" requirements-dev.lock

hash_after_prod=$(sha256sum requirements.lock | awk '{print $1}')
hash_after_dev=$(sha256sum requirements-dev.lock | awk '{print $1}')

changed=()
[ "$hash_before_prod" != "$hash_after_prod" ] && changed+=("requirements.lock")
[ "$hash_before_dev"  != "$hash_after_dev"  ] && changed+=("requirements-dev.lock")

if [ ${#changed[@]} -eq 0 ]; then
    echo "No drift to absorb — lockfiles already match fresh resolution."
    exit 0
fi

echo "Regenerated: ${changed[*]}"

# Stage so the next `git commit` actually picks them up. Pre-commit stashes
# unstaged changes before running hooks — without this, the drift hook re-runs
# against the old committed locks and re-fails.
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git add "${changed[@]}"
    echo "Staged. Review:  git diff --cached requirements.lock requirements-dev.lock"
else
    echo "Not inside a git work tree — skipped staging."
fi
