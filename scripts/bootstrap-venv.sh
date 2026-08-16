#!/usr/bin/env bash
#
# Bootstrap (or rebuild) the project's .venv from scratch.
#
# Why a script (not docs): the install dance is non-obvious because of two
# competing constraints:
#   1. Lockfile is `--require-hashes` (supply-chain mitigation — every dep
#      pinned to an upstream sha256). Good.
#   2. The project itself is local source — there IS no upstream hash for
#      `file:///path/to/kow`, so `uv pip sync` and
#      `uv pip install -e ".[dev]"` both fail in `--require-hashes` mode.
#
# Solution: install hash-pinned deps first (lockfile), then install the
# project editable with `--no-deps` so uv doesn't re-resolve the deps
# (which would either redownload them or clash with the locked versions).
#
# Usage:
#   bash scripts/bootstrap-venv.sh                  # uses python3.12 via uv
#   PY=python3.13 bash scripts/bootstrap-venv.sh    # override interpreter
#
# Re-runnable — wipes .venv each time. Takes ~10s with warm uv cache.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v uv >/dev/null 2>&1; then
    echo "uv not on PATH. Install: curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
    exit 1
fi

# Interpreter selection. Default is 3.12 — matches pyproject `requires-python`
# floor AND the CI test matrix. uv will fetch a managed copy if no system
# 3.12 is available, so this works on Arch (system python is 3.14) without
# fuss.
PY="${PY:-python3.12}"

echo "── Wiping .venv ──"
# .venv may be a per-host bind mount (ansible role avp-dev-venv-mount) so two
# hosts sharing the NFS tree don't clobber each other's venv. `rm -rf .venv`
# fails on a live mountpoint (busy) — clear the CONTENTS and keep the mountpoint
# when it's mounted; otherwise remove it as before.
if mountpoint -q .venv 2>/dev/null; then
    find .venv -mindepth 1 -delete
else
    rm -rf .venv
fi

echo "── Creating .venv with $PY ──"
uv venv .venv --python "$PY"

echo "── Installing hash-pinned dev deps from lockfile ──"
uv pip install --require-hashes -r requirements-dev.lock

echo "── Installing project editable (no-deps; deps already pinned above) ──"
# Why UV_REQUIRE_HASHES=false for this one step: some hardened operator
# environments set `UV_REQUIRE_HASHES=true` globally as a supply-chain
# mitigation — every `uv pip install` then verifies an upstream sha256.
# That's the right default for third-party deps, but the project's own
# editable install (`-e .` against local source) has no upstream hash to
# verify against, so the install would fail with "no hash provided". The
# unset is scoped to this one invocation; the deps above were installed
# under full hash verification, so the security posture is preserved.
# Harmless no-op when UV_REQUIRE_HASHES isn't set in the first place.
UV_REQUIRE_HASHES=false uv pip install --no-deps -e .

echo
echo "✓ .venv ready. Verify:"
echo "    .venv/bin/python -c 'import kow; print(kow.__version__)'"
echo "    .venv/bin/pytest -q"
