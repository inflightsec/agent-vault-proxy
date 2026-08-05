#!/usr/bin/env bash
#
# Pre-tag dry-run: build the wheel and run the full PyPI smoke harness
# against it end-to-end. Same code path that release.yml's
# `pypi-install-smoke` job will exercise against the published PyPI
# artifact, but with no PyPI involvement and no version-number
# commitment.
#
# What it does:
#   1. Builds the wheel (via `uvx --from build pyproject-build`, so
#      `build` is installed into an isolated tool venv — no pollution
#      of the project's .venv, and the host Python doesn't need `build`
#      pre-installed).
#   2. Runs tests/pypi-smoke/run.sh --local-wheel <built-wheel>, which
#      stands up the proxy + an HTTP echo upstream in Docker and
#      exercises the positive (substitution) + negative (fail-closed)
#      assertions against the just-built wheel.
#
# Run this before EVERY tag push. If it goes green, the same harness
# will go green against the published PyPI artifact — the only
# variable between this run and release.yml's smoke is the install
# source (local file vs PyPI URL), which is one Dockerfile branch.
#
# Usage:
#   bash scripts/build-and-smoke-wheel.sh           # build + smoke
#   bash scripts/build-and-smoke-wheel.sh --keep    # leave docker stack up after
#
# Requires: uv (with uvx — ships in uv 0.3+), docker, docker compose v2.20+.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }
red()    { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

if ! command -v uvx >/dev/null 2>&1; then
    red "uvx not on PATH. Install uv:"
    red "  curl -LsSf https://astral.sh/uv/install.sh | sh"
    red "Then re-run this script."
    exit 1
fi

# ============================================================================
# 1. Build the wheel via uvx (isolated tool venv, no project-venv touch)
# ============================================================================
green "[1/2] Building wheel via uvx (isolated, no .venv pollution)..."
rm -rf dist
# `--wheel` skips the sdist — we only need the wheel for the smoke.
# uvx caches the build env; first run installs build + hatchling, every
# subsequent run is fast.
uvx --from build pyproject-build --wheel

WHEEL="$(ls dist/agent_vault_proxy-*.whl 2>/dev/null | head -1)"
if [ -z "$WHEEL" ]; then
    red "Build succeeded but no agent_vault_proxy-*.whl found in dist/"
    exit 1
fi
green "  ✓ Built $(basename "$WHEEL")"

# Assert the wheel actually SHIPS the entrypoint module. A wheel missing
# __main__.py installs cleanly but crash-loops under `-m agent_vault_proxy`
# (the 2026-08-03 incident). Catch it here, before the wheel is ever cached
# or published.
if ! unzip -l "$WHEEL" | grep -q 'agent_vault_proxy/__main__.py'; then
    red "Wheel is missing agent_vault_proxy/__main__.py — 'python -m agent_vault_proxy' would crash-loop."
    red "Contents:"; unzip -l "$WHEEL" | grep agent_vault_proxy || true
    exit 1
fi
green "  ✓ Wheel ships agent_vault_proxy/__main__.py"

# ============================================================================
# 2. Run the PyPI smoke harness against the local wheel
# ============================================================================
green "[2/2] Running PyPI smoke harness against the local wheel..."
exec bash tests/pypi-smoke/run.sh --local-wheel "$WHEEL" "$@"
