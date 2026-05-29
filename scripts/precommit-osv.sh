#!/usr/bin/env bash
# OSV-Scanner CVE check across both lockfiles. Mirrors the CI security job.
# Runs only when pyproject.toml or a lockfile changed (pre-commit filters
# the trigger; this script gets called by that filter).
#
# Graceful degradation: if Docker isn't on PATH, skip with a warning. CI
# remains the enforcement gate.
set -euo pipefail

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "docker not available (binary missing or daemon unreachable) — skipping OSV-Scanner (CI will catch new CVEs)."
    echo "Install/start: https://docs.docker.com/get-docker/  or use OrbStack on macOS."
    exit 0
fi

# Same pin posture as TruffleHog: specific tag, not :latest.
IMAGE="ghcr.io/google/osv-scanner:v2.0.3"

# `requirements.txt:` is the parse-as prefix — our files are named *.lock
# for clarity, but OSV-Scanner's filename heuristic only recognizes the
# literal name `requirements.txt`. The prefix forces the pip extractor.
docker run --rm \
    -v "$(pwd):/src" \
    -w /src \
    "$IMAGE" \
    --lockfile=requirements.txt:requirements.lock \
    --lockfile=requirements.txt:requirements-dev.lock
