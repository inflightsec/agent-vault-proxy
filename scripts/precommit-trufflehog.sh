#!/usr/bin/env bash
# TruffleHog secret scan over the unpushed diff. Mirrors the CI security
# job using the same Docker image, so a pre-commit-clean repo will pass CI
# secret-scanning. --only-verified filters unverified matches (high noise),
# --since-commit HEAD limits to the staged change to keep commits fast.
#
# Graceful degradation: if Docker isn't on PATH, skip with a warning. CI
# remains the enforcement gate.
set -euo pipefail

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "docker not available (binary missing or daemon unreachable) — skipping TruffleHog (CI will catch it)."
    echo "Install/start: https://docs.docker.com/get-docker/  or use OrbStack on macOS."
    exit 0
fi

# Pinned to a specific tag, not :latest. Pre-commit threat model is the
# operator's local machine; CI uses the SHA-pinned action. Tag-pinning here
# keeps the local feedback loop fast without dragging in supply-chain risk
# beyond what `docker pull` already implies.
IMAGE="trufflesecurity/trufflehog:3.91.0"

docker run --rm \
    -v "$(pwd):/workdir" \
    "$IMAGE" \
    git file:///workdir \
    --since-commit HEAD \
    --only-verified \
    --fail
