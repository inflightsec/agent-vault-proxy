#!/usr/bin/env bash
# Semgrep pattern-SAST over src/. Mirrors the CI security job: same three
# rulesets (security-audit, python, secrets), same --error gate, same
# --metrics=off opt-out.
#
# Runs only when a src/ Python file changed (pre-commit `files:` filter).
# Without that scoping, semgrep would run on every doc-only commit and
# make commits feel slow.
#
# Graceful degradation: if Docker isn't on PATH, skip with a warning. CI
# remains the enforcement gate.
set -euo pipefail

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo "docker not available (binary missing or daemon unreachable) — skipping Semgrep (CI will catch SAST findings)."
    echo "Install/start: https://docs.docker.com/get-docker/  or use OrbStack on macOS."
    exit 0
fi

IMAGE="semgrep/semgrep:1.90.0"

docker run --rm \
    -v "$(pwd):/src" \
    -w /src \
    "$IMAGE" \
    semgrep \
    --config=p/security-audit \
    --config=p/python \
    --config=p/secrets \
    --error \
    --metrics=off \
    src/
