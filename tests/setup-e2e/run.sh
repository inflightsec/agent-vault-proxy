#!/usr/bin/env bash
#
# Integration harness for `avp setup --no-service`: build the wheel,
# provision a disposable Ubuntu container for real, assert the end state
# with setup.bats. Mirrors tests/docker-e2e (idempotent, teardown trap,
# --keep to debug). Service ACTIVATION is out of scope by design — the
# unit FILE is asserted, systemd never started. See README.md for the
# real-Mac leg.
#
# Usage: bash tests/setup-e2e/run.sh [--keep]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONTAINER="avp-setup-e2e"
# Ubuntu LTS, tag-pinned like the docker-e2e upstream image; swap in a
# digest pin if this ever runs outside CI + local dev.
IMAGE="ubuntu:24.04"

KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }
red()    { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

WHEEL_DIR="$(mktemp -d)"

teardown() {
    rm -rf "$WHEEL_DIR"
    if [ "$KEEP" -eq 1 ]; then
        yellow "--keep set; tear down later with: docker rm -f $CONTAINER; docker volume rm $CONTAINER-log"
        return
    fi
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    docker volume rm "$CONTAINER-log" >/dev/null 2>&1 || true
}
trap teardown EXIT

green "[1/4] Tearing down any previous run..."
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

green "[2/4] Building the wheel..."
if command -v uv >/dev/null 2>&1; then
    (cd "$REPO_ROOT" && uv build --wheel --out-dir "$WHEEL_DIR" >/dev/null)
else
    (cd "$REPO_ROOT" && python3 -m build --wheel --outdir "$WHEEL_DIR" >/dev/null)
fi
# Deps install --require-hashes in the container — never resolved live
# from open ranges as root.
cp "$REPO_ROOT/requirements.lock" "$WHEEL_DIR/"

green "[3/4] Starting container, installing wheel + bats..."
# CAP_LINUX_IMMUTABLE: chattr +a (append-only audit log) is not in the
# default docker capability set, and setup treats the lock failure as
# fatal by design — grant the cap rather than weaken the invariant.
# The log dir is a named volume (real ext4, not overlayfs) because
# overlayfs upper layers may refuse inode-flag changes (EOPNOTSUPP)
# even with the capability granted.
docker run -d --name "$CONTAINER" \
    --cap-add LINUX_IMMUTABLE \
    -v "$WHEEL_DIR":/wheels:ro \
    -v "$SCRIPT_DIR":/suite:ro \
    -v "$CONTAINER-log":/var/log/kow \
    "$IMAGE" sleep infinity >/dev/null

docker exec "$CONTAINER" bash -eu -o pipefail -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q >/dev/null
    apt-get install -yq --no-install-recommends \
        python3 python3-venv sudo bats e2fsprogs ca-certificates >/dev/null
    python3 -m venv /opt/avp
    /opt/kow/bin/pip install --quiet --require-hashes --only-binary :all: \
        -r /wheels/requirements.lock
    /opt/kow/bin/pip install --quiet --no-deps /wheels/*.whl
    ln -s /opt/kow/bin/avp /usr/local/bin/avp
'

green "[4/4] Running setup.bats inside the container..."
if docker exec "$CONTAINER" bats /suite/setup.bats; then
    green "All setup E2E assertions passed."
else
    red "setup.bats failed — provisioned state for diagnosis:"
    docker exec "$CONTAINER" bash -c '
        id avp || true
        ls -laR /etc/kow /var/lib/kow \
            /var/log/kow /etc/systemd/system 2>/dev/null || true
        lsattr /var/log/kow/audit.jsonl 2>/dev/null || true
    ' >&2 || true
    exit 1
fi
