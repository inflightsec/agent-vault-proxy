#!/usr/bin/env bash
# Runs INSIDE the Linux VM, as root. Provides the one thing the setup-e2e
# harness needs and the agent sandbox cannot offer — a real Docker daemon — then
# hands off to tests/setup-e2e/run.sh unmodified.
#
# That harness builds a wheel, provisions a disposable Ubuntu container, runs
# `kow setup` in it for real, and asserts the end state with bats. It is the only
# check that the documented provisioning actually produces the documented
# layout, which is exactly the drift that broke CI when the avp->kow rename
# missed tests/setup-e2e/.
set -uo pipefail

SRC="${KOW_SRC:-/home/debian/kow-src}"
export DEBIAN_FRONTEND=noninteractive

step() { printf '\n== %s\n' "$*"; }
red()  { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

step "0. prerequisites (docker + build tooling)"
# cloud-init holds the apt lock on a fresh boot; racing it deadlocks.
cloud-init status --wait >/dev/null 2>&1 || true
# cloud-init usually refreshes the index (package_update: true), but this script
# must also work in a guest where it did not.
apt-get update -qq >/tmp/setup-e2e-apt.log 2>&1 \
  || echo "  note: apt-get update failed; installs below may use a stale index"
command -v docker >/dev/null 2>&1 || apt-get install -y -qq docker.io >>/tmp/setup-e2e-apt.log 2>&1
command -v python3 >/dev/null 2>&1 || apt-get install -y -qq python3 >>/tmp/setup-e2e-apt.log 2>&1
python3 -m venv --help >/dev/null 2>&1 || apt-get install -y -qq python3-venv >>/tmp/setup-e2e-apt.log 2>&1
python3 -m pip --version >/dev/null 2>&1 || apt-get install -y -qq python3-pip >>/tmp/setup-e2e-apt.log 2>&1
# The harness builds a wheel with `python3 -m build`. Debian marks the system
# interpreter externally-managed (PEP 668), so pip-installing into it fails —
# take the distro package, and only fall back to pip if that is unavailable.
python3 -m build --version >/dev/null 2>&1 \
  || apt-get install -y -qq python3-build >>/tmp/setup-e2e-apt.log 2>&1
python3 -m build --version >/dev/null 2>&1 \
  || python3 -m pip install --break-system-packages -q build >>/tmp/setup-e2e-apt.log 2>&1
systemctl enable --now docker >/dev/null 2>&1

docker info >/dev/null 2>&1 || { red "docker daemon unreachable"; tail -20 /tmp/setup-e2e-apt.log; exit 1; }
python3 -m build --version >/dev/null 2>&1 || { red "python -m build unavailable"; tail -20 /tmp/setup-e2e-apt.log; exit 1; }
command -v bats >/dev/null 2>&1 || apt-get install -y -qq bats >>/tmp/setup-e2e-apt.log 2>&1
printf '  docker: %s\n' "$(docker --version)"
printf '  build:  %s\n' "$(python3 -m build --version 2>&1 | head -1)"

step "1. hand off to the real harness (unmodified)"
[ -d "$SRC" ] || { red "no source tree at $SRC"; exit 1; }
cd "$SRC" || exit 1
# The harness builds its own wheel with `python3 -m build` in a venv; it needs
# network for the base image and PyPI, which the VM has.
bash tests/setup-e2e/run.sh
rc=$?

printf '\n===== setup-e2e in VM: exit %d =====\n' "$rc"
exit "$rc"
