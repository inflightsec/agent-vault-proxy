#!/usr/bin/env bash
# Full-stack VM end-to-end for keys-on-the-wire.
#
# Boots a throwaway Debian VM under QEMU/KVM with REAL systemd, follows
# docs/install-systemd.md for the static backend, starts the service for real,
# and asserts the whole chain on the wire. This is the only harness that can
# exercise systemd, chattr +a, a real service user, and journald — none of
# which work in a container or the agent sandbox.
#
# Usage: bash tests/vm-e2e/run.sh [--keep] [systemd|docker|rootless|all]
#   --keep   leave the VM running for debugging (ssh -p 2222 debian@127.0.0.1)
#   legs     systemd (default) | tls | docker | rootless | pypi | readme | all
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="${KOW_VM_WORK:-/tmp/kow-vm}"
BASE="$WORK/debian-13.qcow2"
IMG_URL="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
OVERLAY="$WORK/run-$$.qcow2"
SSH_PORT="${KOW_VM_SSH_PORT:-2222}"
CI_PORT="${KOW_VM_CI_PORT:-8877}"   # MUST be >1024: we are not root
KEEP=0; LEGS="systemd"
for a in "$@"; do
  case "$a" in
    --keep) KEEP=1 ;;
    systemd|docker|rootless|tls|pypi|readme|all) LEGS="$a" ;;
  esac
done
[ "$LEGS" = "all" ] && LEGS="systemd tls docker rootless pypi readme"

green(){ printf '\033[1;32m%s\033[0m\n' "$*"; }
red(){ printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

QEMU_PID=""; HTTP_PID=""
cleanup() {
  [ -n "$HTTP_PID" ] && kill "$HTTP_PID" 2>/dev/null
  if [ "$KEEP" = "1" ]; then echo "--keep: VM left on ssh port $SSH_PORT (user: debian)"; return; fi
  [ -n "$QEMU_PID" ] && kill "$QEMU_PID" 2>/dev/null
  rm -f "$OVERLAY" "$WORK/id_vm" "$WORK/id_vm.pub"
  rm -rf "$WORK/seed"
}
trap cleanup EXIT

mkdir -p "$WORK/seed"
[ -f "$BASE" ] || { echo "fetching base image..."; curl -sSL --max-time 2400 -o "$BASE" "$IMG_URL" || { red "image download failed"; exit 1; }; }

# --- build the artefacts the guest needs -------------------------------------
# Ship the SOURCE TREE, not a wheel: the repo pins --require-hashes for supply
# chain, which blocks a local build-isolation build. The guest has a clean pip
# and resolves runtime deps itself — and we install THIS tree, not the last
# published release.
echo "staging source tree for the guest..."
rm -rf "$WORK/seed/kow-src"
rsync -a --exclude .venv --exclude .git --exclude __pycache__ --exclude .mypy_cache \
      --exclude .pytest_cache --exclude demo --exclude dist "$REPO"/ "$WORK/seed/kow-src"/

# The unit file is prose-referenced by install-systemd.md §4 ("copy the hardened
# unit from systemd-unit.md"), so extract it from that doc — the doc stays the
# source of truth.
python3 - "$REPO/docs/systemd-unit.md" > "$WORK/seed/kow.service" <<'PY'
import re, sys, pathlib
text = pathlib.Path(sys.argv[1]).read_text()
m = re.search(r"```(?:ini|systemd)?\n(\[Unit\].*?)```", text, re.S)
if not m:
    sys.exit("no [Unit] block found in systemd-unit.md")
print(m.group(1).rstrip())
PY
grep -q '^\[Unit\]' "$WORK/seed/kow.service" || { red "extracted unit looks wrong"; exit 1; }
cp "$REPO"/tests/vm-e2e/guest-*.sh "$WORK/seed/"

ssh-keygen -q -t ed25519 -N '' -f "$WORK/id_vm" <<<y >/dev/null 2>&1
PUBKEY=$(cat "$WORK/id_vm.pub")

# --- cloud-init over SMBIOS+HTTP (no ISO tooling needed) ---------------------
cat > "$WORK/seed/meta-data" <<EOF
instance-id: kow-e2e
local-hostname: kow-e2e
EOF
cat > "$WORK/seed/user-data" <<EOF
#cloud-config
ssh_authorized_keys:
  - ${PUBKEY}
disable_root: false
packages: [python3-venv, e2fsprogs, iproute2, curl]
package_update: true
runcmd:
  - [ touch, /run/cloud-init-done ]
EOF
( cd "$WORK/seed" && python3 -m http.server "$CI_PORT" --bind 127.0.0.1 >"$WORK/httpd.log" 2>&1 & echo $! > "$WORK/http.pid" )
sleep 1
curl -sf "http://127.0.0.1:${CI_PORT}/user-data" >/dev/null || { red "cloud-init seed server not serving on ${CI_PORT}"; cat "$WORK/httpd.log"; exit 1; }
HTTP_PID=$(cat "$WORK/http.pid")

qemu-img create -q -f qcow2 -F qcow2 -b "$BASE" "$OVERLAY" 20G

echo "booting VM (kvm)..."
qemu-system-x86_64 -enable-kvm -m 4096 -smp 4 -nographic -no-reboot \
  -drive file="$OVERLAY",if=virtio,format=qcow2 \
  -netdev user,id=n0,hostfwd=tcp:127.0.0.1:${SSH_PORT}-:22 -device virtio-net-pci,netdev=n0 \
  -smbios "type=1,serial=ds=nocloud-net;s=http://10.0.2.2:${CI_PORT}/" \
  > "$WORK/console.log" 2>&1 &
QEMU_PID=$!

# -F /dev/null: some hosts (the agent sandbox) have /etc/ssh/ssh_config.d
# drop-ins owned by a non-root uid, and the ssh CLIENT then refuses to run at
# all ("Bad owner or permissions"). Ignoring system config sidesteps it.
SSH="ssh -F /dev/null -p $SSH_PORT -i $WORK/id_vm -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5"
echo -n "waiting for ssh"
for i in $(seq 1 90); do
  $SSH debian@127.0.0.1 true 2>/dev/null && break
  echo -n .; sleep 4
done
echo
$SSH debian@127.0.0.1 true 2>/dev/null || { red "VM never became reachable — see $WORK/console.log"; tail -30 "$WORK/console.log"; exit 1; }
green "VM up"

# cloud-init is still running its own apt transaction at first ssh; racing it
# deadlocks on /var/lib/apt/lists/lock.
echo "waiting for cloud-init to settle..."
$SSH debian@127.0.0.1 'sudo cloud-init status --wait >/dev/null 2>&1 || true'

echo "copying artefacts..."
scp -F /dev/null -P "$SSH_PORT" -i "$WORK/id_vm" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
  -r "$WORK/seed/kow-src" "$WORK/seed/kow.service" "$WORK"/seed/guest-*.sh debian@127.0.0.1:/home/debian/ >/dev/null || { red "scp failed"; exit 1; }

RC=0
for leg in $LEGS; do
  case "$leg" in
    systemd)  echo; green "### LEG: systemd (documented bare-metal install)"
              $SSH debian@127.0.0.1 'sudo bash /home/debian/guest-install.sh' 2>&1 | tee "$WORK/guest-systemd.log" ;;
    docker)   echo; green "### LEG: docker (container path)"
              $SSH debian@127.0.0.1 'sudo bash /home/debian/guest-docker.sh' 2>&1 | tee "$WORK/guest-docker.log" ;;
    rootless) echo; green "### LEG: rootless (unprivileged, no sudo)"
              $SSH debian@127.0.0.1 'bash /home/debian/guest-rootless.sh' 2>&1 | tee "$WORK/guest-rootless.log" ;;
    tls)      echo; green "### LEG: tls (real interception — the core capability)"
              $SSH debian@127.0.0.1 'sudo bash /home/debian/guest-tls.sh' 2>&1 | tee "$WORK/guest-tls.log" ;;
    pypi)     echo; green "### LEG: pypi (build + install from a mock index)"
              $SSH debian@127.0.0.1 'sudo bash /home/debian/guest-pypi.sh' 2>&1 | tee "$WORK/guest-pypi.log" ;;
    readme)   echo; green "### LEG: readme (walk the README quickstart)"
              $SSH debian@127.0.0.1 'bash /home/debian/guest-readme.sh' 2>&1 | tee "$WORK/guest-readme.log" ;;
  esac
  [ "${PIPESTATUS[0]}" -ne 0 ] && RC=1
done

echo
if [ "$RC" -eq 0 ]; then green "VM E2E: ALL LEGS PASS ($LEGS)"; else red "VM E2E: FAILURES in one or more legs"; fi
exit "$RC"
