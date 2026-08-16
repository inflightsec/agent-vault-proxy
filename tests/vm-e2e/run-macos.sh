#!/usr/bin/env bash
# macOS leg of the VM end-to-end. Drives the Sequoia VM that already exists on
# the mainframe for the Laima iOS gate (~/ios-gate-dev, ADR-0036): revert to the
# golden snapshot, boot, install the documented prerequisites, then run the
# documented macOS install (dscl account, /usr/local prefix, chflags sappnd,
# launchd) and assert the same chain the Linux leg does.
#
# The VM is a SHARED resource. This always reverts to golden before and after,
# and never writes a new snapshot.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
GATE="${KOW_MACOS_GATE:-$HOME/ios-gate-dev}"
TAP="${KOW_TAP:-/home/shared/nfs/src/homebrew-keys-on-the-wire}"
LEGS="${1:-launchd}"; [ "$LEGS" = "all" ] && LEGS="launchd brew"
DISK="$GATE/macos-sequoia/disk.qcow2"
VMSSH="$GATE/vmssh"
PY_GUEST=/usr/local/opt/python@3.13/bin/python3.13

green(){ printf '\033[1;32m%s\033[0m\n' "$*"; }
red(){ printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

[ -x "$VMSSH" ] || { red "no macOS gate at $GATE"; exit 1; }

revert() { qemu-img snapshot -a golden "$DISK" >/dev/null 2>&1 && \
           cp "$GATE/macos-sequoia/OVMF_VARS.golden.fd" "$GATE/macos-sequoia/OVMF_VARS-1920x1080.fd" 2>/dev/null; }
stop_vm() { local p; p=$(pgrep -f 'name macos-sequoia,process' | head -1); [ -n "$p" ] && kill "$p" 2>/dev/null; sleep 6; }

cleanup() { stop_vm; revert; echo "VM stopped and reverted to golden"; }
trap cleanup EXIT

echo "==> reverting to golden + booting"
stop_vm; revert
( cd "$GATE" && nohup ./run-vm.sh run >/tmp/kow-macos-boot.log 2>&1 & )

echo -n "waiting for ssh"
for _ in $(seq 1 60); do "$VMSSH" true 2>/dev/null && break; printf .; sleep 10; done
echo
"$VMSSH" true 2>/dev/null || { red "VM never became reachable"; exit 1; }
green "VM up ($("$VMSSH" sw_vers -productVersion 2>/dev/null))"

echo "==> prerequisite: python >=3.12 (macOS ships 3.9)"
"$VMSSH" "test -x $PY_GUEST || (export HOMEBREW_NO_AUTO_UPDATE=1; brew install python@3.13 >/tmp/brewpy.log 2>&1)"
"$VMSSH" "$PY_GUEST -V" || { red "no usable python in guest"; exit 1; }

echo "==> syncing this tree"
SSHOPT="ssh -F /dev/null -i $GATE/vmkey -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
rsync -a -e "$SSHOPT" --exclude .venv --exclude .git --exclude __pycache__ --exclude .mypy_cache \
      --exclude .pytest_cache --exclude demo --exclude dist "$REPO"/ claude@127.0.0.1:kow-src/ || exit 1
SCP="scp -F /dev/null -i $GATE/vmkey -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
$SCP "$REPO"/tests/vm-e2e/guest-install-macos.sh "$REPO"/tests/vm-e2e/guest-brew.sh claude@127.0.0.1:./ || exit 1
# The brew leg tests the REAL tap formula, so ship it from the tap checkout.
if [ -f "$TAP/Formula/keys-on-the-wire.rb" ]; then
  $SCP "$TAP/Formula/keys-on-the-wire.rb" claude@127.0.0.1:kow-formula.rb || exit 1
else
  echo "note: no tap checkout at $TAP — the brew leg will be skipped"
fi

RC=0
for leg in $LEGS; do
  case "$leg" in
    launchd) echo; green "### LEG: launchd (documented macOS install)"
             "$VMSSH" 'bash ~/guest-install-macos.sh' || RC=1 ;;
    brew)    echo; green "### LEG: brew (real tap formula, built from source — slow)"
             if "$VMSSH" 'test -f ~/kow-formula.rb'; then
               # brew build-from-source outlives a normal ssh window; detach and poll.
               "$VMSSH" 'nohup bash ~/guest-brew.sh > ~/brew-e2e.log 2>&1 & echo started' >/dev/null
               for _ in $(seq 1 120); do
                 "$VMSSH" 'pgrep -f guest-brew >/dev/null' 2>/dev/null || break
                 sleep 15
               done
               "$VMSSH" 'cat ~/brew-e2e.log' || RC=1
               "$VMSSH" 'grep -q "0 failed" ~/brew-e2e.log' 2>/dev/null || RC=1
             else
               red "brew leg skipped (no formula staged)"; RC=1
             fi ;;
  esac
done

[ "$RC" -eq 0 ] && green "macOS VM E2E: ALL LEGS PASS ($LEGS)" || red "macOS VM E2E: FAILURES"
exit "$RC"
