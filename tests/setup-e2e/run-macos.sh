#!/usr/bin/env bash
#
# Manual macOS smoke for `avp setup --no-service`. Provisions THIS Mac for
# real (creates the _avp service user + /usr/local/... layout + LaunchDaemon
# plist, never loaded), asserts the end state with setup.bats, then tears it
# all down. The Linux leg (run.sh) uses a throwaway container; the Mac has no
# container, so this script IS the disposable boundary.
#
# avp installs into a throwaway root-owned venv under /tmp — not your public
# PATH or system Python. `avp setup` bakes sys.executable into its sudo -u
# _avp steps, so _avp must be able to traverse + execute the interpreter:
# every parent dir needs o+x. That rules out a repo-tree or home venv (macOS
# home dirs are 0700) and `mktemp -d` (macOS $TMPDIR is a 0700 per-user dir).
# /tmp (1777, cleared on reboot) is world-traversable and genuinely ephemeral.
# Override with VENV=... only if you know the path is world-traversable.
#
# Usage:
#   bash tests/setup-e2e/run-macos.sh          # provision, test, teardown
#   bash tests/setup-e2e/run-macos.sh --keep   # leave provisioned state + venv
#   bash tests/setup-e2e/run-macos.sh --yes    # skip the confirmation prompt
#
# You are prompted ONCE for the BWS token (macOS getpass reads /dev/tty, not
# stdin); paste any throwaway value.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENV="${VENV:-/tmp/avp-smoke-venv}"
PY="${PY:-python3}"

KEEP=0
ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        --keep) KEEP=1 ;;
        --yes)  ASSUME_YES=1 ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }
red()    { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

[ "$(uname -s)" = "Darwin" ] || { red "macOS only — on Linux use run.sh."; exit 1; }
command -v bats >/dev/null || { red "bats not found — brew install bats-core."; exit 1; }
command -v "$PY" >/dev/null || { red "$PY not found."; exit 1; }
"$PY" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 12) else 1)' \
    || { red "$PY is older than 3.12 (project floor). Retry with PY=python3.12 ..."; exit 1; }

teardown_host() {
    # Clear the append-only flag before removing the audit log, then drop
    # everything `avp setup` created. Only ever touches AVP's own paths.
    sudo chflags nosappnd /usr/local/var/log/agent-vault-proxy/audit.jsonl 2>/dev/null || true
    sudo rm -rf /usr/local/etc/agent-vault-proxy \
        /usr/local/var/lib/agent-vault-proxy \
        /usr/local/var/log/agent-vault-proxy \
        /Library/LaunchDaemons/io.inflightsec.agent-vault-proxy.plist
    sudo dscl . -delete /Users/_avp 2>/dev/null || true
    sudo dscl . -delete /Groups/_avp 2>/dev/null || true
}

teardown() {
    if [ "$KEEP" -eq 1 ]; then
        yellow "--keep set; leaving provisioned state + $VENV in place."
        yellow "Remove later by re-running this script without --keep."
        return
    fi
    green "[4/4] Tearing down provisioned state + venv..."
    teardown_host
    sudo rm -rf "$VENV"
}

if [ "$ASSUME_YES" -ne 1 ]; then
    yellow "This provisions agent-vault-proxy on THIS Mac for real: it creates the"
    yellow "_avp service user and /usr/local/...agent-vault-proxy files, then deletes"
    yellow "them again at the end. Do not run it on a Mac with a real avp install."
    read -r -p "Continue? [y/N] " reply
    case "$reply" in [yY]*) ;; *) echo "aborted."; exit 0 ;; esac
fi

trap teardown EXIT

green "[1/4] Pre-cleaning any leftovers from a previous run..."
teardown_host
sudo rm -rf "$VENV"

green "[2/4] Building throwaway venv at $VENV and installing avp..."
sudo "$PY" -m venv "$VENV"
sudo "$VENV/bin/pip" install --quiet "$REPO_ROOT"

green "[3/4] Running setup.bats (you'll be prompted once for a throwaway token)..."
# Force a known TERM so the bats formatter doesn't trip on exotic terminfo
# (e.g. xterm-ghostty missing from root's database). PATH carries the venv
# so the suite's bare `avp` resolves to the _avp-reachable interpreter.
sudo env TERM=xterm-256color PATH="$VENV/bin:$PATH" \
    bats "$SCRIPT_DIR/setup.bats"

green "macOS setup smoke passed."
