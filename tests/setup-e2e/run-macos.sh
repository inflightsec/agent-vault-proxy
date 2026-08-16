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
#   bash tests/setup-e2e/run-macos.sh             # provision, test, teardown (bws)
#   bash tests/setup-e2e/run-macos.sh --static    # real install, file-based static
#                                                 #   secrets, no Bitwarden, no token
#   bash tests/setup-e2e/run-macos.sh --dry-run   # plan only: no sudo, no Bitwarden
#   bash tests/setup-e2e/run-macos.sh --keep      # leave provisioned state + venv
#   bash tests/setup-e2e/run-macos.sh --yes       # skip the confirmation prompt
#
# Full provisioning needs admin (creates a service user, writes /usr/local,
# installs a LaunchDaemon), so macOS shows an "administer your computer"
# prompt. The default (bws) path also asks ONCE for a throwaway token; --static
# does the same real install backed by a static secrets file — no Bitwarden,
# no token. --dry-run skips admin entirely.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VENV="${VENV:-/tmp/avp-smoke-venv}"
PY="${PY:-python3}"

KEEP=0
ASSUME_YES=0
DRY_RUN=0
STATIC=0
for arg in "$@"; do
    case "$arg" in
        --keep)    KEEP=1 ;;
        --yes)     ASSUME_YES=1 ;;
        --dry-run) DRY_RUN=1 ;;
        --static)  STATIC=1 ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done
BACKEND=bws
[ "$STATIC" -eq 1 ] && BACKEND=static

green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }
red()    { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

[ "$(uname -s)" = "Darwin" ] || { red "macOS only — on Linux use run.sh."; exit 1; }
command -v "$PY" >/dev/null || { red "$PY not found."; exit 1; }
"$PY" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 12) else 1)' \
    || { red "$PY is older than 3.12 (project floor). Retry with PY=python3.12 ..."; exit 1; }

if [ "$DRY_RUN" -eq 1 ]; then
    # Plan-only smoke: no sudo (so no "administer your computer" prompt), no
    # token, no Bitwarden, no host changes. `avp setup --dry-run` renders the
    # full plan and mutates nothing, running entirely as you.
    DRYVENV="/tmp/avp-dryrun-venv"
    green "[1/2] Building local venv at $DRYVENV and installing avp (no sudo)..."
    rm -rf "$DRYVENV"
    "$PY" -m venv "$DRYVENV"
    "$DRYVENV/bin/pip" install --quiet "$REPO_ROOT"

    setup_flags="--no-service"
    [ "$STATIC" -eq 1 ] && setup_flags="$setup_flags --static"
    green "[2/2] Planning 'avp setup $setup_flags' (no sudo, no token, no Bitwarden)..."
    # The doctor pass at the tail reports the not-yet-generated CA, so a
    # non-zero exit is expected; assert on the rendered plan, not the status.
    plan="$("$DRYVENV/bin/avp" setup $setup_flags --dry-run 2>&1 || true)"
    printf '%s\n' "$plan"

    fail=0
    for needle in "Create the dedicated launchd user" "0750" "Install the launchd plist"; do
        printf '%s' "$plan" | grep -qF "$needle" || { red "plan missing: $needle"; fail=1; }
    done
    if printf '%s' "$plan" | grep -q "launchctl"; then
        red "plan included launchctl activation under --no-service"; fail=1
    fi
    if [ -e /usr/local/etc/kow ]; then
        red "dry-run mutated the host"; fail=1
    fi

    rm -rf "$DRYVENV"
    [ "$fail" -eq 0 ] || { red "dry-run smoke FAILED."; exit 1; }
    green "macOS dry-run smoke passed — plan renders, no Bitwarden, nothing provisioned."
    exit 0
fi

command -v bats >/dev/null || { red "bats not found — brew install bats-core."; exit 1; }

teardown_host() {
    # Clear the append-only flag before removing the audit log, then drop
    # everything `avp setup` created. Only ever touches AVP's own paths.
    sudo chflags nosappnd /usr/local/var/log/kow/audit.jsonl 2>/dev/null || true
    sudo rm -rf /usr/local/etc/kow \
        /usr/local/var/lib/kow \
        /usr/local/var/log/kow \
        /Library/LaunchDaemons/io.inflightsec.kow.plist
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
    yellow "This provisions kow on THIS Mac for real: it creates the"
    yellow "_avp service user and /usr/local/...kow files, then deletes"
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

if [ "$BACKEND" = bws ]; then
    green "[3/4] Running setup.bats (bws — you'll be prompted once for a throwaway token)..."
else
    green "[3/4] Running setup.bats (static secrets — no Bitwarden, no token)..."
fi
# Force a known TERM so the bats formatter doesn't trip on exotic terminfo
# (e.g. xterm-ghostty missing from root's database). PATH carries the venv so
# the suite's bare `avp` resolves to the _avp-reachable interpreter; AVP_BACKEND
# drives run_setup's --static and the secret-source assertions.
sudo env TERM=xterm-256color AVP_BACKEND="$BACKEND" PATH="$VENV/bin:$PATH" \
    bats "$SCRIPT_DIR/setup.bats"

green "macOS setup smoke passed."
