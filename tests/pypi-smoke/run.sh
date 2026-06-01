#!/usr/bin/env bash
#
# Post-publish PyPI smoke test for agent-vault-proxy.
#
# Pulls the published wheel from PyPI (or any --index-url you point at),
# stands up the proxy + an HTTP echo upstream on an isolated bridge
# network, and runs the same positive/negative assertions as the
# docker-e2e harness — but against the PyPI-installed binary, not a
# locally built one.
#
# Asserts:
#   POS 1. The upstream's echoed Authorization header contains the REAL
#          secret (substitution happened on the wire).
#   POS 2. No placeholder bytes appear in the echoed headers.
#   POS 3. The proxy's audit log records inject_decision: allowed with
#          the right secret_name.
#   NEG 1. A request to an unbound destination is denied (proxy returns
#          a non-200 status without ever reaching upstream).
#   NEG 2. The proxy's audit log records the deny.
#
# Idempotent: tears down any previous stack, builds, runs, asserts,
# tears down again. Exit 0 = the PyPI wheel works end-to-end.
#
# Usage:
#   bash tests/pypi-smoke/run.sh <version>                                # install from PyPI
#   bash tests/pypi-smoke/run.sh 0.4.2
#   bash tests/pypi-smoke/run.sh 0.4.2 --keep                             # leave stack up after
#   PACKAGE_INDEX_URL=https://test.pypi.org/simple/ bash tests/pypi-smoke/run.sh 0.4.2
#
#   bash tests/pypi-smoke/run.sh --local-wheel <path>                     # install from local wheel
#   bash tests/pypi-smoke/run.sh --local-wheel dist/agent_vault_proxy-0.4.2-py3-none-any.whl
#
# The --local-wheel form is the dry-run before tagging a release: build
# the wheel locally (`python -m build`), smoke it through this harness,
# then push the tag once you've seen it pass.
#
# Required: docker, docker compose v2.20+ (`--wait` support), python3.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLACEHOLDER="test-PLACEHOLDER-01HXY1234567890ABC"
REAL_SECRET="REAL-SECRET-VALUE-only-for-the-pypi-smoke-harness"

green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }
red()    { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

# ── Argument parsing ─────────────────────────────────────────────────
usage() {
    cat >&2 <<EOF
Usage:
  $0 <version> [--keep]                          # install from PyPI
  $0 --local-wheel <path-to-wheel> [--keep]      # install from local wheel

  <version>          e.g. 0.4.2  (no leading 'v')
  --local-wheel PATH path to a built wheel — typically dist/agent_vault_proxy-<ver>-py3-none-any.whl
  --keep             don't tear down after the run (for debugging)
EOF
    exit 2
}

INSTALL_SOURCE=pypi
LOCAL_WHEEL=""
PACKAGE_VERSION=""
KEEP=0

# Two-shape argument parser: either positional <version> [--keep], or
# --local-wheel <path> [--keep].
while [ $# -gt 0 ]; do
    case "$1" in
        --local-wheel)
            shift
            [ $# -ge 1 ] || usage
            INSTALL_SOURCE=local
            LOCAL_WHEEL="$1"
            shift
            ;;
        --keep)
            KEEP=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        --*)
            red "Unknown flag: $1"
            usage
            ;;
        *)
            if [ -z "$PACKAGE_VERSION" ] && [ "$INSTALL_SOURCE" = "pypi" ]; then
                PACKAGE_VERSION="$1"
                shift
            else
                red "Unexpected positional argument: $1"
                usage
            fi
            ;;
    esac
done

if [ "$INSTALL_SOURCE" = "local" ]; then
    if [ ! -f "$LOCAL_WHEEL" ]; then
        red "--local-wheel path does not exist: $LOCAL_WHEEL"
        exit 2
    fi
    # Resolve to an absolute path so the cp into the build context works
    # regardless of where the script is called from.
    LOCAL_WHEEL="$(cd "$(dirname "$LOCAL_WHEEL")" && pwd)/$(basename "$LOCAL_WHEEL")"
    # Parse the version out of the wheel filename:
    #   agent_vault_proxy-0.4.2-py3-none-any.whl → 0.4.2
    WHEEL_BASE="$(basename "$LOCAL_WHEEL")"
    PACKAGE_VERSION="$(printf '%s' "$WHEEL_BASE" | sed -nE 's/^agent_vault_proxy-([0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)-.*\.whl$/\1/p')"
    if [ -z "$PACKAGE_VERSION" ]; then
        red "Could not parse version from wheel filename: $WHEEL_BASE"
        red "Expected: agent_vault_proxy-X.Y.Z[-...]-py3-none-any.whl"
        exit 2
    fi
elif [ -z "$PACKAGE_VERSION" ]; then
    usage
fi

# Strip any accidental leading 'v' so callers can pass `v0.4.2` or `0.4.2`.
PACKAGE_VERSION="${PACKAGE_VERSION#v}"

# Sanity-check the version shape — refuse weird inputs early. PEP 440 is
# more permissive than this, but the smoke only tests release versions
# (X.Y.Z[.N]), never pre/dev releases.
if ! printf '%s' "$PACKAGE_VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?$'; then
    red "Refusing to smoke-test version '$PACKAGE_VERSION' — expected X.Y.Z"
    exit 2
fi

# REAL_SECRET goes into the avp-init container's heredoc which writes
# secrets.yml. Restrict to a safe charset so a future value couldn't
# corrupt the YAML or inject extra keys. The hardcoded value above
# satisfies this; the guard exists to keep future edits honest.
if ! printf '%s' "$REAL_SECRET" | grep -qE '^[A-Za-z0-9_-]+$'; then
    red "REAL_SECRET contains characters outside [A-Za-z0-9_-]; refusing to embed."
    exit 1
fi

export TEST_SECRET="$REAL_SECRET"
export PACKAGE_VERSION
export PACKAGE_INDEX_URL="${PACKAGE_INDEX_URL:-https://pypi.org/simple/}"
export INSTALL_SOURCE

cd "$SCRIPT_DIR"

# Always (re-)create the wheels/ build-context dir. The Dockerfile
# COPYs from it unconditionally; an empty dir is fine in PyPI mode, a
# staged wheel is required in local mode.
rm -rf wheels && mkdir -p wheels
if [ "$INSTALL_SOURCE" = "local" ]; then
    cp "$LOCAL_WHEEL" wheels/
    yellow "Staged $(basename "$LOCAL_WHEEL") into ./wheels/ for local install"
fi

# ── Teardown handler ─────────────────────────────────────────────────
teardown() {
    if [ "$KEEP" -eq 1 ]; then
        yellow "--keep set; stack left running."
        yellow "Tear down later with: cd $SCRIPT_DIR && docker compose down -v"
        return
    fi
    docker compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap teardown EXIT

if [ "$INSTALL_SOURCE" = "local" ]; then
    green "[1/5] PyPI smoke: agent-vault-proxy==$PACKAGE_VERSION from local wheel $(basename "$LOCAL_WHEEL")"
else
    green "[1/5] PyPI smoke: agent-vault-proxy==$PACKAGE_VERSION from $PACKAGE_INDEX_URL"
fi

green "[2/5] Tearing down any previous run..."
docker compose down -v --remove-orphans >/dev/null 2>&1 || true

green "[3/5] Building image from PyPI artifact + bringing up stack..."
if ! docker compose up -d --build --quiet-pull >/dev/null; then
    red "compose up failed — dumping logs from each service:"
    for svc in avp-init avp upstream; do
        red "----- $svc logs -----"
        docker compose logs --no-color "$svc" >&2 || true
    done
    exit 1
fi

# Wait for both services healthy (compose --wait).
if ! docker compose up -d --wait --wait-timeout 120 >/dev/null 2>&1; then
    red "Services did not all reach healthy within 120s."
    docker compose ps >&2 || true
    for svc in avp-init avp upstream; do
        red "----- $svc logs -----"
        docker compose logs --no-color --tail=40 "$svc" >&2 || true
    done
    exit 1
fi

# ── Diagnostics dump (reused by every failure path) ──────────────────
dump_diagnostics() {
    red "----- BEGIN DIAGNOSTICS -----"
    red "[installed version inside avp-pypi-smoke]"
    docker exec avp-pypi-smoke sh -c 'cat /etc/agent-vault-proxy-version 2>/dev/null; pip show agent-vault-proxy 2>/dev/null | head -3' >&2 || true
    red "[avp container logs (last 80 lines)]"
    docker compose logs --no-color --tail=80 avp >&2 || true
    red "[audit log inside avp-pypi-smoke (last 40 lines)]"
    docker exec avp-pypi-smoke sh -c 'tail -40 /var/log/agent-vault-proxy/audit.jsonl 2>/dev/null || echo "(audit log empty or unreadable)"' >&2 || true
    red "[bindings.yaml as mounted]"
    docker exec avp-pypi-smoke sh -c 'cat /etc/agent-vault-proxy/bindings.yaml 2>&1 | head -40' >&2 || true
    # NEVER cat secrets.yml. Stat-only diagnostic — confirms presence,
    # ownership, mode without ever logging the value. Same discipline
    # as docker-e2e/run.sh.
    red "[secrets.yml stat (value never logged)]"
    docker exec avp-pypi-smoke sh -c 'stat -c "%a %u:%g %s bytes %n" /etc/agent-vault-proxy/secrets.yml 2>&1' >&2 || true
    red "----- END DIAGNOSTICS -----"
}

green "[4/5] POSITIVE test: substitution happens on the wire"

ECHO_RESPONSE_FILE="$(mktemp)"
trap 'rm -f "$ECHO_RESPONSE_FILE"; teardown' EXIT

# Exec curl-equivalent from inside the avp container so we share its
# docker network and resolve `upstream.test` via the bridge's DNS.
# Plain HTTP — same justification as docker-e2e: the substitution path
# is identical for HTTP and HTTPS once mitmproxy hands the flow to the
# addon, and HTTPS would require a CA-signed echo upstream.
docker exec avp-pypi-smoke python -c "
import http.client, json
conn = http.client.HTTPConnection('127.0.0.1', 14322, timeout=10)
conn.request(
    'GET',
    'http://upstream.test:8080/',
    headers={'Authorization': 'Bearer $PLACEHOLDER', 'Host': 'upstream.test:8080'},
)
resp = conn.getresponse()
body = resp.read().decode('utf-8', errors='replace')
print(json.dumps({'status': resp.status, 'body': body}))
" > "$ECHO_RESPONSE_FILE"

POS_STATUS=$(python3 -c "import json; print(json.load(open('$ECHO_RESPONSE_FILE'))['status'])")
POS_BODY=$(python3 -c "import json; print(json.load(open('$ECHO_RESPONSE_FILE'))['body'])")

if [ "$POS_STATUS" != "200" ]; then
    red "POS: upstream returned $POS_STATUS, expected 200"
    red "body: $POS_BODY"
    dump_diagnostics
    exit 1
fi

ECHOED_AUTH=$(python3 -c "
import json
body = json.loads('''$POS_BODY''')
print(body.get('headers', {}).get('authorization', ''))
")

if ! printf '%s' "$ECHOED_AUTH" | grep -qF "Bearer $REAL_SECRET"; then
    red "POS: upstream did NOT receive the real secret"
    red "  echoed Authorization: $ECHOED_AUTH"
    dump_diagnostics
    exit 1
fi
if printf '%s' "$ECHOED_AUTH" | grep -qF "$PLACEHOLDER"; then
    red "POS: PLACEHOLDER leaked to the upstream — substitution failed"
    red "  echoed Authorization: $ECHOED_AUTH"
    dump_diagnostics
    exit 1
fi
green "  ✓ upstream received the real secret; placeholder did not leak"

# Audit-log assertion: inject_decision allowed for TEST_API_KEY.
AUDIT_ALLOWED=$(docker exec avp-pypi-smoke sh -c '
  grep -E "\"decision\":\"allowed\".*\"secret_name\":\"TEST_API_KEY\"" \
    /var/log/agent-vault-proxy/audit.jsonl | tail -1
') || AUDIT_ALLOWED=""
if [ -z "$AUDIT_ALLOWED" ]; then
    red "POS: no inject_decision: allowed entry for TEST_API_KEY in audit log"
    dump_diagnostics
    exit 1
fi
green "  ✓ audit log recorded the inject_decision: allowed"

green "[5/5] NEGATIVE test: unbound destination denied"

# Aim at example.com (not in bindings). The proxy should refuse to
# inject — the placeholder is forwarded verbatim, but the proxy
# either denies the CONNECT outright (mode-dependent) or never
# substitutes. We assert the audit log records a deny.
NEG_STATUS=$(docker exec avp-pypi-smoke python -c "
import http.client
try:
    conn = http.client.HTTPConnection('127.0.0.1', 14322, timeout=10)
    conn.request(
        'GET',
        'http://example.invalid/',
        headers={'Authorization': 'Bearer $PLACEHOLDER', 'Host': 'example.invalid'},
    )
    print(conn.getresponse().status)
except Exception as e:
    # Proxy refusing the request outright is also acceptable — print a
    # synthetic non-200 so the assertion below treats it as expected.
    print('599')
" || echo "599")

if [ "$NEG_STATUS" = "200" ]; then
    red "NEG: unbound destination returned 200 — proxy didn't fail-closed"
    dump_diagnostics
    exit 1
fi

# The addon has two separate deny paths for an unbound destination,
# depending on which gate fires first:
#   1. unmatched_destination_policy: deny — fires BEFORE placeholder
#      analysis when the request's host is in no binding at all.
#      Emits {"type":"deny","reason":"unmatched_destination",...}.
#   2. inject_decision destination_not_in_binding — fires inside the
#      inject path when a placeholder IS present but the matched
#      secret's bindings don't cover this host.
#      Emits {"type":"inject_decision","decision":"denied",...}.
# The pypi-smoke negative test aims at example.invalid (in no binding
# at all), so path 1 fires. Earlier versions of this grep only knew
# path 2 and went red despite the proxy correctly returning 403 — see
# v0.4.2 changelog. tests/docker-e2e/run.sh already greps both shapes.
AUDIT_DENIED=$(docker exec avp-pypi-smoke sh -c '
  grep -E "\"decision\":\"denied\"|\"decision\":\"forwarded_unmodified\"|\"type\":\"deny\"" \
    /var/log/agent-vault-proxy/audit.jsonl | tail -1
') || AUDIT_DENIED=""
if [ -z "$AUDIT_DENIED" ]; then
    red "NEG: no deny/inject_decision-denied/forwarded_unmodified entry in audit log for the unbound destination"
    dump_diagnostics
    exit 1
fi
green "  ✓ unbound destination handled fail-closed; audit recorded the decision"

echo
green "════════════════════════════════════════════════════════════════════"
green "✓ PyPI smoke passed for agent-vault-proxy==$PACKAGE_VERSION"
if [ "$INSTALL_SOURCE" = "local" ]; then
    green "  (installed from local wheel $(basename "$LOCAL_WHEEL"))"
else
    green "  (installed from $PACKAGE_INDEX_URL)"
fi
green "════════════════════════════════════════════════════════════════════"
