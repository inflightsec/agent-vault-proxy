#!/usr/bin/env bash
#
# Docker end-to-end harness for agent-vault-proxy.
#
# Builds the image, stands up the avp container plus an HTTP echo
# upstream on an isolated bridge network, then exercises both a
# positive substitution path and a negative "deny unbound destination"
# path through the proxy. Asserts:
#
#   POS  1. The upstream's echoed Authorization header contains the
#           REAL secret (not the placeholder).
#   POS  2. No placeholder bytes appear in the echoed headers.
#   POS  3. The proxy's audit log records inject_decision: allowed
#           with the right secret_name.
#   NEG  1. A request to an unbound destination is denied with 403.
#   NEG  2. The proxy's audit log records the deny.
#
# Idempotent: tears down any previous run, builds fresh, runs, asserts,
# tears down again. Exit 0 = all assertions passed.
#
# Usage:
#   bash tests/docker-e2e/run.sh
#   bash tests/docker-e2e/run.sh --keep   # don't tear down (for debugging)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PLACEHOLDER="test-PLACEHOLDER-01HXY1234567890ABC"
REAL_SECRET="REAL-SECRET-VALUE-only-for-the-e2e-harness"

# Passed through compose's parse-time interpolation into the avp-init
# container's heredoc, which generates /etc/agent-vault-proxy/secrets.yml
# in-container. Generation (rather than a host bind mount) sidesteps the
# Docker userns-remap case where container "root" maps to a non-root
# host UID that can't read the operator's 0600 secrets.yml.
#
# Input-validate REAL_SECRET against a narrow charset before exporting:
# the avp-init heredoc embeds the value into a YAML string literal, and
# a value containing `"`, `\n`, or `\\` could break the YAML or inject
# extra keys. The harness's hardcoded value satisfies the constraint;
# this guard exists to keep future edits honest.
if ! printf '%s' "$REAL_SECRET" | grep -qE '^[A-Za-z0-9_-]+$'; then
    red "REAL_SECRET contains characters outside [A-Za-z0-9_-]."
    red "The harness embeds it into a YAML string literal via shell heredoc;"
    red "characters outside this set could corrupt the generated file or"
    red "inject extra YAML keys. Restrict to the documented charset."
    exit 1
fi
export TEST_SECRET="$REAL_SECRET"

KEEP=0
if [ "${1:-}" = "--keep" ]; then
    KEEP=1
fi

green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }
red()    { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

cd "$SCRIPT_DIR"

teardown() {
    if [ "$KEEP" -eq 1 ]; then
        yellow "--keep set; leaving the stack running."
        yellow "Tear down later with: cd $SCRIPT_DIR && docker compose down -v"
        return
    fi
    docker compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap teardown EXIT

green "[1/5] Tearing down any previous run..."
docker compose down -v --remove-orphans >/dev/null 2>&1 || true

green "[2/5] Building avp image and starting stack..."
if ! docker compose up -d --build --quiet-pull >/dev/null; then
    red "compose up failed — dumping logs from each service before teardown:"
    for svc in avp-init avp upstream; do
        red "----- $svc logs -----"
        docker compose logs --no-color "$svc" >&2 || true
    done
    exit 1
fi

green "[3/5] Waiting for both services to report healthy..."
# Compose 2.20+ supports `--wait`; fall back to a polling loop otherwise.
if ! docker compose up -d --wait --wait-timeout 90 >/dev/null 2>&1; then
    for _ in $(seq 1 45); do
        avp_status=$(docker inspect -f '{{.State.Health.Status}}' avp-e2e 2>/dev/null || echo "starting")
        ups_status=$(docker inspect -f '{{.State.Health.Status}}' avp-e2e-upstream 2>/dev/null || echo "starting")
        if [ "$avp_status" = "healthy" ] && [ "$ups_status" = "healthy" ]; then
            break
        fi
        sleep 2
    done
fi

# Final readiness check — fail fast if either side never came up.
for svc in avp-e2e avp-e2e-upstream; do
    status=$(docker inspect -f '{{.State.Health.Status}}' "$svc" 2>/dev/null || echo "missing")
    if [ "$status" != "healthy" ]; then
        red "$svc is not healthy (status: $status)"
        docker compose logs "$(echo "$svc" | sed 's/avp-e2e-//; s/^/_/; s/_$/avp/')" || true
        exit 1
    fi
done

green "[4/5] POSITIVE test: substitution happens on the wire"

# `--resolve upstream.test:80:127.0.0.1` would dodge the proxy. Instead
# we route through the proxy and let mitmproxy + the docker network do
# DNS resolution. From inside the proxy container `upstream.test`
# resolves to the upstream service via the network alias.
#
# We hit plain HTTP, not HTTPS, on purpose: the substitution logic the
# E2E test is checking is the addon's wire-mutation step, which is
# identical for HTTP and HTTPS once mitmproxy hands the flow to the
# addon. Avoiding HTTPS skips the upstream-cert-trust dance which would
# require either a CA-signed echo upstream or `--ssl-insecure` flag
# threading. The existing tests/smoke/layer3_proxy_anthropic.py covers
# the live-HTTPS path against api.anthropic.com.
ECHO_RESPONSE_FILE="$(mktemp)"
trap 'rm -f "$ECHO_RESPONSE_FILE"; teardown' EXIT

# Exec curl from inside the avp container so we share its docker network
# and resolve `upstream.test` via the bridge's embedded DNS. The proxy
# listens on the same loopback inside the container, so a per-process
# HTTPS_PROXY=http://127.0.0.1:14322 routes the curl through it without
# the host-network published port mattering.
docker exec avp-e2e python -c "
import http.client, json, os, sys
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

POS_STATUS=$(python3 -c "import json,sys; print(json.load(open('$ECHO_RESPONSE_FILE'))['status'])")
POS_BODY=$(python3 -c "import json; print(json.load(open('$ECHO_RESPONSE_FILE'))['body'])")

dump_diagnostics() {
    red "----- BEGIN DIAGNOSTICS -----"
    red "[client response]"
    cat "$ECHO_RESPONSE_FILE" >&2 || true
    echo >&2
    red "[avp container logs (mitmdump stderr — last 80 lines)]"
    docker compose logs --no-color --tail=80 avp >&2 || true
    red "[audit log inside avp-e2e (last 40 lines)]"
    docker exec avp-e2e sh -c 'tail -40 /var/log/agent-vault-proxy/audit.jsonl 2>/dev/null || echo "(audit log empty or unreadable)"' >&2 || true
    red "[bindings.yaml as mounted in avp-e2e]"
    docker exec avp-e2e sh -c 'cat /etc/agent-vault-proxy/bindings.yaml 2>&1 | head -40' >&2 || true
    # NEVER cat secrets.yml. Even when its value is a fake test fixture,
    # `cat secrets.yml` models a pattern that would leak real credentials
    # if copied into a production-like diagnostic path. Print stat-only
    # so the operator can confirm the file is present, owned, and at the
    # expected mode — that's the load-bearing diagnostic signal here.
    red "[secrets.yml as mounted in avp-e2e (stat only — value never logged)]"
    docker exec avp-e2e sh -c 'stat -c "%a %u:%g %s bytes %n" /etc/agent-vault-proxy/secrets.yml 2>&1' >&2 || true
    red "[avp config + listener state]"
    docker exec avp-e2e sh -c 'ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo "(no ss/netstat)"' >&2 || true
    red "----- END DIAGNOSTICS -----"
}

if [ "$POS_STATUS" != "200" ]; then
    red "POS: upstream returned $POS_STATUS, expected 200"
    red "body: $POS_BODY"
    dump_diagnostics
    exit 1
fi

# The echo upstream returns JSON; look for the substituted Authorization
# in its parsed headers.
ECHOED_AUTH=$(python3 -c "
import json, sys
body = json.loads('''$POS_BODY''')
headers = body.get('headers', {})
# header keys are lowercased by the echo image
auth = headers.get('authorization', '')
print(auth)
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

# Audit log assertion: inject_decision allowed for TEST_API_KEY
AUDIT_LINE=$(docker exec avp-e2e sh -c '
  grep -E "\"decision\":\"allowed\".*\"secret_name\":\"TEST_API_KEY\"" \
    /var/log/agent-vault-proxy/audit.jsonl | tail -1
') || AUDIT_LINE=""
if [ -z "$AUDIT_LINE" ]; then
    red "POS: no inject_decision: allowed entry for TEST_API_KEY in audit log"
    docker exec avp-e2e tail -5 /var/log/agent-vault-proxy/audit.jsonl >&2 || true
    exit 1
fi
green "  ✓ audit log contains inject_decision: allowed"

green "[5/5] NEGATIVE test: unbound destination denied"

docker exec avp-e2e python -c "
import http.client
conn = http.client.HTTPConnection('127.0.0.1', 14322, timeout=10)
conn.request(
    'GET',
    'http://evil.test:8080/',
    headers={'Authorization': 'Bearer $PLACEHOLDER', 'Host': 'evil.test:8080'},
)
resp = conn.getresponse()
print(resp.status)
" > "$ECHO_RESPONSE_FILE"

NEG_STATUS=$(cat "$ECHO_RESPONSE_FILE" | tr -d '[:space:]')
if [ "$NEG_STATUS" != "403" ]; then
    red "NEG: expected 403 for unbound destination, got '$NEG_STATUS'"
    exit 1
fi
green "  ✓ unbound destination got 403"

AUDIT_DENY=$(docker exec avp-e2e sh -c '
  grep -E "\"type\":\"deny\".*\"reason\":\"unmatched_destination\".*\"host\":\"evil.test\"" \
    /var/log/agent-vault-proxy/audit.jsonl | tail -1
') || AUDIT_DENY=""
if [ -z "$AUDIT_DENY" ]; then
    red "NEG: no deny:unmatched_destination entry for evil.test in audit log"
    docker exec avp-e2e tail -5 /var/log/agent-vault-proxy/audit.jsonl >&2 || true
    exit 1
fi
green "  ✓ audit log contains the deny event"

echo
green "All E2E assertions passed."
