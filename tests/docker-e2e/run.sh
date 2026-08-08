#!/usr/bin/env bash
#
# Docker end-to-end harness for agent-vault-proxy.
#
# Builds the image, stands up the avp container plus an HTTP echo
# upstream on an isolated bridge network, then exercises three positive
# substitution paths (v0.5 header / body / multi injectors) and a
# negative "deny unbound destination" path through the proxy. Asserts:
#
#   POS-HDR  1. The upstream's echoed Authorization header contains the
#              REAL secret (not the placeholder).
#   POS-HDR  2. No placeholder bytes appear in the echoed headers.
#   POS-HDR  3. Audit log records inject_decision: allowed / TEST_API_KEY.
#   POS-BODY 1. A JSON POST to /body has the placeholder substituted
#              inside the request BODY on the wire (echo confirms).
#   POS-BODY 2. Audit log records allowed / TEST_BODY_KEY.
#   POS-MULTI 1. A JSON POST to /multi with the placeholder in BOTH the
#              X-Multi-Key header AND the JSON payload lands with the
#              real value substituted in both places on one request.
#   POS-MULTI 2. Audit log records allowed / TEST_MULTI_KEY.
#   POS-COMPOSITE-HEADER  inject.template+compose renders Basic(b64(user:pass))
#              into the Authorization header on the wire; allowed audit.
#   POS-COMPOSITE-BODY    same compose machinery rendered into the JSON body;
#              allowed audit.
#   NEG      1. A request to an unbound destination is denied with 403.
#   NEG      2. The proxy's audit log records the deny.
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
BODY_PLACEHOLDER="body-PLACEHOLDER-01HXY1234567890BDY"
MULTI_PLACEHOLDER="multi-PLACEHOLDER-01HXY1234567890MLT"

REAL_SECRET="REAL-SECRET-VALUE-only-for-the-e2e-harness"
REAL_BODY_SECRET="REAL-BODY-VALUE-only-for-the-e2e-harness"
REAL_MULTI_SECRET="REAL-MULTI-VALUE-only-for-the-e2e-harness"

KEEP=0
if [ "${1:-}" = "--keep" ]; then
    KEEP=1
fi

green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }
red()    { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

# Passed through compose's parse-time interpolation into the avp-init
# container's heredoc, which generates /etc/agent-vault-proxy/secrets.yml
# in-container. Generation (rather than a host bind mount) sidesteps the
# Docker userns-remap case where container "root" maps to a non-root
# host UID that can't read the operator's 0600 secrets.yml.
#
# Input-validate each real secret against a narrow charset before
# exporting: the avp-init heredoc embeds each value into a YAML string
# literal, and a value containing `"`, `\n`, or `\\` could break the
# YAML or inject extra keys. The harness's hardcoded values satisfy the
# constraint; this guard exists to keep future edits honest.
_charset_check() {
    if ! printf '%s' "$2" | grep -qE '^[A-Za-z0-9_-]+$'; then
        red "$1 contains characters outside [A-Za-z0-9_-]."
        red "The harness embeds it into a YAML string literal via shell heredoc;"
        red "characters outside this set could corrupt the generated file or"
        red "inject extra YAML keys. Restrict to the documented charset."
        exit 1
    fi
}
_charset_check REAL_SECRET       "$REAL_SECRET"
_charset_check REAL_BODY_SECRET  "$REAL_BODY_SECRET"
_charset_check REAL_MULTI_SECRET "$REAL_MULTI_SECRET"

export TEST_SECRET="$REAL_SECRET"
export TEST_BODY_SECRET="$REAL_BODY_SECRET"
export TEST_MULTI_SECRET="$REAL_MULTI_SECRET"

# Self-signed TLS cert for the mock OAuth token endpoint (CN/SAN token.mock).
# Generated fresh per run into a tmpdir; mounted into token-mock (server cert)
# and into avp as SSL_CERT_FILE (CA) so the token-exchange trusts it without
# editing the image or src. World-readable (throwaway) to dodge userns-remap
# read issues. OAUTH_CERT_DIR is consumed by docker-compose.yml.
OAUTH_CERT_DIR="$(mktemp -d)"
export OAUTH_CERT_DIR
if ! openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
        -keyout "$OAUTH_CERT_DIR/server.key" -out "$OAUTH_CERT_DIR/server.crt" \
        -subj "/CN=token.mock" -addext "subjectAltName=DNS:token.mock" >/dev/null 2>&1; then
    red "failed to generate the mock oauth TLS cert (is openssl installed?)"
    exit 1
fi
chmod 644 "$OAUTH_CERT_DIR/server.key" "$OAUTH_CERT_DIR/server.crt"

cd "$SCRIPT_DIR"

teardown() {
    [ -n "${OAUTH_CERT_DIR:-}" ] && rm -rf "$OAUTH_CERT_DIR"
    if [ "$KEEP" -eq 1 ]; then
        yellow "--keep set; leaving the stack running."
        yellow "Tear down later with: cd $SCRIPT_DIR && docker compose down -v"
        return
    fi
    docker compose down -v --remove-orphans >/dev/null 2>&1 || true
}
trap teardown EXIT

green "[1/17] Tearing down any previous run..."
docker compose down -v --remove-orphans >/dev/null 2>&1 || true

green "[2/17] Building avp image and starting stack..."
if ! docker compose up -d --build --quiet-pull >/dev/null; then
    red "compose up failed — dumping logs from each service before teardown:"
    for svc in avp-init avp upstream; do
        red "----- $svc logs -----"
        docker compose logs --no-color "$svc" >&2 || true
    done
    exit 1
fi

green "[3/17] Waiting for both services to report healthy..."
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

green "[4/17] POS-HDR: header-injector substitutes Authorization on the wire"

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

green "[5/17] POS-BODY: body-injector substitutes JSON payload on the wire"

# POST /body with the placeholder inside the JSON body. The upstream
# echo returns the received request body verbatim in its JSON response,
# so a grep for the real value (present) + placeholder (absent) proves
# the substitution fired on the wire.
docker exec avp-e2e python -c "
import http.client, json
placeholder = '$BODY_PLACEHOLDER'
payload = json.dumps({'api_token': placeholder, 'note': 'body-injector-e2e'})
conn = http.client.HTTPConnection('127.0.0.1', 14322, timeout=10)
conn.request(
    'POST',
    'http://upstream.test:8080/body',
    body=payload,
    headers={'Host': 'upstream.test:8080', 'Content-Type': 'application/json'},
)
resp = conn.getresponse()
body = resp.read().decode('utf-8', errors='replace')
print(json.dumps({'status': resp.status, 'body': body}))
" > "$ECHO_RESPONSE_FILE"

BODY_STATUS=$(python3 -c "import json; print(json.load(open('$ECHO_RESPONSE_FILE'))['status'])")
BODY_ECHO=$(python3 -c "import json; print(json.load(open('$ECHO_RESPONSE_FILE'))['body'])")

if [ "$BODY_STATUS" != "200" ]; then
    red "POS-BODY: upstream returned $BODY_STATUS, expected 200"
    red "body: $BODY_ECHO"
    dump_diagnostics
    exit 1
fi
if ! printf '%s' "$BODY_ECHO" | grep -qF "$REAL_BODY_SECRET"; then
    red "POS-BODY: upstream did NOT receive the real body secret"
    red "  echoed body: $BODY_ECHO"
    dump_diagnostics
    exit 1
fi
if printf '%s' "$BODY_ECHO" | grep -qF "$BODY_PLACEHOLDER"; then
    red "POS-BODY: PLACEHOLDER leaked to the upstream — body substitution failed"
    red "  echoed body: $BODY_ECHO"
    dump_diagnostics
    exit 1
fi
green "  ✓ body-injector substituted JSON payload; placeholder did not leak"

BODY_AUDIT=$(docker exec avp-e2e sh -c '
  grep -E "\"decision\":\"allowed\".*\"secret_name\":\"TEST_BODY_KEY\"" \
    /var/log/agent-vault-proxy/audit.jsonl | tail -1
') || BODY_AUDIT=""
if [ -z "$BODY_AUDIT" ]; then
    red "POS-BODY: no inject_decision: allowed entry for TEST_BODY_KEY in audit log"
    docker exec avp-e2e tail -5 /var/log/agent-vault-proxy/audit.jsonl >&2 || true
    exit 1
fi
green "  ✓ audit log contains inject_decision: allowed for TEST_BODY_KEY"

green "[6/17] POS-MULTI: multi-injector substitutes header AND body on one request"

# POST /multi with the placeholder in BOTH the X-Multi-Key header AND
# the JSON payload. The multi injector runs the header and body leaf
# substitutions on the same flow — both places must land as the real
# value, and the placeholder must appear NOWHERE in the echo.
docker exec avp-e2e python -c "
import http.client, json
placeholder = '$MULTI_PLACEHOLDER'
payload = json.dumps({'signed_payload': placeholder, 'note': 'multi-injector-e2e'})
conn = http.client.HTTPConnection('127.0.0.1', 14322, timeout=10)
conn.request(
    'POST',
    'http://upstream.test:8080/multi',
    body=payload,
    headers={
        'Host': 'upstream.test:8080',
        'Content-Type': 'application/json',
        'X-Multi-Key': placeholder,
    },
)
resp = conn.getresponse()
body = resp.read().decode('utf-8', errors='replace')
print(json.dumps({'status': resp.status, 'body': body}))
" > "$ECHO_RESPONSE_FILE"

MULTI_STATUS=$(python3 -c "import json; print(json.load(open('$ECHO_RESPONSE_FILE'))['status'])")
MULTI_ECHO=$(python3 -c "import json; print(json.load(open('$ECHO_RESPONSE_FILE'))['body'])")

if [ "$MULTI_STATUS" != "200" ]; then
    red "POS-MULTI: upstream returned $MULTI_STATUS, expected 200"
    red "body: $MULTI_ECHO"
    dump_diagnostics
    exit 1
fi

# Real value must appear at least twice — once in the echoed
# X-Multi-Key header, once in the echoed body payload.
OCCURRENCES=$(printf '%s' "$MULTI_ECHO" | grep -oF "$REAL_MULTI_SECRET" | wc -l | tr -d ' ')
if [ "$OCCURRENCES" -lt 2 ]; then
    red "POS-MULTI: real value appeared $OCCURRENCES time(s) in echo, expected >=2 (header + body)"
    red "  echoed: $MULTI_ECHO"
    dump_diagnostics
    exit 1
fi
if printf '%s' "$MULTI_ECHO" | grep -qF "$MULTI_PLACEHOLDER"; then
    red "POS-MULTI: PLACEHOLDER leaked to the upstream — multi substitution failed"
    red "  echoed: $MULTI_ECHO"
    dump_diagnostics
    exit 1
fi
green "  ✓ multi-injector substituted BOTH header and body; placeholder did not leak"

MULTI_AUDIT=$(docker exec avp-e2e sh -c '
  grep -E "\"decision\":\"allowed\".*\"secret_name\":\"TEST_MULTI_KEY\"" \
    /var/log/agent-vault-proxy/audit.jsonl | tail -1
') || MULTI_AUDIT=""
if [ -z "$MULTI_AUDIT" ]; then
    red "POS-MULTI: no inject_decision: allowed entry for TEST_MULTI_KEY in audit log"
    docker exec avp-e2e tail -5 /var/log/agent-vault-proxy/audit.jsonl >&2 || true
    exit 1
fi
green "  ✓ audit log contains inject_decision: allowed for TEST_MULTI_KEY"

green "[7/17] POS-COMPOSITE-HEADER: inject.template+compose renders Basic on the wire"

# Composite = two atomic secrets (E2E_USER + E2E_PASS) assembled by the
# sandboxed Jinja template at fetch time. Expected rendered value is
# base64("e2e-user:e2e-pass-value") — computed here so the assertion is exact.
EXPECTED_COMPOSITE=$(python3 -c "import base64; print(base64.b64encode(b'e2e-user:e2e-pass-value').decode())")

docker exec avp-e2e python -c "
import http.client, json
conn = http.client.HTTPConnection('127.0.0.1', 14322, timeout=10)
conn.request(
    'GET',
    'http://upstream.test:8080/composite-header',
    headers={'Authorization': 'Bearer cphdr-PLACEHOLDER-01HXY1234567890CH', 'Host': 'upstream.test:8080'},
)
resp = conn.getresponse()
body = resp.read().decode('utf-8', errors='replace')
print(json.dumps({'status': resp.status, 'body': body}))
" > "$ECHO_RESPONSE_FILE"

CH_STATUS=$(python3 -c "import json; print(json.load(open('$ECHO_RESPONSE_FILE'))['status'])")
CH_BODY=$(python3 -c "import json; print(json.load(open('$ECHO_RESPONSE_FILE'))['body'])")
if [ "$CH_STATUS" != "200" ]; then
    red "POS-COMPOSITE-HEADER: upstream returned $CH_STATUS, expected 200"
    dump_diagnostics
    exit 1
fi
CH_AUTH=$(python3 -c "
import json
print(json.loads('''$CH_BODY''').get('headers', {}).get('authorization', ''))
")
if ! printf '%s' "$CH_AUTH" | grep -qF "Basic $EXPECTED_COMPOSITE"; then
    red "POS-COMPOSITE-HEADER: expected 'Basic $EXPECTED_COMPOSITE', echoed Authorization: $CH_AUTH"
    dump_diagnostics
    exit 1
fi
if printf '%s' "$CH_AUTH" | grep -qF "cphdr-PLACEHOLDER"; then
    red "POS-COMPOSITE-HEADER: placeholder leaked to upstream"
    dump_diagnostics
    exit 1
fi
green "  ✓ composite header rendered the Basic credential; placeholder did not leak"

CH_AUDIT=$(docker exec avp-e2e sh -c '
  grep -E "\"decision\":\"allowed\".*\"secret_name\":\"COMPOSITE_HEADER\"" \
    /var/log/agent-vault-proxy/audit.jsonl | tail -1
') || CH_AUDIT=""
if [ -z "$CH_AUDIT" ]; then
    red "POS-COMPOSITE-HEADER: no inject_decision: allowed entry for COMPOSITE_HEADER"
    docker exec avp-e2e tail -5 /var/log/agent-vault-proxy/audit.jsonl >&2 || true
    exit 1
fi
green "  ✓ audit log contains inject_decision: allowed for COMPOSITE_HEADER"

green "[8/17] POS-COMPOSITE-BODY: inject.template+compose renders into the JSON body"

docker exec avp-e2e python -c "
import http.client, json
payload = json.dumps({'cred': 'cpbody-PLACEHOLDER-01HXY1234567890CB', 'note': 'composite-body-e2e'})
conn = http.client.HTTPConnection('127.0.0.1', 14322, timeout=10)
conn.request(
    'POST',
    'http://upstream.test:8080/composite-body',
    body=payload,
    headers={'Host': 'upstream.test:8080', 'Content-Type': 'application/json'},
)
resp = conn.getresponse()
body = resp.read().decode('utf-8', errors='replace')
print(json.dumps({'status': resp.status, 'body': body}))
" > "$ECHO_RESPONSE_FILE"

CB_STATUS=$(python3 -c "import json; print(json.load(open('$ECHO_RESPONSE_FILE'))['status'])")
CB_BODY=$(python3 -c "import json; print(json.load(open('$ECHO_RESPONSE_FILE'))['body'])")
if [ "$CB_STATUS" != "200" ]; then
    red "POS-COMPOSITE-BODY: upstream returned $CB_STATUS, expected 200"
    red "body: $CB_BODY"
    dump_diagnostics
    exit 1
fi
if ! printf '%s' "$CB_BODY" | grep -qF "$EXPECTED_COMPOSITE"; then
    red "POS-COMPOSITE-BODY: rendered credential not found in upstream echo"
    red "body: $CB_BODY"
    dump_diagnostics
    exit 1
fi
if printf '%s' "$CB_BODY" | grep -qF "cpbody-PLACEHOLDER"; then
    red "POS-COMPOSITE-BODY: placeholder leaked to upstream"
    dump_diagnostics
    exit 1
fi
green "  ✓ composite body rendered the credential into JSON; placeholder did not leak"

CB_AUDIT=$(docker exec avp-e2e sh -c '
  grep -E "\"decision\":\"allowed\".*\"secret_name\":\"COMPOSITE_BODY\"" \
    /var/log/agent-vault-proxy/audit.jsonl | tail -1
') || CB_AUDIT=""
if [ -z "$CB_AUDIT" ]; then
    red "POS-COMPOSITE-BODY: no inject_decision: allowed entry for COMPOSITE_BODY"
    docker exec avp-e2e tail -5 /var/log/agent-vault-proxy/audit.jsonl >&2 || true
    exit 1
fi
green "  ✓ audit log contains inject_decision: allowed for COMPOSITE_BODY"

green "[9/17] SCOPE-VIOLATION: out-of-scope path -> placeholder verbatim, denied audit"

# TEST_API_KEY is bound to GET "/". A GET to /nope is a path-scope violation:
# per G5, the placeholder is forwarded UN-injected (fail-closed by omission)
# and audited denied. The REAL secret must NOT appear; the placeholder is
# expected to pass through verbatim (documented forward-verbatim behaviour).
docker exec avp-e2e python -c "
import http.client, json
conn = http.client.HTTPConnection('127.0.0.1', 14322, timeout=10)
conn.request(
    'GET',
    'http://upstream.test:8080/nope',
    headers={'Authorization': 'Bearer $PLACEHOLDER', 'Host': 'upstream.test:8080'},
)
resp = conn.getresponse()
body = resp.read().decode('utf-8', errors='replace')
print(json.dumps({'status': resp.status, 'body': body}))
" > "$ECHO_RESPONSE_FILE"

SV_BODY=$(python3 -c "import json; print(json.load(open('$ECHO_RESPONSE_FILE'))['body'])")
SV_AUTH=$(python3 -c "
import json
print(json.loads('''$SV_BODY''').get('headers', {}).get('authorization', ''))
")
if printf '%s' "$SV_AUTH" | grep -qF "$REAL_SECRET"; then
    red "SCOPE-VIOLATION: REAL secret was injected on an out-of-scope request"
    dump_diagnostics
    exit 1
fi
if ! printf '%s' "$SV_AUTH" | grep -qF "$PLACEHOLDER"; then
    red "SCOPE-VIOLATION: expected the placeholder forwarded verbatim, echoed: $SV_AUTH"
    dump_diagnostics
    exit 1
fi
green "  ✓ out-of-scope request forwarded the placeholder verbatim; real secret NOT injected"

SV_AUDIT=$(docker exec avp-e2e sh -c '
  grep -E "\"decision\":\"denied\".*\"reason\":\"binding_scope_violation\".*\"secret_name\":\"TEST_API_KEY\"" \
    /var/log/agent-vault-proxy/audit.jsonl | tail -1
') || SV_AUDIT=""
if [ -z "$SV_AUDIT" ]; then
    red "SCOPE-VIOLATION: no denied/binding_scope_violation audit entry for TEST_API_KEY"
    docker exec avp-e2e tail -5 /var/log/agent-vault-proxy/audit.jsonl >&2 || true
    exit 1
fi
green "  ✓ audit log contains denied: binding_scope_violation for TEST_API_KEY"

green "[10/17] FAIL-CLOSED: bound secret unavailable -> 503, no leak, audited"

# FAILCLOSED_KEY is bound to GET /failclosed but its secret is NOT in the
# static secrets file. The binding matches, the fetch fails, and AVP returns
# 503 without ever reaching the upstream. Assert the 503 and the audited
# secret_unavailable denial. No real secret exists to leak, and the placeholder
# never reaches the upstream (503 short-circuits before forwarding).
FC_STATUS=$(docker exec avp-e2e python -c "
import http.client
conn = http.client.HTTPConnection('127.0.0.1', 14322, timeout=10)
conn.request(
    'GET',
    'http://upstream.test:8080/failclosed',
    headers={'Authorization': 'Bearer failclosed-PLACEHOLDER-01HXY1234567FC', 'Host': 'upstream.test:8080'},
)
print(conn.getresponse().status)
" | tr -d '[:space:]')
if [ "$FC_STATUS" != "503" ]; then
    red "FAIL-CLOSED: expected 503 for an unavailable secret, got '$FC_STATUS'"
    dump_diagnostics
    exit 1
fi
green "  ✓ unavailable secret returned 503 (fail-closed; request never forwarded)"

FC_AUDIT=$(docker exec avp-e2e sh -c '
  grep -E "\"decision\":\"denied\".*\"reason\":\"secret_unavailable.*\"secret_name\":\"FAILCLOSED_KEY\"" \
    /var/log/agent-vault-proxy/audit.jsonl | tail -1
') || FC_AUDIT=""
if [ -z "$FC_AUDIT" ]; then
    red "FAIL-CLOSED: no denied/secret_unavailable audit entry for FAILCLOSED_KEY"
    docker exec avp-e2e tail -5 /var/log/agent-vault-proxy/audit.jsonl >&2 || true
    exit 1
fi
green "  ✓ audit log contains denied: secret_unavailable for FAILCLOSED_KEY"

green "[11/17] HOST-VALIDATION: installed image rejects junk/TLD-wildcard hosts, gates wildcards"

# Exercise the DEPLOYED image's config-load validation (not a wire path, but
# runs the real installed code inside the container). Rejects empty /
# whitespace / bare-* / public-suffix wildcards always; registrable-domain
# wildcards are rejected by default and accepted only with the opt-in flag.
docker exec avp-e2e python -c "
import sys
from kow.config import Config
from pydantic import ValidationError
def mk(host, allow=None):
    d = {'version': 1, 'secrets': {'F': {'placeholder': 'F-PLACEHOLDER-01HXY1234567890ABCD',
         'inject': {'header': 'Authorization', 'format': 'Bearer {F}'},
         'bindings': [{'host': host}]}}, 'audit': {'path': '/tmp/x.jsonl'},
         'backend': {'type': 'static', 'config': {'type': 'static', 'path': '/tmp/s.yml'}}}
    if allow is not None: d['allow_wildcard_hosts'] = allow
    return d
def rejected(h, a=None):
    try: Config.model_validate(mk(h, a)); return False
    except ValidationError: return True
def accepted(h, a=None):
    try: Config.model_validate(mk(h, a)); return True
    except ValidationError: return False
checks = [('empty', rejected('')), ('whitespace', rejected('   ')), ('bare-*', rejected('*')),
    ('public-suffix *.co.uk', rejected('*.co.uk', True)), ('public-suffix *.com', rejected('*.com', True)),
    ('wildcard off by default', rejected('*.github.com')),
    ('wildcard opt-in accepted', accepted('*.github.com', True)),
    ('exact host accepted', accepted('api.github.com'))]
bad = [n for n, ok in checks if not ok]
if bad:
    print('HOST-VALIDATION FAILURES:', bad); sys.exit(1)
print('all host-validation checks passed')
" || { red "HOST-VALIDATION: installed config-load validation did not behave as expected"; dump_diagnostics; exit 1; }
green "  ✓ image rejects empty/whitespace/bare-*/public-suffix; wildcards gated by opt-in"

# The next four run the DEPLOYED image's own policy/config/resolution code via
# `docker exec` — the right shape for pre-wire decisions (they never reach an
# upstream, so there is no wire echo to assert). Dict-based configs avoid
# YAML-in-shell quoting. Each was verified against the same installed modules.

green "[12/17] FORWARD-UNMODIFIED: installed policy forwards an unbound destination un-injected"
docker exec avp-e2e python -c "
import sys
from kow.config import Config
from kow.policy import decide
def cfg(policy):
    return Config.model_validate({'version': 1, 'secrets': {'F': {'placeholder': 'F-PLACEHOLDER-01HXY1234567890ABCD', 'inject': {'header': 'Authorization', 'format': 'Bearer {F}'}, 'bindings': [{'host': 'bound.test'}]}}, 'audit': {'path': '/tmp/x.jsonl'}, 'unmatched_destination_policy': policy, 'backend': {'type': 'static', 'config': {'type': 'static', 'path': '/tmp/s.yml'}}})
d = decide(config=cfg('forward_unmodified'), host='unbound.test', port=80, method='GET', path='/', connect_host=None, header_get=lambda n: None)
if d.decision != 'forward_unmodified':
    print('FAIL forward:', d.decision, d.reason); sys.exit(1)
d2 = decide(config=cfg('deny'), host='unbound.test', port=80, method='GET', path='/', connect_host=None, header_get=lambda n: None)
if not (d2.decision == 'denied' and d2.reason == 'unmatched_destination' and d2.response_status == 403):
    print('FAIL deny:', d2.decision, d2.reason); sys.exit(1)
print('forward/deny policy OK')
" || { red "FORWARD-UNMODIFIED: installed policy behaved unexpectedly"; dump_diagnostics; exit 1; }
green "  ✓ forward_unmodified forwards unbound; deny returns 403 (installed policy)"

green "[13/17] SNI-MISMATCH: installed policy denies CONNECT-host vs request-host disagreement"
docker exec avp-e2e python -c "
import sys
from kow.config import Config
from kow.policy import decide
c = Config.model_validate({'version': 1, 'secrets': {'F': {'placeholder': 'F-PLACEHOLDER-01HXY1234567890ABCD', 'inject': {'header': 'Authorization', 'format': 'Bearer {F}'}, 'bindings': [{'host': 'bound.test'}]}}, 'audit': {'path': '/tmp/x.jsonl'}, 'backend': {'type': 'static', 'config': {'type': 'static', 'path': '/tmp/s.yml'}}})
d = decide(config=c, host='bound.test', port=443, method='GET', path='/', connect_host='evil.test', header_get=lambda n: None)
if not (d.decision == 'denied' and d.reason == 'sni_host_mismatch' and d.response_status == 403):
    print('FAIL sni:', d.decision, d.reason); sys.exit(1)
print('sni_host_mismatch OK')
" || { red "SNI-MISMATCH: installed policy behaved unexpectedly"; dump_diagnostics; exit 1; }
green "  ✓ CONNECT/request host mismatch denied as sni_host_mismatch (installed policy)"

green "[14/17] BINDING-SOURCE-BOTH: file-only binding survives in both mode (2026-07-02 regression)"
docker exec avp-e2e python -c "
import sys
from kow.config import Config
from kow.runtime_bindings import resolve_runtime_bindings
from kow.placeholders import derive_placeholder
SALT = b'\x05' * 32
np = derive_placeholder('NOTED', SALT); fp = derive_placeholder('FILEONLY', SALT)
cfg = Config.model_validate({'version': 1, 'secrets': {
  'NOTED': {'placeholder': np, 'inject': {'header': 'Authorization', 'format': 'Bearer {NOTED}'}, 'bindings': [{'host': 'file-noted.example.com'}]},
  'FILEONLY': {'placeholder': fp, 'inject': {'header': 'Authorization', 'format': 'Bearer {FILEONLY}'}, 'bindings': [{'host': 'file-only.example.com'}]}},
  'audit': {'path': '/tmp/x.jsonl'}, 'binding_source': 'both', 'backend': {'type': 'static', 'config': {'type': 'static', 'path': '/tmp/s.yml'}}})
class B:
    def list_secret_names(self): return ['NOTED']
    def fetch(self, n, ctx=None): return 'v'
    def fetch_with_meta(self, n, ctx=None): return ('v', 'host: noted.example.com') if n == 'NOTED' else ('v', '')
r = resolve_runtime_bindings(backend=B(), binding_source='both', install_salt=SALT, file_config=cfg)
if 'FILEONLY' not in r.specs:
    print('FAIL: file-only binding DROPPED in both mode'); sys.exit(1)
print('both-mode file-only survives OK')
" || { red "BINDING-SOURCE-BOTH: file-only binding did not survive both mode"; dump_diagnostics; exit 1; }
green "  ✓ file-only binding stays active in both mode (installed resolver; regression guard)"

green "[15/17] OAUTH2-CONFIG: installed image loads oauth2_refresh + SSRF-guards the token_url"
# Full token-exchange/rotation/write-back wire flow needs an HTTPS mock that
# passes the SSRF guard (loopback + private are blocked by design); that lives
# in tests/test_oauth2_refresh_e2e.py. Here we assert the installed image
# recognises the injector, applies a provider preset, and rejects a private
# token_url at config-load.
docker exec avp-e2e python -c "
import sys
from kow.config import Config
from pydantic import ValidationError
base = {'version': 1, 'audit': {'path': '/tmp/x.jsonl'}, 'backend': {'type': 'static', 'config': {'type': 'static', 'path': '/tmp/s.yml'}}}
def mk(inj):
    d = dict(base); d['secrets'] = {'GH': {'placeholder': 'GH-PLACEHOLDER-01HXY1234567890ABCD', 'inject': inj, 'bindings': [{'host': 'api.example.com'}]}}; return d
c = Config.model_validate(mk({'type': 'oauth2_refresh', 'provider': 'google', 'client_id_secret': 'CID', 'client_secret_secret': 'CSEC', 'refresh_token_secret': 'RT'}))
if type(c.secrets['GH'].inject).__name__ != 'Oauth2RefreshInjector':
    print('FAIL: oauth2_refresh not recognised'); sys.exit(1)
try:
    Config.model_validate(mk({'type': 'oauth2_refresh', 'token_url': 'https://10.0.0.5/token', 'client_auth_method': 'body_post', 'client_id_secret': 'CID', 'client_secret_secret': 'CSEC', 'refresh_token_secret': 'RT'}))
    print('FAIL: SSRF did not reject private token_url'); sys.exit(1)
except ValidationError:
    pass
print('oauth2 config + SSRF OK')
" || { red "OAUTH2-CONFIG: installed image did not load/guard oauth2_refresh as expected"; dump_diagnostics; exit 1; }
green "  ✓ oauth2_refresh loads with provider preset; private token_url SSRF-rejected (installed)"

green "[16/17] OAUTH2-WIRE: refresh-token exchange -> minted Bearer on the wire + audits"

# GET /oauth with the oauth placeholder. AVP fetches the refresh token, POSTs it
# to the mock token endpoint over HTTPS (trusted via SSL_CERT_FILE), receives an
# access_token, and injects it as a Bearer to the upstream — the full v0.7 flow.
# The mock returns a ROTATED refresh_token, so refresh_token_rotated must fire
# too (write-back to the read-only static backend is a no-op -> the event's
# outcome is write_back_unavailable; the rotation *detection* is what we assert).
docker exec avp-e2e python -c "
import http.client, json
conn = http.client.HTTPConnection('127.0.0.1', 14322, timeout=15)
conn.request(
    'GET',
    'http://upstream.test:8080/oauth',
    headers={'Authorization': 'Bearer oauth-PLACEHOLDER-01HXY1234567890OATH', 'Host': 'upstream.test:8080'},
)
resp = conn.getresponse()
body = resp.read().decode('utf-8', errors='replace')
print(json.dumps({'status': resp.status, 'body': body}))
" > "$ECHO_RESPONSE_FILE"

OA_STATUS=$(python3 -c "import json; print(json.load(open('$ECHO_RESPONSE_FILE'))['status'])")
OA_BODY=$(python3 -c "import json; print(json.load(open('$ECHO_RESPONSE_FILE'))['body'])")
if [ "$OA_STATUS" != "200" ]; then
    red "OAUTH2-WIRE: upstream returned $OA_STATUS, expected 200"
    red "body: $OA_BODY"
    dump_diagnostics
    exit 1
fi
OA_AUTH=$(python3 -c "
import json
print(json.loads('''$OA_BODY''').get('headers', {}).get('authorization', ''))
")
if ! printf '%s' "$OA_AUTH" | grep -qF "Bearer MOCK-ACCESS-TOKEN-abc123"; then
    red "OAUTH2-WIRE: minted access token did not reach the upstream; echoed: $OA_AUTH"
    dump_diagnostics
    exit 1
fi
if printf '%s' "$OA_AUTH" | grep -qF "oauth-PLACEHOLDER"; then
    red "OAUTH2-WIRE: placeholder leaked to the upstream"
    dump_diagnostics
    exit 1
fi
green "  ✓ refresh-token exchanged; minted Bearer reached the upstream; placeholder gone"

OA_TX=$(docker exec avp-e2e sh -c '
  grep -E "\"type\":\"token_exchange\".*\"outcome\":\"success\"" \
    /var/log/agent-vault-proxy/audit.jsonl | tail -1
') || OA_TX=""
if [ -z "$OA_TX" ]; then
    red "OAUTH2-WIRE: no token_exchange: success audit event"
    docker exec avp-e2e tail -5 /var/log/agent-vault-proxy/audit.jsonl >&2 || true
    exit 1
fi
green "  ✓ audit log contains token_exchange: success"

OA_ROT=$(docker exec avp-e2e sh -c '
  grep -E "\"type\":\"refresh_token_rotated\"" \
    /var/log/agent-vault-proxy/audit.jsonl | tail -1
') || OA_ROT=""
if [ -z "$OA_ROT" ]; then
    red "OAUTH2-WIRE: no refresh_token_rotated audit event"
    docker exec avp-e2e tail -5 /var/log/agent-vault-proxy/audit.jsonl >&2 || true
    exit 1
fi
green "  ✓ audit log contains refresh_token_rotated (write-back attempted; static backend => write_back_unavailable)"

green "[17/17] NEGATIVE test: unbound destination denied"

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
