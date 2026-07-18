"""Container-free E2E assertions against a REAL running avp proxy process.

Sends absolute-URI requests straight to the proxy via http.client (no urllib
no_proxy/loopback bypass), so every request genuinely transits the proxy.
Reads the generated secrets file for the expected real values, so no secret
literal lives in this file. Stdlib + PyYAML (a runtime dep) only.

Cases (mirrors tests/docker-e2e, minus oauth which needs a mock HTTPS endpoint):
  POS-HDR / POS-BODY / POS-MULTI / POS-COMPOSITE-HEADER / POS-COMPOSITE-BODY
  FAILCLOSED (missing secret -> 503) / NEG (unbound host -> 403)
Plus: allowed + deny audit events, and NO real secret bytes in the proxy log.
"""

from __future__ import annotations

import base64
import http.client
import json
import sys
from pathlib import Path

import yaml

ECHO_PORT = sys.argv[1]
PROXY_HOST, PROXY_PORT = "127.0.0.1", int(sys.argv[2])
WORKDIR = Path(sys.argv[3])
AUDIT = WORKDIR / "audit.jsonl"
PROXY_LOG = WORKDIR / "proxy.log"

PH = {
    "hdr": "test-PLACEHOLDER-01HXY1234567890ABC",
    "body": "body-PLACEHOLDER-01HXY1234567890BDY",
    "multi": "multi-PLACEHOLDER-01HXY1234567890MLT",
    "cphdr": "cphdr-PLACEHOLDER-01HXY1234567890CH",
    "cpbody": "cpbody-PLACEHOLDER-01HXY1234567890CB",
    "failclosed": "failclosed-PLACEHOLDER-01HXY1234567FC",
}

secrets = yaml.safe_load((WORKDIR / "secrets.yaml").read_text())["secrets"]
REAL_HDR = secrets["TEST_API_KEY"]
REAL_BODY = secrets["TEST_BODY_KEY"]
REAL_MULTI = secrets["TEST_MULTI_KEY"]
COMPOSITE = base64.b64encode(f"{secrets['E2E_USER']}:{secrets['E2E_PASS']}".encode()).decode()
ALL_REAL = [
    secrets[k] for k in ("TEST_API_KEY", "TEST_BODY_KEY", "TEST_MULTI_KEY", "E2E_USER", "E2E_PASS")
]
# Everything that must NEVER reach a log: the source values AND the rendered
# composite Basic credential (which is directly usable on its own).
_SECRET_VALUES = [*ALL_REAL, COMPOSITE]


def redact(s: str) -> str:
    """Scrub any real secret / composite value from a string before it is
    printed — a failing assertion must not spill credentials into CI output."""
    for v in _SECRET_VALUES:
        if v:
            s = s.replace(v, "***REDACTED***")
    return s


fails: list[str] = []
oks: list[str] = []


def via_proxy(method, abs_url, headers=None, body=None):
    conn = http.client.HTTPConnection(PROXY_HOST, PROXY_PORT, timeout=15)
    try:
        conn.request(method, abs_url, body=body, headers=headers or {})
        r = conn.getresponse()
        return r.status, r.read()
    finally:
        conn.close()


def echo_of(body_bytes):
    return json.loads(body_bytes)


def hdr_ci(headers: dict, name: str) -> str:
    low = name.lower()
    for k, v in headers.items():
        if k.lower() == low:
            return v
    return ""


def check(name, cond, detail=""):
    (oks if cond else fails).append(f"{name}{'' if cond else ': ' + redact(detail)}")


url = f"http://127.0.0.1:{ECHO_PORT}"
JSON = {"Content-Type": "application/json"}

# POS-HDR
st, b = via_proxy("GET", f"{url}/hdr", {"Authorization": f"Bearer {PH['hdr']}"})
auth = hdr_ci(echo_of(b).get("headers", {}), "Authorization") if st == 200 else f"<status {st}>"
check("POS-HDR real secret injected", REAL_HDR in auth, f"authz={auth!r}")
check("POS-HDR placeholder not leaked", PH["hdr"] not in auth)

# POS-BODY
st, b = via_proxy(
    "POST", f"{url}/body", JSON, json.dumps({"api_token": PH["body"], "n": "e2e"}).encode()
)
eb = echo_of(b).get("body", "") if st == 200 else f"<status {st}>"
check("POS-BODY real secret in body", REAL_BODY in eb, f"body={eb!r}")
check("POS-BODY placeholder not leaked", PH["body"] not in eb)

# POS-MULTI (header + body from one placeholder)
st, b = via_proxy(
    "POST",
    f"{url}/multi",
    {**JSON, "X-Multi-Key": PH["multi"]},
    json.dumps({"signed_payload": PH["multi"], "n": "e2e"}).encode(),
)
echo = echo_of(b) if st == 200 else {"headers": {}, "body": f"<status {st}>"}
mh = hdr_ci(echo.get("headers", {}), "X-Multi-Key")
mb = echo.get("body", "")
check("POS-MULTI header substituted", REAL_MULTI in mh, f"x-multi-key={mh!r}")
check("POS-MULTI body substituted", REAL_MULTI in mb, f"body={mb!r}")
check("POS-MULTI placeholder not leaked", PH["multi"] not in (mh + mb))

# POS-COMPOSITE-HEADER
st, b = via_proxy("GET", f"{url}/composite-header", {"Authorization": f"Bearer {PH['cphdr']}"})
auth = hdr_ci(echo_of(b).get("headers", {}), "Authorization") if st == 200 else f"<status {st}>"
check("POS-COMPOSITE-HEADER Basic rendered", f"Basic {COMPOSITE}" in auth, f"authz={auth!r}")
check("POS-COMPOSITE-HEADER placeholder not leaked", PH["cphdr"] not in auth)

# POS-COMPOSITE-BODY
st, b = via_proxy(
    "POST", f"{url}/composite-body", JSON, json.dumps({"cred": PH["cpbody"], "n": "e2e"}).encode()
)
eb = echo_of(b).get("body", "") if st == 200 else f"<status {st}>"
check("POS-COMPOSITE-BODY rendered into body", COMPOSITE in eb, f"body={eb!r}")
check("POS-COMPOSITE-BODY placeholder not leaked", PH["cpbody"] not in eb)

# FAILCLOSED (secret absent -> 503, never forwarded)
st, _b = via_proxy("GET", f"{url}/failclosed", {"Authorization": f"Bearer {PH['failclosed']}"})
check("FAILCLOSED missing secret -> 503", st == 503, f"got {st}")

# NEG (unbound host string 'localhost' -> deny 403)
st, _b = via_proxy(
    "GET", f"http://localhost:{ECHO_PORT}/hdr", {"Authorization": f"Bearer {PH['hdr']}"}
)
check("NEG unbound destination -> 403", st == 403, f"got {st}")

# ── AUDIT + LEAK ─────────────────────────────────────────────────────────────
events = (
    [json.loads(x) for x in AUDIT.read_text().splitlines() if x.strip()] if AUDIT.exists() else []
)
allowed = [
    e for e in events if e.get("type") == "inject_decision" and e.get("decision") == "allowed"
]
denies = [e for e in events if e.get("type") == "deny"]
check("AUDIT >=5 allowed inject_decisions", len(allowed) >= 5, f"got {len(allowed)}")
check("AUDIT >=1 deny", len(denies) >= 1, f"got {len(denies)}")

audit_text = AUDIT.read_text() if AUDIT.exists() else ""
log_text = PROXY_LOG.read_text() if PROXY_LOG.exists() else ""
leaked = [r for r in _SECRET_VALUES if r in audit_text or r in log_text]
check(
    "NO real secret bytes in audit log or proxy log", not leaked, f"leaked {len(leaked)} value(s)"
)

for o in oks:
    print(f"  PASS {o}")
for f in fails:
    print(f"  FAIL {f}")
print(f"\n{'ALL PASS (' + str(len(oks)) + ')' if not fails else 'FAILURES: ' + str(len(fails))}")
sys.exit(1 if fails else 0)
