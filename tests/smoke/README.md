# Smoke test runbook

Goal: prove the proxy works end-to-end against real BWS and real Anthropic API,
**without touching your installed systemd unit, system HTTPS_PROXY, or any
host firewall rules**. Everything lives in `/tmp/avp-smoke/` and gets cleaned
up when you delete the directory.

## One-command run (recommended)

```bash
export BWS_ORG_ID=<your-bitwarden-org-uuid>
./tests/smoke/run-smoke.sh
```

That's it. The script does setup, runs all three layers, starts and stops
the proxy, and prints PASS/FAIL with audit-log tail at the end.

`BWS_ACCESS_TOKEN` is auto-resolved from `~/.config/bws/token` if present.
Set it explicitly to override.

If you prefer manual control or need to debug a specific layer, the
step-by-step instructions below remain valid.

If anything looks wrong at any step, Ctrl-C the proxy terminal and stop.
No state outside `/tmp/avp-smoke/` and `~/.mitmproxy/` (mitmproxy's CA dir,
which already exists from prior use).

## Three layers, in order

| Layer | Proves | Time |
|---|---|---|
| 1 | Unit tests: logic correct in isolation | 2 sec |
| 2 | BWS integration: real Bitwarden fetch works | 30 sec |
| 3 | Full pipeline: proxy substitutes against real Anthropic API | 60 sec |

Run them in order. If Layer 2 fails, don't bother with Layer 3 yet.

## Setup (do once)

```bash
mkdir -p /tmp/avp-smoke
chmod 700 /tmp/avp-smoke

# Drop your BWS access token into the smoke dir (the one for the project
# containing ANTHROPIC_API_KEY). The token from your normal BWS preload works.
cp ~/.config/bws/token /tmp/avp-smoke/bws-token
chmod 400 /tmp/avp-smoke/bws-token

# Edit tests/smoke/bindings.smoke.yaml — set bws.organization_id to your
# Bitwarden organization UUID.
```

To find your organization UUID, check the Bitwarden web UI URL when viewing
the org, or `bws project list` returns it.

## Layer 1: unit tests

```bash
cd <your-checkout>/agent-vault-proxy
.venv/bin/pytest -v
```

Expected: all tests pass.

If anything fails: stop. Don't proceed.

## Layer 2: BWS read test (no proxy involved)

```bash
cd <your-checkout>/agent-vault-proxy
.venv/bin/python tests/smoke/layer2_bws_read.py
```

Expected output:
```
OK   [ANTHROPIC_API_KEY]: fetched, length=108, prefix='sk-ant-a'
PASS: BWS integration works end-to-end
```

The script prints only the length and first 8 characters, never the full
value.

If this fails:
- `BwsUnavailableError: BWS auth failed`, token invalid or expired
- `SecretNotFoundError`: secret name doesn't exist in BWS, or the machine
  account doesn't have read access to it
- network error - BWS API unreachable

Fix the BWS side before going to Layer 3.

## Layer 3, Full pipeline against real Anthropic API

This needs two terminals.

### Terminal 1, start the proxy

```bash
cd <your-checkout>/agent-vault-proxy
.venv/bin/python -m kow --set avp_config=tests/smoke/bindings.smoke.yaml
```

Expected: mitmproxy banner, listening on 127.0.0.1:14322. Leave this
terminal open.

On first run, mitmproxy generates its CA in `~/.mitmproxy/`. If you don't
already have one, you'll see it create the files.

### Terminal 2 - run the test client

```bash
cd <your-checkout>/agent-vault-proxy
.venv/bin/python tests/smoke/layer3_proxy_anthropic.py
```

Expected:
```
Anthropic returned: 200
  reply text: 'pong' (or similar short reply)

--- last 5 audit events ---
  inject_decision: allowed
  upstream_response: 200

PASS: full pipeline works, Anthropic accepted the substituted request
```

If you see `401`: the proxy forwarded the placeholder verbatim (substitution
broken) OR the real key is invalid. Check the audit log to determine which:
```bash
tail /tmp/avp-smoke/audit.jsonl
```
`inject_decision: denied` means the proxy refused to substitute (config
mismatch). `inject_decision: allowed` followed by `upstream_response: 401`
means the substituted key didn't work at Anthropic (real-key problem).

### Optional, negative tests

```bash
.venv/bin/python tests/smoke/layer3_negative.py
```

Sends a request to an unbound destination, expects 403 from the proxy.

## What this smoke test does NOT prove

- Anything about nft kernel egress lockdown (Test G7) - that's a system-level
  config we haven't applied yet
- Anything about bwrap CA installation - we used mitmproxy's CA explicitly
  via `--cacert` in the test client; the agent integration is separate
- Per-request synchronous fsync ordering (G6 micro-property): that's
  asserted by the unit test suite

These are the next-step verifications, AFTER smoke test passes.

## Teardown

```bash
# Stop the proxy with Ctrl-C in Terminal 1.
rm -rf /tmp/avp-smoke
```

That's it. Nothing in `/etc/`, `/var/`, or your installed systemd unit
was touched.

## If you want a paranoid pre-flight check

Before running Layer 3, verify the proxy isn't doing anything unexpected:

```bash
# Confirm the proxy is listening only on loopback
ss -tlnp | grep 14322
# Should show: 127.0.0.1:14322

# Confirm the proxy process's UID is yours, not root
ps -o user,pid,cmd -C python | grep mitmdump
```

If the proxy is bound to anything other than 127.0.0.1, or running as root,
stop and investigate before proceeding.
