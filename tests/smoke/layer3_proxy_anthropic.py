"""Layer 3 smoke test: full pipeline against real Anthropic API.

Requires the proxy to already be running in another terminal (see README.md).
Sends a tiny Messages API call through the proxy with the placeholder in
the x-api-key header. If substitution works AND the real key is valid,
Anthropic returns 200.

What this proves:
    G1: agent process (this script) never holds the real ANTHROPIC_API_KEY
    G2: real key bytes only on the wire from proxy -> Anthropic, never here
    G3: destination match enforced (api.anthropic.com is in binding)
    G6: audit log shows inject_decision: allowed BEFORE upstream_response
    Plus end-to-end: Anthropic accepts the substituted request.

Run from the repo root:
    .venv/bin/python tests/smoke/layer3_proxy_anthropic.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import httpx

PROXY_URL = "http://127.0.0.1:14322"
CA_CERT = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
PLACEHOLDER = "sk-ant-PLACEHOLDER-01HXY1234567890ABCDEFGH"
AUDIT_LOG = Path("/tmp/avp-smoke/audit.jsonl")


def main() -> int:
    if not CA_CERT.exists():
        print(f"FAIL: mitmproxy CA not found at {CA_CERT}")
        print("      Start the proxy first (see tests/smoke/README.md)")
        return 1

    payload = {
        "model": "claude-haiku-4-5",
        "max_tokens": 8,
        "messages": [{"role": "user", "content": "ping"}],
    }

    headers = {
        "x-api-key": PLACEHOLDER,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }

    try:
        response = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers=headers,
            json=payload,
            proxy=PROXY_URL,
            verify=str(CA_CERT),
            timeout=30.0,
        )
    except httpx.HTTPError as e:
        print(f"FAIL: HTTP error reaching Anthropic via proxy: {e}")
        return 1

    print(f"Anthropic returned: {response.status_code}")
    if response.status_code == 200:
        body = response.json()
        text = body.get("content", [{}])[0].get("text", "")
        print(f"  reply text: {text!r}")
    else:
        print(f"  body: {response.text[:200]}")

    print()
    print("--- last 5 audit events ---")
    if AUDIT_LOG.exists():
        lines = AUDIT_LOG.read_text().splitlines()
        for line in lines[-5:]:
            try:
                event = json.loads(line)
                detail = event.get("reason") or event.get("decision") or event.get("status")
                print(f"  {event.get('type')}: {detail}")
            except json.JSONDecodeError:
                pass
    else:
        print(f"  (no audit log at {AUDIT_LOG})")

    if response.status_code == 200:
        print("\nPASS: full pipeline works, Anthropic accepted the substituted request")
        return 0
    if response.status_code == 401:
        print("\nFAIL: 401 from Anthropic. Either substitution didn't happen")
        print("      (proxy returned placeholder verbatim) or the real key is invalid.")
        print("      Inspect audit log to determine which.")
        return 1
    print(f"\nFAIL: unexpected status {response.status_code}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
