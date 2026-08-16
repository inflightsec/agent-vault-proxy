"""Surface 1 (egress scheme) — documents a defense-in-depth observation.

G2 promises real secret bytes reach the wire only inside upstream TLS records.
The injection path is SCHEME-AGNOSTIC by design: a plain-HTTP request (no CONNECT,
so decide()'s SNI/Host G3 gate is skipped) to a bound host still substitutes the
real secret. The local-e2e harness (tests/local-e2e) drives the proxy over
http:// loopback and ASSERTS injection on every positive case — so scheme-agnostic
injection is intended, tested behavior, and G2's TLS-only property is enforced
operationally (HTTPS_PROXY + egress firewall), not by a per-request code gate.

This asserts the stricter *code-level* G2 invariant (no real secret substituted
onto a non-TLS request). It xfails because the current design intentionally does
not enforce it in code. A scheme gate would satisfy it but is a BEHAVIOR CHANGE
that breaks the http-based local-e2e harness — a maintainer design decision, not
landed here. Kept as the pin: if a code-level scheme gate is ever added, this
flips to an unexpected pass (strict) and must become a plain assertion.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from mitmproxy.test import tflow

from kow.addon import AgentVaultProxyAddon
from kow.audit import AuditWriter
from kow.backends import FetchContext
from kow.caching import CachingSecretsClient
from kow.config import load_config
from kow.secret import Secret

PLACEHOLDER = "sk-PLACEHOLDER-01HXY1234567890ABCDEFGHIJ"
REAL = "sk-REAL-DO-NOT-LEAK-0xDEADBEEF"


class _FakeBackend:
    def fetch(self, name: str, ctx: FetchContext | None = None) -> Secret:
        return Secret(REAL)


def _build_addon(tmp_path: Path) -> AgentVaultProxyAddon:
    audit = tmp_path / "audit.jsonl"
    cfg = tmp_path / "bindings.yaml"
    cfg.write_text(
        f"""
version: 1
secrets:
  OPENAI_API_KEY:
    placeholder: "{PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "Bearer {{OPENAI_API_KEY}}"
    bindings:
      - host: "api.openai.com"
unmatched_destination_policy: deny
audit:
  path: {audit}
  fail_on_unwritable: true
"""
    )
    addon = AgentVaultProxyAddon()
    addon.config = load_config(cfg)
    addon.audit = AuditWriter(str(audit))
    addon.client = CachingSecretsClient(
        _FakeBackend(), ttl_seconds=300, jitter_seconds=0, max_entries=100
    )
    return addon


@pytest.mark.xfail(
    strict=True,
    reason="Injection is scheme-agnostic by design (local-e2e drives http:// and "
    "asserts injection); G2's TLS-only property is operational, not a code gate. "
    "A code-level scheme gate is a maintainer decision — see the module docstring.",
)
def test_plain_http_request_must_not_receive_real_secret(tmp_path: Path) -> None:
    addon = _build_addon(tmp_path)

    # A plain-HTTP proxied request: no CONNECT tunnel, so http_connect never
    # fires and avp_connect_host stays unset (G3/SNI gate skipped in decide()).
    flow: Any = tflow.tflow()
    flow.request.scheme = "http"
    flow.request.host = "api.openai.com"
    flow.request.port = 80
    flow.request.method = "POST"
    flow.request.path = "/v1/chat/completions"
    flow.request.headers["Authorization"] = f"Bearer {PLACEHOLDER}"

    # Deliberately no addon.http_connect(flow) — non-tunneled plain HTTP.
    addon.requestheaders(flow)

    outgoing = flow.request.headers.get("Authorization", "")
    assert REAL not in outgoing, (
        "code-level G2: real secret substituted onto a non-TLS request "
        "(currently intended — see module docstring)."
    )
