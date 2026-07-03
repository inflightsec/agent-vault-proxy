"""Stateful no-leak invariant over the REAL addon inject path.

``test_matching_properties.py`` proves the matcher is correct in isolation.
This proves the *integration* still honours it: it drives the actual
``http_connect`` -> ``requestheaders`` pipeline (no mock), then asserts the
one invariant that matters —

    the real secret value lands in the outgoing request IFF that request is
    authorized for the secret, and never appears in the audit stream.

Why stateful and not a plain ``@given``: the caching client survives a config
reload, so a value fetched while a request was authorized could leak on a
later request after the scope tightens. That cross-reload path is the drift a
unit test can't see — the matcher stays perfect while the addon serves a stale
cached secret to a now-unauthorized request. The ``reload`` rule exercises it.

The oracle (:func:`_authorized`) is a hand-written, independent restatement of
the policy — it does NOT import the matcher — so a regression that makes the
addon and the matcher drift *together* still fails here.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule
from mitmproxy.test import tflow

from agent_vault_proxy.addon import AgentVaultProxyAddon
from agent_vault_proxy.audit import AuditWriter
from agent_vault_proxy.backends import FetchContext
from agent_vault_proxy.caching import CachingSecretsClient
from agent_vault_proxy.config import load_config

# Distinctive so a substring search in headers/audit is unambiguous.
REAL = "sk-REAL-DO-NOT-LEAK-0xDEADBEEF"
PLACEHOLDER = "sk-PLACEHOLDER-01HXY1234567890ABCDEFGHIJ"


# Two scope variants for the SAME secret+host. "wide" = any method/path;
# "narrow" = only POST under /v1/**. Reloading between them, with the cache
# warm, is the stateful drift we hunt.
def _yaml(bindings: str, audit: Path) -> str:
    return f"""
version: 1
secrets:
  OPENAI_API_KEY:
    placeholder: "{PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "Bearer {{OPENAI_API_KEY}}"
    bindings:
{bindings}
unmatched_destination_policy: deny
audit:
  path: {audit}
  fail_on_unwritable: true
"""


_BINDINGS = {
    "wide": '      - host: "api.openai.com"\n',
    "narrow": (
        '      - host: "api.openai.com"\n        methods: ["POST"]\n        paths: ["/v1/**"]\n'
    ),
}

HOSTS = ["api.openai.com", "evil.example.com"]  # bound / unbound
METHODS = ["GET", "POST"]
PATHS = ["/v1/chat", "/v1/a/b", "/other"]


def _authorized(variant: str, host: str, method: str, path: str) -> bool:
    """Independent oracle — plain Python, no matcher import."""
    if host != "api.openai.com":
        return False
    if variant == "wide":
        return True
    return method == "POST" and path.startswith("/v1/")


class _FakeBackend:
    """Constant-value backend; first I/O is fetch (Protocol contract)."""

    def fetch(self, name: str, ctx: FetchContext | None = None) -> str:
        return REAL


class NoLeakMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self._dir = tempfile.TemporaryDirectory()
        root = Path(self._dir.name)
        self._audit = root / "audit.jsonl"
        self._configs = {}
        for variant, bindings in _BINDINGS.items():
            p = root / f"{variant}.yaml"
            p.write_text(_yaml(bindings, self._audit))
            self._configs[variant] = load_config(p)
        self.addon = AgentVaultProxyAddon()
        self.addon.audit = AuditWriter(str(self._audit))
        # ONE caching client for the machine's life — survives reloads.
        self.addon.client = CachingSecretsClient(
            _FakeBackend(), ttl_seconds=300, jitter_seconds=0, max_entries=100
        )
        self.variant = "wide"

    @initialize()
    def _start(self) -> None:
        self.addon.config = self._configs["wide"]
        self.variant = "wide"

    @rule(variant=st.sampled_from(list(_BINDINGS)))
    def reload(self, variant: str) -> None:
        # Reassign config (cache deliberately untouched) — mirrors a live
        # bindings reload while secrets stay cached.
        self.addon.config = self._configs[variant]
        self.variant = variant

    @rule(
        host=st.sampled_from(HOSTS),
        method=st.sampled_from(METHODS),
        path=st.sampled_from(PATHS),
    )
    def request(self, host: str, method: str, path: str) -> None:
        flow = tflow.tflow()
        flow.request.host = host
        flow.request.port = 443
        flow.request.scheme = "https"
        flow.request.method = method
        flow.request.path = path
        flow.request.headers["Authorization"] = f"Bearer {PLACEHOLDER}"

        self.addon.http_connect(flow)
        if flow.response is None:  # destination allowed; run the inject path
            self.addon.requestheaders(flow)

        injected = REAL in flow.request.headers.get("Authorization", "")
        expected = _authorized(self.variant, host, method, path)
        assert injected == expected, (
            f"leak/deny drift: variant={self.variant} {method} {host}{path} "
            f"injected={injected} expected={expected}"
        )

    @invariant()
    def secret_never_in_audit(self) -> None:
        if self._audit.exists():
            assert REAL not in self._audit.read_text()

    def teardown(self) -> None:
        self._dir.cleanup()


TestNoLeak = NoLeakMachine.TestCase
