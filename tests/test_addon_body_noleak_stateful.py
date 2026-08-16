"""Stateful no-leak invariant over the REAL addon BODY-injection path.

Rec 2 surface #3 / Rec 3 coverage gap: the header path has NoLeakMachine
(test_addon_noleak_stateful) and the oauth2 path has its own stateful machine,
but the streaming body path had none — yet it fetches via the SAME
cross-reload CachingSecretsClient, so the identical warm-cache-after-reload
drift the header machine hunts could exist here and was untested.

This drives http_connect -> requestheaders -> the streaming body replacer
against the real addon (the policy is not mocked), reloading between a wide and
a narrow scope with the cache warm, and asserts:

    the real secret lands in the outgoing BODY iff the request is authorized
    for that secret, and never appears in the audit stream.

The oracle (:func:`_authorized`) is an independent restatement of the policy
(no matcher import), so a regression that drifts the addon and the matcher
together still fails here.

Outcome: this PASSES on current code — _collect_candidates re-checks binding
scope per request before attaching the replacer, so a tightened scope denies
even with the value cached. Kept as the durable regression guard that closes
the body-path no-leak coverage gap.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule
from mitmproxy.test import tflow

from kow.addon import AgentVaultProxyAddon
from kow.audit import AuditWriter
from kow.backends import FetchContext
from kow.caching import CachingSecretsClient
from kow.config import load_config
from kow.secret import Secret

REAL = "tok-REAL-DO-NOT-LEAK-0xDEADBEEF"
PLACEHOLDER = "tok_PLACEHOLDER_01HXY1234567890ABC"  # 35 chars (matches body tests)


def _yaml(bindings: str, audit: Path) -> str:
    return f"""
version: 1
secrets:
  WEBHOOK_TOKEN:
    placeholder: "{PLACEHOLDER}"
    inject:
      type: body
      format: "{{WEBHOOK_TOKEN}}"
    bindings:
{bindings}
unmatched_destination_policy: deny
audit:
  path: {audit}
  fail_on_unwritable: true
"""


# Two scope variants for the SAME secret+host. Reloading between them with the
# cache warm is the stateful drift we hunt on the body path.
_BINDINGS = {
    "wide": '      - host: "hooks.example.com"\n',
    "narrow": (
        '      - host: "hooks.example.com"\n        methods: ["POST"]\n        paths: ["/v1/**"]\n'
    ),
}

HOSTS = ["hooks.example.com", "evil.example.com"]  # bound / unbound
METHODS = ["GET", "POST"]
PATHS = ["/v1/hook", "/v1/a/b", "/other"]


def _authorized(variant: str, host: str, method: str, path: str) -> bool:
    """Independent oracle — plain Python, no matcher import."""
    if host != "hooks.example.com":
        return False
    if variant == "wide":
        return True
    return method == "POST" and path.startswith("/v1/")


class _FakeBackend:
    def fetch(self, name: str, ctx: FetchContext | None = None) -> Secret:
        return Secret(REAL)


def _stream_through(replacer: Any, chunks: list[bytes]) -> bytes:
    out = bytearray()
    for chunk in chunks:
        out.extend(replacer(chunk))
    out.extend(replacer(b""))  # end-of-stream flush
    return bytes(out)


class BodyNoLeakMachine(RuleBasedStateMachine):
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
        # Reassign config (cache deliberately untouched) — a live bindings
        # reload while secrets stay cached.
        self.addon.config = self._configs[variant]
        self.variant = variant

    @rule(
        host=st.sampled_from(HOSTS),
        method=st.sampled_from(METHODS),
        path=st.sampled_from(PATHS),
    )
    def request(self, host: str, method: str, path: str) -> None:
        flow: Any = tflow.tflow()
        flow.request.host = host
        flow.request.port = 443
        flow.request.scheme = "https"
        flow.request.method = method
        flow.request.path = path

        self.addon.http_connect(flow)
        if flow.response is None:  # destination allowed; run the inject path
            self.addon.requestheaders(flow)

        body_in = f'{{"token":"{PLACEHOLDER}"}}'.encode()
        if callable(flow.request.stream):
            body_out = _stream_through(flow.request.stream, [body_in])
        else:
            # No replacer attached (unbound host, or scope-rejected) — the
            # body is forwarded unchanged.
            body_out = body_in
        injected = REAL.encode() in body_out
        expected = _authorized(self.variant, host, method, path)
        assert injected == expected, (
            f"body leak/deny drift: variant={self.variant} {method} {host}{path} "
            f"injected={injected} expected={expected}"
        )

    @invariant()
    def secret_never_in_audit(self) -> None:
        if self._audit.exists():
            assert REAL not in self._audit.read_text()

    def teardown(self) -> None:
        self._dir.cleanup()


TestBodyNoLeak = BodyNoLeakMachine.TestCase
