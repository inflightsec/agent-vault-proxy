"""Stateful no-leak invariant for the oauth2_refresh path.

Mirrors ``test_addon_noleak_stateful.py`` (Hypothesis
``RuleBasedStateMachine`` + independent oracle) but exercises the
oauth2_refresh injector — its own derived-token cache, write-back path,
and rotation chain on top of the shared pipeline. Invariants that must
hold across ANY interleaving of requests + reloads + rotations:

1. Access-token, refresh-token (old + new), and client-secret bytes
   never appear in the audit stream.
2. Injected access token MATCHES the most-recent value the upstream
   returned for this binding (cache + write-back stay consistent under
   rotation; mismatch = stale cached access token would be served).

The oracle (``_authorized``) is plain Python — does NOT import the
policy — so a regression that drifts the addon and policy TOGETHER
still fails here."""

from __future__ import annotations

import json
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from hypothesis import settings
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, rule
from hypothesis.strategies import sampled_from

from agent_vault_proxy.addon import AgentVaultProxyAddon
from tests import _oauth_helpers as oh
from tests._oauth_helpers import PLACEHOLDER, FakeBackend, FakeResp

INITIAL_REFRESH = "rtok-INITIAL-DO-NOT-LEAK"
INITIAL_CLIENT_SECRET = "csec-INITIAL-DO-NOT-LEAK"
INITIAL_CLIENT_ID = "cid-INITIAL"  # client_id can be public; not asserted absent


@pytest.fixture(autouse=True)
def stub_ssrf_dns_public(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    oh.apply_public_ssrf_stub(monkeypatch)
    yield


def _yaml_for_scope(scope: str, audit: Path, write_back: bool = True) -> str:
    """``wide``: GET+POST on /**. ``narrow``: POST on /v1/** only."""
    if scope == "wide":
        binding = '      - host: "api.example.com"\n        methods: ["GET", "POST"]\n'
    else:
        binding = (
            '      - host: "api.example.com"\n'
            '        methods: ["POST"]\n'
            '        paths: ["/v1/**"]\n'
        )
    wb = "true" if write_back else "false"
    return f"""
version: 1
binding_source: file
secrets:
  ACME_OAUTH:
    placeholder: "{PLACEHOLDER}"
    inject:
      type: oauth2_refresh
      token_url: https://oauth2-noleak.example.com/token
      client_auth_method: body_post
      client_id_secret: ACME_CLIENT_ID
      client_secret_secret: ACME_CLIENT_SECRET
      refresh_token_secret: ACME_REFRESH_TOKEN
      refresh_token_write_back: {wb}
    bindings:
{binding}
audit:
  path: {audit}
  fail_on_unwritable: true
cache:
  ttl_seconds: 300
  jitter_seconds: 0
  max_entries: 100
unmatched_destination_policy: deny
"""


# Probe surface used by the request rule.
HOSTS = ["api.example.com", "unbound.example.com"]
METHODS = ["GET", "POST"]
PATHS = ["/v1/chat", "/other"]


def _authorized(scope: str, host: str, method: str, path: str) -> bool:
    """Independent oracle — plain Python, no policy import."""
    if host != "api.example.com":
        return False
    if scope == "wide":
        return method in ("GET", "POST")
    return method == "POST" and path.startswith("/v1/")


class OAuth2NoLeakMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self._dir = tempfile.TemporaryDirectory()
        root = Path(self._dir.name)
        self._audit_path = root / "audit.jsonl"
        self._cfg_wide = root / "wide.yaml"
        self._cfg_narrow = root / "narrow.yaml"
        self._cfg_wide.write_text(_yaml_for_scope("wide", self._audit_path))
        self._cfg_narrow.write_text(_yaml_for_scope("narrow", self._audit_path))

        self._backend = FakeBackend(
            {
                "ACME_CLIENT_ID": INITIAL_CLIENT_ID,
                "ACME_CLIENT_SECRET": INITIAL_CLIENT_SECRET,
                "ACME_REFRESH_TOKEN": INITIAL_REFRESH,
            }
        )

        self.addon = AgentVaultProxyAddon()
        self.addon.configure_from_path(self._cfg_wide, backend_override=self._backend)
        self.scope = "wide"
        self._next_id = 1
        self._next_responses: list[bytes] = []  # queue of JSON bodies for the next exchanges
        self._expected_access_token: str | None = None  # oracle: latest exchanged access token
        self._secret_bytes: set[str] = {INITIAL_REFRESH, INITIAL_CLIENT_SECRET}

    @initialize()
    def _start(self) -> None:
        if self._audit_path.exists():
            self._audit_path.unlink()

    @rule()
    def rotate(self) -> None:
        """Stage a rotation response: next exchange returns at-N + rtok-N."""
        n = self._next_id
        self._next_id += 1
        new_access = f"at-{n}-DO-NOT-LEAK"
        new_refresh = f"rtok-{n}-DO-NOT-LEAK"
        self._secret_bytes.add(new_refresh)
        self._secret_bytes.add(new_access)  # access tokens are also sensitive
        body = json.dumps(
            {"access_token": new_access, "refresh_token": new_refresh, "expires_in": 3600}
        ).encode()
        self._next_responses.append(body)

    @rule(scope=sampled_from(["wide", "narrow"]))
    def reload(self, scope: str) -> None:
        """Rebuild config + flush derived-token cache (slice-6 invariant)."""
        cfg = self._cfg_wide if scope == "wide" else self._cfg_narrow
        self.addon.configure_from_path(cfg, backend_override=self._backend)
        self.scope = scope
        self._expected_access_token = None  # cache flush invalidates the oracle

    @rule(
        host=sampled_from(HOSTS),
        method=sampled_from(METHODS),
        path=sampled_from(PATHS),
    )
    def request(self, host: str, method: str, path: str) -> None:
        """Drive one agent request through the addon."""
        flow = oh.make_request(
            host,
            {"Authorization": f"Bearer {PLACEHOLDER}"},
            method=method,
            path=path,
        )

        will_exchange = (
            _authorized(self.scope, host, method, path) and self._expected_access_token is None
        )

        def fake_urlopen(req: Any, timeout: float | None = None) -> FakeResp:
            if self._next_responses:
                body = self._next_responses.pop(0)
            else:
                # default: non-rotating 200 echoing the current vault refresh token
                current_rt = self._backend.values["ACME_REFRESH_TOKEN"]
                body = json.dumps(
                    {
                        "access_token": f"at-noop-{self._next_id}",
                        "refresh_token": current_rt,
                        "expires_in": 3600,
                    }
                ).encode()
            return FakeResp(body, geturl_value="https://oauth2-noleak.example.com/token")

        with patch(
            "agent_vault_proxy.injectors.oauth2_refresh._transport_open", side_effect=fake_urlopen
        ):
            self.addon.http_connect(flow)
            if flow.response is None:
                self.addon.requestheaders(flow)

        injected = flow.request.headers.get("Authorization", "")
        expected_authorized = _authorized(self.scope, host, method, path)

        if not expected_authorized:
            # unauthorized → placeholder forwarded verbatim, never injected
            assert injected.startswith("Bearer ") and "PLACEHOLDER" in injected, (
                f"unauthorized request had injected token: scope={self.scope} "
                f"{method} {host}{path} headers={dict(flow.request.headers)}"
            )
        else:
            assert "PLACEHOLDER" not in injected, (
                f"authorized request still carries placeholder: scope={self.scope} "
                f"{method} {host}{path} injected={injected}"
            )
            if will_exchange:
                # oracle: on cache miss, the injected bytes are the new cached access token
                self._expected_access_token = injected.split(" ", 1)[1]

    @invariant()
    def no_secret_bytes_in_audit(self) -> None:
        if not self._audit_path.exists():
            return
        blob = self._audit_path.read_text()
        for sec in self._secret_bytes:
            assert sec not in blob, (
                f"secret bytes {sec!r} leaked to audit; first 200 chars: {blob[:200]!r}"
            )

    @invariant()
    def vault_holds_latest_refresh_token(self) -> None:
        # Must be either the initial value or one of the staged rotations —
        # never a malformed / empty token (slice-7 shape guard).
        rt = self._backend.values["ACME_REFRESH_TOKEN"]
        assert len(rt) >= 8, f"vault holds malformed refresh token: {rt!r}"
        assert rt in self._secret_bytes, (
            f"vault holds unknown refresh token {rt!r} — not initial and not from any rotation"
        )

    def teardown(self) -> None:
        self._dir.cleanup()


OAuth2NoLeakMachine.TestCase.settings = settings(
    max_examples=25,
    stateful_step_count=20,
    deadline=None,
)

TestOAuth2NoLeak = OAuth2NoLeakMachine.TestCase
