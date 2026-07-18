"""End-to-end tests for the oauth2_refresh resolution step inside the
addon (ADR-0017 slice 6).

The tests drive ``AgentVaultProxyAddon.requestheaders`` with synthetic
mitmproxy flows, mocking the token-endpoint POST at the ``urlopen``
boundary so the runtime is hermetic. The cache, audit, dispatch
ordering, and per-outcome audit shapes are pinned together — these
are the load-bearing contracts ADR-0017 §7 / §11 commit to.
"""

from __future__ import annotations

import json
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.error import HTTPError

import pytest

from agent_vault_proxy.addon import AgentVaultProxyAddon
from agent_vault_proxy.caching import CachingSecretsClient
from tests import _oauth_helpers as oh
from tests._oauth_helpers import PLACEHOLDER, FailingBackend, FakeBackend, FakeResp


@pytest.fixture(autouse=True)
def stub_ssrf_dns(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    oh.apply_public_ssrf_stub(monkeypatch)
    yield


def _build_addon(tmp_path: Path) -> tuple[AgentVaultProxyAddon, Path]:
    addon, audit_path, _client = oh.build_oauth_addon(tmp_path)
    return addon, audit_path


def _ok_response_body() -> bytes:
    return json.dumps({"access_token": "at-FRESH", "expires_in": 3600}).encode()


# ---------------------------------------------------------------------------
# Success path — cache miss + exchange + injection + dual audit
# ---------------------------------------------------------------------------


def test_cache_miss_exchange_success_injects_and_audits(tmp_path: Path) -> None:
    addon, audit_path = _build_addon(tmp_path)
    flow = oh.make_request("www.googleapis.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
        return_value=FakeResp(_ok_response_body()),
    ):
        addon.requestheaders(flow)

    # Header rewritten with the exchanged access token.
    assert flow.request.headers["Authorization"] == "Bearer at-FRESH"
    # Both audit events present in the correct order.
    events = oh.read_audit(audit_path)
    token_exchange = [e for e in events if e["type"] == "token_exchange"]
    inject_decisions = [e for e in events if e["type"] == "inject_decision"]
    assert len(token_exchange) == 1
    assert token_exchange[0]["outcome"] == "success"
    assert token_exchange[0]["binding_name"] == "GOOGLE_OAUTH"
    assert token_exchange[0]["token_url_host"] == "oauth2.example.com"
    assert len(inject_decisions) == 1
    assert inject_decisions[0]["decision"] == "allowed"
    assert inject_decisions[0]["secret_name"] == "GOOGLE_OAUTH"
    # Ordering: token_exchange fires BEFORE the inject_decision.
    te_idx = events.index(token_exchange[0])
    id_idx = events.index(inject_decisions[0])
    assert te_idx < id_idx


def test_token_exchange_event_carries_expected_metadata(tmp_path: Path) -> None:
    addon, audit_path = _build_addon(tmp_path)
    flow = oh.make_request("www.googleapis.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
        return_value=FakeResp(_ok_response_body()),
    ):
        addon.requestheaders(flow)
    events = oh.read_audit(audit_path)
    te = next(e for e in events if e["type"] == "token_exchange")
    assert te["used_default_expiry"] is False
    # Effective TTL is the upstream expires_in minus the spec's safety
    # margin (60 s default), give or take wall-clock jitter from the
    # test machine. Pin to within ±5 s of expected.
    assert te["cache_ttl_effective_seconds"] >= 3600 - 60 - 5
    assert te["cache_ttl_effective_seconds"] <= 3600 - 60 + 5
    # No secret material in the event.
    serialised = json.dumps(te)
    assert "rtok-real" not in serialised
    assert "csec-real" not in serialised
    assert "at-FRESH" not in serialised


# ---------------------------------------------------------------------------
# Cache hit path — no exchange call, no token_exchange audit
# ---------------------------------------------------------------------------


def test_cache_hit_skips_exchange_and_token_exchange_audit(tmp_path: Path) -> None:
    """Two requests in a row: the first triggers exchange + caches;
    the second hits the cache and MUST NOT invoke urlopen again. The
    second request gets only an ``inject_decision`` audit — no second
    ``token_exchange`` event."""
    addon, audit_path = _build_addon(tmp_path)
    call_count = 0

    def side_effect(req: Any, timeout: float | None = None) -> FakeResp:
        nonlocal call_count
        call_count += 1
        return FakeResp(_ok_response_body())

    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open", side_effect=side_effect
    ):
        for _ in range(2):
            flow = oh.make_request("www.googleapis.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
            addon.http_connect(flow)
            addon.requestheaders(flow)
            assert flow.request.headers["Authorization"] == "Bearer at-FRESH"

    assert call_count == 1
    events = oh.read_audit(audit_path)
    assert sum(1 for e in events if e["type"] == "token_exchange") == 1
    assert sum(1 for e in events if e["type"] == "inject_decision") == 2


# ---------------------------------------------------------------------------
# Failure paths — invalid_grant, network error, SSRF rebind
# ---------------------------------------------------------------------------


def _http_err(status: int, body: bytes) -> HTTPError:
    import io

    return HTTPError(
        url="https://oauth2.example.com/token",
        code=status,
        msg=f"HTTP {status}",
        hdrs=None,  # type: ignore[arg-type]
        fp=io.BytesIO(body),
    )


def test_invalid_grant_denies_and_audits(tmp_path: Path) -> None:
    addon, audit_path = _build_addon(tmp_path)
    flow = oh.make_request("www.googleapis.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    err = _http_err(400, json.dumps({"error": "invalid_grant"}).encode())
    with patch("agent_vault_proxy.injectors.oauth2_refresh._transport_open", side_effect=err):
        addon.requestheaders(flow)

    assert flow.response is not None
    assert flow.response.status_code == 503
    events = oh.read_audit(audit_path)
    te = next(e for e in events if e["type"] == "token_exchange")
    deny = next(e for e in events if e["type"] == "inject_decision")
    assert te["outcome"] == "token_endpoint_error:invalid_grant"
    assert deny["decision"] == "denied"
    assert deny["reason"] == "token_exchange_failed:token_endpoint_error:invalid_grant"


def test_network_failure_denies_and_audits(tmp_path: Path) -> None:
    addon, audit_path = _build_addon(tmp_path)
    flow = oh.make_request("www.googleapis.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    from urllib.error import URLError

    # urlopen retries once on URLError; mock sleeps.
    with (
        patch(
            "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
            side_effect=URLError("refused"),
        ),
        patch("time.sleep"),
    ):
        addon.requestheaders(flow)
    events = oh.read_audit(audit_path)
    te = next(e for e in events if e["type"] == "token_exchange")
    deny = next(e for e in events if e["type"] == "inject_decision")
    assert te["outcome"] == "token_endpoint_unreachable"
    assert deny["reason"] == "token_exchange_failed:token_endpoint_unreachable"


def test_ssrf_rebound_url_blocks_before_urlopen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Override the autouse SSRF DNS stub: token URL host now resolves
    to a private IP at request time. The exchange MUST short-circuit
    to ``ssrf_blocked`` and NEVER call urlopen."""
    # Build the addon while DNS is still public (so config-load passes).
    addon, audit_path = _build_addon(tmp_path)
    # Now flip the resolver: same hostname now points loopback.
    monkeypatch.setattr(
        "agent_vault_proxy._ssrf_guard.socket.getaddrinfo",
        lambda *a, **kw: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 0)),
        ],
    )
    flow = oh.make_request("www.googleapis.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    urlopen_called: list[bool] = []
    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
        side_effect=lambda *a, **kw: urlopen_called.append(True),
    ):
        addon.requestheaders(flow)
    assert urlopen_called == []  # request-time guard short-circuited
    events = oh.read_audit(audit_path)
    te = next(e for e in events if e["type"] == "token_exchange")
    assert te["outcome"] == "ssrf_blocked"


# ---------------------------------------------------------------------------
# Vault-input failures — no token_exchange audit (never reached the exchange)
# ---------------------------------------------------------------------------


def test_vault_input_unavailable_denies_before_exchange(tmp_path: Path) -> None:
    """If the BWS fetch for one of the three input secrets fails, AVP
    never gets to the token-exchange step. The audit must NOT contain
    a ``token_exchange`` event — only the ``inject_decision: denied``
    with the standard ``secret_unavailable:`` reason."""
    from agent_vault_proxy.backends import BackendUnavailableError

    addon, audit_path = _build_addon(tmp_path)
    addon.client = CachingSecretsClient(
        FailingBackend(BackendUnavailableError("down for inputs")),
        ttl_seconds=300,
        jitter_seconds=0,
        max_entries=100,
    )
    flow = oh.make_request("www.googleapis.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    urlopen_called: list[bool] = []
    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
        side_effect=lambda *a, **kw: urlopen_called.append(True),
    ):
        addon.requestheaders(flow)
    assert urlopen_called == []
    events = oh.read_audit(audit_path)
    assert not any(e["type"] == "token_exchange" for e in events)
    deny = next(e for e in events if e["type"] == "inject_decision")
    assert deny["decision"] == "denied"
    assert deny["reason"].startswith("secret_unavailable:")


# ---------------------------------------------------------------------------
# Reload-resets-cache (Oracle C4 follow-through)
# ---------------------------------------------------------------------------


def test_reload_resets_derived_token_cache(tmp_path: Path) -> None:
    """A config reload MUST clear the derived-token cache. Without
    this, a binding whose ``refresh_token_secret`` rotated in the
    vault would still get the old access token until ``expires_at``
    elapsed. The reload is the natural clearing point because the
    secret resolution path runs through it."""
    addon, audit_path = _build_addon(tmp_path)
    # First request seeds the cache.
    flow = oh.make_request("www.googleapis.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
        return_value=FakeResp(_ok_response_body()),
    ):
        addon.requestheaders(flow)
    assert flow.request.headers["Authorization"] == "Bearer at-FRESH"

    # Reload the same config (a no-op shape-wise, but the reload
    # itself MUST rebuild the cache instance).
    cache_before_reload = addon._token_cache
    addon.configure_from_path(
        tmp_path / "bindings.yaml",
        backend_override=FakeBackend(
            {
                "GOOGLE_OAUTH_CLIENT_ID": "cid-real",
                "GOOGLE_OAUTH_CLIENT_SECRET": "csec-real",
                "GOOGLE_OAUTH_REFRESH_TOKEN": "rtok-real",
            }
        ),
    )
    assert addon._token_cache is not cache_before_reload

    # New request must trigger a fresh exchange.
    call_count = 0

    def side_effect(req: Any, timeout: float | None = None) -> FakeResp:
        nonlocal call_count
        call_count += 1
        return FakeResp(
            json.dumps({"access_token": "at-AFTER-RELOAD", "expires_in": 3600}).encode()
        )

    flow2 = oh.make_request("www.googleapis.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow2)
    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open", side_effect=side_effect
    ):
        addon.requestheaders(flow2)
    assert call_count == 1
    assert flow2.request.headers["Authorization"] == "Bearer at-AFTER-RELOAD"
