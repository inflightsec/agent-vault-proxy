"""Tests for the OAuth2 refresh-token exchange (ADR-0017 slice 5).

The exchange module is the synchronous core of the resolution step
that lands in slice 6. It takes a spec + three resolved secrets,
issues one HTTPS POST to the token endpoint, parses the response per
RFC 6749 §5.1 / §5.2, and returns an :class:`ExchangeResult` whose
``outcome`` field drives the audit event vocabulary from the ADR.

Network is fully mocked at the ``urlopen`` boundary. The synchronous
``exchange`` is what every other layer composes; the async wrapper
just dispatches it through ``loop.run_in_executor``.
"""

from __future__ import annotations

import asyncio
import json
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.error import HTTPError, URLError

import pytest

from agent_vault_proxy.config import Config, Oauth2RefreshInjector
from agent_vault_proxy.injectors.oauth2_refresh import (
    ExchangeResult,
    _transport_open,
    exchange,
    exchange_async,
)
from tests import _oauth_helpers as oh
from tests._oauth_helpers import FakeResp as _FakeResponse
from tests._tls_helpers import run_loopback_tls_http_server

_FOO_PH = "foo_PLACEHOLDER_01HXY1234567890"


# ---------------------------------------------------------------------------
# Fixtures — hermetic spec + mock urlopen builder
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def stub_ssrf_dns(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """All test hostnames map to a public IP so the request-time SSRF
    check passes by default. Individual tests that exercise the SSRF
    path override this with their own monkeypatch."""
    oh.apply_public_ssrf_stub(monkeypatch)
    yield


@pytest.fixture
def spec_body_post() -> Oauth2RefreshInjector:
    """Spec via explicit URL + body_post (avoids any DNS-touching
    preset path)."""
    raw = {
        "version": 1,
        "secrets": {
            "FOO": {
                "placeholder": _FOO_PH,
                "inject": {
                    "type": "oauth2_refresh",
                    "token_url": "https://oauth2.example.com/token",
                    "client_auth_method": "body_post",
                    "client_id_secret": "C_ID",
                    "client_secret_secret": "C_SEC",
                    "refresh_token_secret": "R_TOK",
                },
                "bindings": [{"host": "api.example.com"}],
            }
        },
        "audit": {"path": "/tmp/x.jsonl"},
    }
    spec = Config.model_validate(raw).secrets["FOO"].inject
    assert isinstance(spec, Oauth2RefreshInjector)
    return spec


@pytest.fixture
def spec_basic_auth() -> Oauth2RefreshInjector:
    raw = {
        "version": 1,
        "secrets": {
            "FOO": {
                "placeholder": _FOO_PH,
                "inject": {
                    "type": "oauth2_refresh",
                    "token_url": "https://oauth2.example.com/token",
                    "client_auth_method": "basic",
                    "client_id_secret": "C_ID",
                    "client_secret_secret": "C_SEC",
                    "refresh_token_secret": "R_TOK",
                    "scopes": "openid email",
                },
                "bindings": [{"host": "api.example.com"}],
            }
        },
        "audit": {"path": "/tmp/x.jsonl"},
    }
    spec = Config.model_validate(raw).secrets["FOO"].inject
    assert isinstance(spec, Oauth2RefreshInjector)
    return spec


def _make_http_error(status: int, body: bytes) -> HTTPError:
    """Build an :class:`HTTPError` shaped like ``urlopen`` raises on
    4xx/5xx — has ``.code`` and ``.read()``."""
    import io

    return HTTPError(
        url="https://oauth2.example.com/token",
        code=status,
        msg=f"HTTP {status}",
        hdrs=None,  # type: ignore[arg-type]
        fp=io.BytesIO(body),
    )


# ---------------------------------------------------------------------------
# Successful exchange — body_post + basic auth, with and without rotation
# ---------------------------------------------------------------------------


def _capture(calls: list[Any]) -> Any:
    """Build a urlopen side-effect that records every call's Request
    and returns a 200 with a vanilla token response."""

    def side_effect(req: Any, timeout: float | None = None) -> _FakeResponse:
        calls.append((req, timeout))
        return _FakeResponse(json.dumps({"access_token": "at-A", "expires_in": 3600}).encode())

    return side_effect


def test_body_post_success(spec_body_post: Oauth2RefreshInjector) -> None:
    calls: list[Any] = []
    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open", side_effect=_capture(calls)
    ):
        result = exchange(spec_body_post, "cid", "csec", "rtok")
    assert result.outcome == "success"
    assert result.access_token == "at-A"
    assert result.expires_at is not None
    assert result.new_refresh_token is None  # not rotated
    # Body shape — must include grant_type + refresh_token + client_id + client_secret.
    req, timeout = calls[0]
    body = req.data.decode("utf-8")
    assert "grant_type=refresh_token" in body
    assert "refresh_token=rtok" in body
    assert "client_id=cid" in body
    assert "client_secret=csec" in body
    # body_post means no Authorization header.
    headers = {k.lower(): v for k, v in req.header_items()}
    assert "authorization" not in headers
    # Timeout is honoured.
    assert timeout == 10.0


def test_basic_auth_success(spec_basic_auth: Oauth2RefreshInjector) -> None:
    """Basic auth method — credentials in Authorization header, NOT in
    body. ``scopes`` is forwarded in the form body."""
    calls: list[Any] = []
    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open", side_effect=_capture(calls)
    ):
        result = exchange(spec_basic_auth, "cid", "csec", "rtok")
    assert result.outcome == "success"
    req, _ = calls[0]
    body = req.data.decode("utf-8")
    assert "grant_type=refresh_token" in body
    assert "refresh_token=rtok" in body
    # Credentials NOT in body.
    assert "client_id=" not in body
    assert "client_secret=" not in body
    # Scopes carried.
    assert "scope=openid+email" in body or "scope=openid%20email" in body
    # Basic auth header present and decodable.
    import base64

    headers = {k.lower(): v for k, v in req.header_items()}
    auth = headers["authorization"]
    assert auth.startswith("Basic ")
    creds = base64.b64decode(auth.split(" ", 1)[1]).decode("ascii")
    assert creds == "cid:csec"


def test_rotated_refresh_token_captured(spec_body_post: Oauth2RefreshInjector) -> None:
    """Upstream re-issues a new refresh token alongside the access
    token (Google with rotation enabled, MS, Auth0). The exchange
    must surface it for slice 7's write-back path. Distinct from the
    original via not-equal check, not just non-None."""

    def side_effect(req: Any, timeout: float | None = None) -> _FakeResponse:
        return _FakeResponse(
            json.dumps(
                {
                    "access_token": "at-A",
                    "expires_in": 3600,
                    "refresh_token": "rtok-NEW",
                }
            ).encode()
        )

    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open", side_effect=side_effect
    ):
        result = exchange(spec_body_post, "cid", "csec", "rtok-OLD")
    assert result.outcome == "success"
    assert result.new_refresh_token == "rtok-NEW"


def test_same_refresh_token_returned_not_rotation(
    spec_body_post: Oauth2RefreshInjector,
) -> None:
    """If the upstream echoes back the SAME refresh_token, that is
    not a rotation — write-back must skip. The exchange surfaces
    ``new_refresh_token=None`` in that case."""

    def side_effect(req: Any, timeout: float | None = None) -> _FakeResponse:
        return _FakeResponse(
            json.dumps(
                {
                    "access_token": "at-A",
                    "expires_in": 3600,
                    "refresh_token": "rtok-SAME",
                }
            ).encode()
        )

    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open", side_effect=side_effect
    ):
        result = exchange(spec_body_post, "cid", "csec", "rtok-SAME")
    assert result.outcome == "success"
    assert result.new_refresh_token is None  # echoed = no rotation


def test_expires_in_missing_uses_default_with_flag(
    spec_body_post: Oauth2RefreshInjector,
) -> None:
    """RFC 6749 §5.1 makes ``expires_in`` OPTIONAL. Some providers omit
    it. The exchange returns success with ``expires_at`` capped to the
    spec's ``cache_ttl_max_seconds`` and ``used_default_expiry=True``
    so the audit layer can flag it."""

    def side_effect(req: Any, timeout: float | None = None) -> _FakeResponse:
        return _FakeResponse(json.dumps({"access_token": "at-A"}).encode())

    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open", side_effect=side_effect
    ):
        result = exchange(spec_body_post, "cid", "csec", "rtok")
    assert result.outcome == "success"
    assert result.access_token == "at-A"
    assert result.used_default_expiry is True
    assert result.expires_at is not None


# ---------------------------------------------------------------------------
# OAuth error response shapes (RFC 6749 §5.2)
# ---------------------------------------------------------------------------


def test_invalid_grant_400_categorised(spec_body_post: Oauth2RefreshInjector) -> None:
    """The single most common 4xx outcome: refresh token is
    expired/revoked. Operators need to see this distinctly so
    ``avp doctor`` can hint at remediation."""

    err = _make_http_error(
        400,
        json.dumps({"error": "invalid_grant", "error_description": "Token expired"}).encode(),
    )
    with patch("agent_vault_proxy.injectors.oauth2_refresh._transport_open", side_effect=err):
        result = exchange(spec_body_post, "cid", "csec", "rtok")
    assert result.outcome == "token_endpoint_error:invalid_grant"
    assert result.access_token is None
    assert result.error_description == "Token expired"


def test_invalid_client_401_categorised(spec_body_post: Oauth2RefreshInjector) -> None:
    err = _make_http_error(401, json.dumps({"error": "invalid_client"}).encode())
    with patch("agent_vault_proxy.injectors.oauth2_refresh._transport_open", side_effect=err):
        result = exchange(spec_body_post, "cid", "csec", "rtok")
    assert result.outcome == "token_endpoint_error:invalid_client"


def test_arbitrary_oauth_error_code_passes_through(
    spec_body_post: Oauth2RefreshInjector,
) -> None:
    """Any RFC 6749 §5.2 error code surfaces in the outcome verbatim.
    The taxonomy isn't restricted — providers extend it."""
    err = _make_http_error(400, json.dumps({"error": "invalid_scope"}).encode())
    with patch("agent_vault_proxy.injectors.oauth2_refresh._transport_open", side_effect=err):
        result = exchange(spec_body_post, "cid", "csec", "rtok")
    assert result.outcome == "token_endpoint_error:invalid_scope"


def test_4xx_without_json_body_falls_back_to_status(
    spec_body_post: Oauth2RefreshInjector,
) -> None:
    err = _make_http_error(403, b"Forbidden")
    with patch("agent_vault_proxy.injectors.oauth2_refresh._transport_open", side_effect=err):
        result = exchange(spec_body_post, "cid", "csec", "rtok")
    assert result.outcome == "token_endpoint_status:403"


# ---------------------------------------------------------------------------
# 5xx + retry + network errors
# ---------------------------------------------------------------------------


def test_5xx_retried_once_then_success(spec_body_post: Oauth2RefreshInjector) -> None:
    """One retry on 5xx with backoff per ADR-0017 §4. Pin the count so
    a regression that retries more (DoSing the provider) or zero times
    (giving up on a transient) surfaces."""
    seq = [
        _make_http_error(502, b"Bad Gateway"),
        _FakeResponse(json.dumps({"access_token": "at-A", "expires_in": 3600}).encode()),
    ]
    call_count = 0

    def side_effect(req: Any, timeout: float | None = None) -> Any:
        nonlocal call_count
        item = seq[call_count]
        call_count += 1
        if isinstance(item, HTTPError):
            raise item
        return item

    with (
        patch(
            "agent_vault_proxy.injectors.oauth2_refresh._transport_open", side_effect=side_effect
        ),
        patch("time.sleep") as sleep_mock,
    ):
        result = exchange(spec_body_post, "cid", "csec", "rtok")
    assert result.outcome == "success"
    assert call_count == 2
    # Backoff slept once with the documented 1 s budget.
    assert sleep_mock.call_count == 1
    assert sleep_mock.call_args[0][0] == 1.0


def test_5xx_twice_does_not_retry_third(spec_body_post: Oauth2RefreshInjector) -> None:
    """Retry budget is exactly one. Two failures = give up."""
    call_count = 0

    def side_effect(req: Any, timeout: float | None = None) -> Any:
        nonlocal call_count
        call_count += 1
        raise _make_http_error(500, b"err")

    with (
        patch(
            "agent_vault_proxy.injectors.oauth2_refresh._transport_open", side_effect=side_effect
        ),
        patch("time.sleep"),
    ):
        result = exchange(spec_body_post, "cid", "csec", "rtok")
    assert call_count == 2  # one initial + one retry
    assert result.outcome == "token_endpoint_status:500"


def test_4xx_does_not_retry(spec_body_post: Oauth2RefreshInjector) -> None:
    """4xx is the credential / scope / config problem class — retry
    cannot help. Pin zero retries."""
    call_count = 0

    def side_effect(req: Any, timeout: float | None = None) -> Any:
        nonlocal call_count
        call_count += 1
        raise _make_http_error(400, json.dumps({"error": "invalid_grant"}).encode())

    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open", side_effect=side_effect
    ):
        result = exchange(spec_body_post, "cid", "csec", "rtok")
    assert call_count == 1
    assert result.outcome == "token_endpoint_error:invalid_grant"


def test_connection_refused_categorised_unreachable(
    spec_body_post: Oauth2RefreshInjector,
) -> None:
    with (
        patch(
            "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
            side_effect=URLError("connection refused"),
        ),
        patch("time.sleep"),
    ):
        result = exchange(spec_body_post, "cid", "csec", "rtok")
    assert result.outcome == "token_endpoint_unreachable"
    assert result.access_token is None


def test_timeout_categorised_unreachable(spec_body_post: Oauth2RefreshInjector) -> None:
    with (
        patch(
            "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
            side_effect=TimeoutError("timed out"),
        ),
        patch("time.sleep"),
    ):
        result = exchange(spec_body_post, "cid", "csec", "rtok")
    assert result.outcome == "token_endpoint_unreachable"


# ---------------------------------------------------------------------------
# Response-parsing edge cases
# ---------------------------------------------------------------------------


def test_non_json_response_parse_failed(spec_body_post: Oauth2RefreshInjector) -> None:
    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
        side_effect=lambda *a, **kw: _FakeResponse(b"<html>not json</html>"),
    ):
        result = exchange(spec_body_post, "cid", "csec", "rtok")
    assert result.outcome == "response_parse_failed"


def test_json_without_access_token_parse_failed(
    spec_body_post: Oauth2RefreshInjector,
) -> None:
    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
        side_effect=lambda *a, **kw: _FakeResponse(
            json.dumps({"token_type": "Bearer", "expires_in": 3600}).encode()
        ),
    ):
        result = exchange(spec_body_post, "cid", "csec", "rtok")
    assert result.outcome == "response_parse_failed"


# ---------------------------------------------------------------------------
# Request-time SSRF re-check (DNS rebinding defense)
# ---------------------------------------------------------------------------


def test_request_time_ssrf_blocks_dns_rebound_url(
    spec_body_post: Oauth2RefreshInjector,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Token URL passed config-load SSRF; at runtime, the same hostname
    now resolves to a private IP (DNS rebinding). The exchange MUST
    refuse and return ``ssrf_blocked`` without calling ``urlopen``."""

    def stub(host: str, *_a: object, **_kw: object) -> list[tuple]:
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("10.0.0.1", 0))]

    monkeypatch.setattr("agent_vault_proxy._ssrf_guard.socket.getaddrinfo", stub)
    urlopen_called: list[bool] = []
    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
        side_effect=lambda *a, **kw: urlopen_called.append(True) or _FakeResponse(b""),
    ):
        result = exchange(spec_body_post, "cid", "csec", "rtok")
    assert result.outcome == "ssrf_blocked"
    assert urlopen_called == []  # MUST short-circuit before any outbound


# ---------------------------------------------------------------------------
# Off-thread dispatch — async wrapper does not block the event loop
# ---------------------------------------------------------------------------


def test_exchange_async_uses_run_in_executor(
    spec_body_post: Oauth2RefreshInjector,
) -> None:
    """``exchange_async`` MUST dispatch through ``run_in_executor`` so
    the mitmproxy asyncio loop is not blocked by a slow token endpoint.
    Pin the dispatch path by asserting the running loop's thread id
    differs from the thread the synchronous exchange runs on."""
    import threading

    loop_thread_id: list[int] = []
    fetch_thread_id: list[int] = []

    def side_effect(req: Any, timeout: float | None = None) -> _FakeResponse:
        fetch_thread_id.append(threading.get_ident())
        return _FakeResponse(json.dumps({"access_token": "at-A", "expires_in": 3600}).encode())

    async def runner() -> ExchangeResult:
        loop_thread_id.append(threading.get_ident())
        with patch(
            "agent_vault_proxy.injectors.oauth2_refresh._transport_open", side_effect=side_effect
        ):
            return await exchange_async(spec_body_post, "cid", "csec", "rtok")

    result = asyncio.run(runner())
    assert result.outcome == "success"
    # The synchronous exchange ran on a different thread than the loop.
    assert fetch_thread_id[0] != loop_thread_id[0]


# ---------------------------------------------------------------------------
# Hardening: redirects are refused at the opener — never followed
# ---------------------------------------------------------------------------


def test_redirect_refused_never_followed(
    spec_body_post: Oauth2RefreshInjector,
) -> None:
    """The no-redirect opener surfaces ANY 3xx as ``HTTPError``;
    ``exchange`` maps it to ``token_endpoint_status:<code>`` with NO
    retry — the Location target is never contacted, public or private
    alike (ADR-0017 hardening series; replaces the former post-call
    ``geturl()`` check, which could only distrust a redirect AFTER the
    redirected host had been visited on the wire)."""
    import io

    calls: list[object] = []

    def refuse(req: object, timeout: float | None = None) -> object:
        calls.append(req)
        raise HTTPError(
            "https://token.example.com/oauth2/token",
            302,
            "Found",
            None,  # type: ignore[arg-type]
            io.BytesIO(b"<html>moved</html>"),
        )

    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
        side_effect=refuse,
    ):
        result = exchange(spec_body_post, "cid", "csec", "rtok")
    assert result.outcome == "token_endpoint_status:302"
    assert len(calls) == 1  # deterministic refusal — no retry on 3xx


def test_transport_opener_refuses_redirect_on_the_wire(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Drive the REAL opener against a live local server answering 302:
    ``_transport_open`` must raise ``HTTPError(302)`` and must NOT fetch
    the Location target — the on-the-wire proof that redirects are
    disabled at the transport, not post-checked."""
    import urllib.request
    from http.server import BaseHTTPRequestHandler

    hits = {"redirect": 0, "target": 0}

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/target":
                hits["target"] += 1
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"should never be fetched")
            else:
                hits["redirect"] += 1
                self.send_response(302)
                self.send_header("Location", "/target")
                self.end_headers()

        def log_message(self, *args: object) -> None:  # silence test noise
            return

    with run_loopback_tls_http_server(tmp_path, _Handler) as server:
        monkeypatch.setattr(
            "agent_vault_proxy.injectors._token_transport.resolve_and_vet",
            lambda url: [(socket.AF_INET, "127.0.0.1")],
        )
        monkeypatch.setattr(
            "agent_vault_proxy.injectors._token_transport._TLS_CONTEXT",
            server.client_context,
        )
        req = urllib.request.Request(f"https://pinned.test:{server.port}/start")
        with pytest.raises(HTTPError) as excinfo:
            _transport_open(req, timeout=5.0)
        assert excinfo.value.code == 302
        assert hits["redirect"] == 1
        assert hits["target"] == 0, "redirect Location was followed — opener must refuse"


def test_token_type_bearer_accepted_case_insensitive(
    spec_body_post: Oauth2RefreshInjector,
) -> None:
    """RFC 6750 §1.2 says the Bearer scheme is case-insensitive.
    Pin Bearer/bearer/BEARER/BeArEr all as success."""
    for variant in ("Bearer", "bearer", "BEARER", "BeArEr"):
        body = json.dumps(
            {"access_token": "at-A", "token_type": variant, "expires_in": 3600}
        ).encode()
        with patch(
            "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
            return_value=_FakeResponse(body),
        ):
            result = exchange(spec_body_post, "cid", "csec", "rtok")
        assert result.outcome == "success", f"variant {variant!r} should succeed"


def test_token_type_non_bearer_rejected(
    spec_body_post: Oauth2RefreshInjector,
) -> None:
    """If the upstream issues a non-Bearer token (legacy MAC, vendor
    DPoP), AVP must refuse rather than silently inject it as a Bearer
    header — the agent would either get an upstream 401 from the
    type mismatch OR (worse) the proxy would send credentials in a
    malformed scheme. Explicit ``unsupported_token_type`` outcome
    surfaces it on the audit trail."""
    for bad_type in ("MAC", "DPoP", "Basic", "PoP"):
        body = json.dumps(
            {"access_token": "at-A", "token_type": bad_type, "expires_in": 3600}
        ).encode()
        with patch(
            "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
            return_value=_FakeResponse(body),
        ):
            result = exchange(spec_body_post, "cid", "csec", "rtok")
        assert result.outcome == "unsupported_token_type", (
            f"token_type {bad_type!r} should be rejected, got {result.outcome}"
        )


def test_token_type_omitted_accepted_with_warning(
    spec_body_post: Oauth2RefreshInjector,
) -> None:
    """RFC 6749 §5.1 says token_type is REQUIRED in the response. In
    practice some providers omit it. Be lenient with a logged warning
    rather than reject — strictness would break legitimate exchanges
    against under-spec providers and add operator friction with no
    security gain (we only know how to inject Bearer anyway, so the
    assumption is implicit either way)."""
    body = json.dumps({"access_token": "at-A", "expires_in": 3600}).encode()
    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
        return_value=_FakeResponse(body),
    ):
        result = exchange(spec_body_post, "cid", "csec", "rtok")
    assert result.outcome == "success"
    assert result.access_token == "at-A"


def test_request_carries_avp_user_agent(
    spec_body_post: Oauth2RefreshInjector,
) -> None:
    """AVP identifies itself rather than shipping the default
    ``Python-urllib/3.X`` (some providers block stock urllib UA outright
    with confusing 4xx errors; identifying AVP also helps providers
    whitelist explicitly when needed)."""
    captured: list[str | None] = []

    def side_effect(req: Any, timeout: float | None = None) -> _FakeResponse:
        captured.append(req.get_header("User-agent"))
        return _FakeResponse(b'{"access_token":"at-Z","expires_in":3600}')

    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open", side_effect=side_effect
    ):
        exchange(spec_body_post, "cid", "csec", "rtok")
    assert captured == ["agent-vault-proxy/oauth2-refresh"]


def test_parse_error_sanitizes_and_caps_provider_error_description() -> None:
    """Silas M2: a hostile token endpoint could reflect posted secret material or inject ANSI
    control sequences via ``error_description``, which lands in the fsynced audit stream. It must
    be control-stripped and length-capped before it can be emitted."""
    from agent_vault_proxy.injectors.oauth2_refresh import _parse_error

    hostile = json.dumps(
        {"error": "invalid_client", "error_description": "leak\x1b[2J\n\r" + "A" * 400}
    ).encode()
    result = _parse_error(400, hostile)
    desc = result.error_description
    assert desc is not None
    assert "\x1b" not in desc and "\n" not in desc and "\r" not in desc  # control chars stripped
    assert len(desc) <= 200  # length capped
    assert result.outcome == "token_endpoint_error:invalid_client"
