"""Tests for ``avp oauth login`` (ADR-0042 bootstrap).

The egress seam patched throughout is ``oauth_login._oauth_post`` (the SSRF-vetted,
pinned form POST) and, for the loopback path, ``webbrowser.open`` — a fake browser
thread drives the real ephemeral callback server so state/redirect handling is
exercised end to end.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import threading
import urllib.request
from urllib.parse import parse_qs, urlparse

import pytest

from kow.backends import (
    BackendWriteConflictError,
    SecretNotFoundError,
)
from kow.cli import oauth_login as ol
from kow.placeholders import PLACEHOLDER_PREFIX
from kow.secret import Secret

_LIVE_TOKEN = "1//refresh-token-value-abcdefghijklmnop"


class FakeBackend:
    """Minimal writable, notes-aware backend for the CLI tests."""

    def __init__(self, values: dict[str, str]) -> None:
        self._v = dict(values)
        self.written: dict[str, str] = {}

    def fetch(self, name: str, ctx: object = None) -> Secret:
        if name not in self._v:
            raise SecretNotFoundError(name)
        return Secret(self._v[name])

    def fetch_with_meta(self, name: str, ctx: object = None) -> tuple[Secret, str | None]:
        if name not in self._v:
            raise SecretNotFoundError(name)
        return Secret(self._v[name]), None

    def update(
        self,
        name: str,
        value: str,
        ctx: object = None,
        *,
        expected_current_value: str | None = None,
    ) -> None:
        if name not in self._v:
            raise SecretNotFoundError(name)
        if expected_current_value is not None and self._v[name] != expected_current_value:
            raise BackendWriteConflictError(name)
        self._v[name] = value
        self.written[name] = value


def _args(**over: object) -> argparse.Namespace:
    base = {
        "oauth_cmd": "login",
        "binding": "GOOGLE",
        "provider": "google",
        "client_id_secret": "GOOGLE_CLIENT_ID",
        "client_secret_secret": "GOOGLE_CLIENT_SECRET",  # runtime requires one (Silas H1)
        "refresh_token_secret": "GOOGLE_REFRESH",
        "scopes": "openid email",
        "resource": None,
        "authorization_endpoint": None,
        "token_endpoint": None,
        "device_authorization_endpoint": None,
        "loopback": False,
        "device": True,
        "callback_port": 0,
        "config": "/etc/kow/bindings.yaml",
        "force": False,
    }
    base.update(over)
    return argparse.Namespace(**base)


# --- PKCE / helpers ---------------------------------------------------------


def test_pkce_pair_is_valid_s256() -> None:
    verifier, challenge = ol._pkce_pair()
    assert 43 <= len(verifier) <= 128
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    assert challenge == expected.decode()
    assert "=" not in challenge  # unpadded


def test_pkce_pair_is_unique_per_call() -> None:
    assert ol._pkce_pair()[0] != ol._pkce_pair()[0]


def test_looks_live_distinguishes_placeholder_and_empty_from_real() -> None:
    assert ol._looks_live(_LIVE_TOKEN) is True
    assert ol._looks_live("") is False
    assert ol._looks_live(PLACEHOLDER_PREFIX + "abcdefghijklmnop") is False


def test_prevet_rejects_plain_http() -> None:
    with pytest.raises(ol.OAuthFlowError):
        ol._prevet("http://accounts.google.com/x")


def test_prevet_blocks_internal_host(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(_url: str) -> None:
        raise ol.SsrfBlockedError("blocked")

    monkeypatch.setattr(ol, "check_url_not_internal", _boom)
    with pytest.raises(ol.OAuthFlowError):
        ol._prevet("https://169.254.169.254/token")


def test_resolve_endpoints_prefers_explicit_over_preset() -> None:
    ns = _args(authorization_endpoint="https://example.test/auth")
    auth_ep, token_ep, device_ep = ol._resolve_endpoints(ns)
    assert auth_ep == "https://example.test/auth"  # override wins
    assert token_ep == "https://oauth2.googleapis.com/token"  # preset
    assert device_ep == "https://oauth2.googleapis.com/device/code"  # preset


# --- device grant -----------------------------------------------------------


def _device_start() -> dict[str, object]:
    return {
        "device_code": "DEV-CODE",
        "user_code": "WDJB-MJHT",
        "verification_uri": "https://www.google.com/device",
        "interval": 1,
        "expires_in": 30,
    }


def test_device_flow_pending_then_success(monkeypatch: pytest.MonkeyPatch) -> None:
    seq = [
        _device_start(),
        {"error": "authorization_pending"},
        {"refresh_token": _LIVE_TOKEN, "access_token": "at"},
    ]
    monkeypatch.setattr(ol.time, "sleep", lambda _s: None)
    monkeypatch.setattr(ol, "_oauth_post", lambda *_a, **_k: seq.pop(0))
    got = ol._device_flow(
        device_authorization_endpoint="https://oauth2.googleapis.com/device/code",
        token_endpoint="https://oauth2.googleapis.com/token",
        client_id="cid",
        client_secret=None,
        client_auth_basic=False,
        scopes="openid",
        resource=None,
    )
    assert got == _LIVE_TOKEN


def test_device_flow_slow_down_increases_interval(monkeypatch: pytest.MonkeyPatch) -> None:
    seq = [_device_start(), {"error": "slow_down"}, {"refresh_token": _LIVE_TOKEN}]
    slept: list[float] = []
    monkeypatch.setattr(ol.time, "sleep", lambda s: slept.append(s))
    monkeypatch.setattr(ol, "_oauth_post", lambda *_a, **_k: seq.pop(0))
    ol._device_flow(
        device_authorization_endpoint="https://oauth2.googleapis.com/device/code",
        token_endpoint="https://oauth2.googleapis.com/token",
        client_id="cid",
        client_secret=None,
        client_auth_basic=False,
        scopes=None,
        resource=None,
    )
    # first poll slept 1 (interval), second slept 6 (1 + 5 slow_down bump)
    assert slept == [1, 6]


def test_device_flow_access_denied_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    seq = [_device_start(), {"error": "access_denied"}]
    monkeypatch.setattr(ol.time, "sleep", lambda _s: None)
    monkeypatch.setattr(ol, "_oauth_post", lambda *_a, **_k: seq.pop(0))
    with pytest.raises(ol.OAuthFlowError, match="access_denied"):
        ol._device_flow(
            device_authorization_endpoint="https://oauth2.googleapis.com/device/code",
            token_endpoint="https://oauth2.googleapis.com/token",
            client_id="cid",
            client_secret=None,
            client_auth_basic=False,
            scopes=None,
            resource=None,
        )


def test_device_flow_rejects_non_https_verification_uri(monkeypatch: pytest.MonkeyPatch) -> None:
    bad = {
        "device_code": "d",
        "user_code": "U",
        "verification_uri": "http://phish.test/device",  # not https
    }
    monkeypatch.setattr(ol, "_oauth_post", lambda *_a, **_k: bad)
    with pytest.raises(ol.OAuthFlowError, match="not https"):
        ol._device_flow(
            device_authorization_endpoint="https://oauth2.googleapis.com/device/code",
            token_endpoint="https://oauth2.googleapis.com/token",
            client_id="cid",
            client_secret=None,
            client_auth_basic=False,
            scopes=None,
            resource=None,
        )


def test_device_error_string_is_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    seq = [_device_start(), {"error": "denied\x1b[31m\n\rinjected"}]
    monkeypatch.setattr(ol.time, "sleep", lambda _s: None)
    monkeypatch.setattr(ol, "_oauth_post", lambda *_a, **_k: seq.pop(0))
    with pytest.raises(ol.OAuthFlowError) as exc:
        ol._device_flow(
            device_authorization_endpoint="https://oauth2.googleapis.com/device/code",
            token_endpoint="https://oauth2.googleapis.com/token",
            client_id="cid",
            client_secret=None,
            client_auth_basic=False,
            scopes=None,
            resource=None,
        )
    msg = str(exc.value)
    assert "\x1b" not in msg and "\n" not in msg and "\r" not in msg


def test_device_flow_missing_fields_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ol, "_oauth_post", lambda *_a, **_k: {"user_code": "X"})
    with pytest.raises(ol.OAuthFlowError, match="missing required fields"):
        ol._device_flow(
            device_authorization_endpoint="https://oauth2.googleapis.com/device/code",
            token_endpoint="https://oauth2.googleapis.com/token",
            client_id="cid",
            client_secret=None,
            client_auth_basic=False,
            scopes=None,
            resource=None,
        )


# --- auth-code exchange -----------------------------------------------------


def test_exchange_code_no_refresh_token_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ol, "_oauth_post", lambda *_a, **_k: {"access_token": "at"})
    with pytest.raises(ol.OAuthFlowError, match="no refresh_token"):
        ol._exchange_code(
            token_endpoint="https://oauth2.googleapis.com/token",
            code="c",
            code_verifier="v",
            redirect_uri="http://127.0.0.1:5/callback",
            client_id="cid",
            client_secret=None,
            client_auth_basic=False,
            resource=None,
        )


def test_exchange_code_error_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ol, "_oauth_post", lambda *_a, **_k: {"error": "invalid_grant"})
    with pytest.raises(ol.OAuthFlowError, match="invalid_grant"):
        ol._exchange_code(
            token_endpoint="https://oauth2.googleapis.com/token",
            code="c",
            code_verifier="v",
            redirect_uri="http://127.0.0.1:5/callback",
            client_id="cid",
            client_secret=None,
            client_auth_basic=False,
            resource=None,
        )


# --- populate-guard ---------------------------------------------------------


def test_populate_writes_over_placeholder() -> None:
    be = FakeBackend({"GOOGLE_REFRESH": PLACEHOLDER_PREFIX + "sentinel00000000"})
    rc = ol._populate_secret(be, "GOOGLE_REFRESH", _LIVE_TOKEN, force=False)
    assert rc == 0
    assert be.written["GOOGLE_REFRESH"] == _LIVE_TOKEN


def test_populate_refuses_live_without_force(capsys: pytest.CaptureFixture[str]) -> None:
    be = FakeBackend({"GOOGLE_REFRESH": _LIVE_TOKEN})
    rc = ol._populate_secret(be, "GOOGLE_REFRESH", "1//new-refresh-token-abcdef", force=False)
    assert rc == 1
    assert "GOOGLE_REFRESH" not in be.written
    assert "--force" in capsys.readouterr().err


def test_populate_allows_live_with_force() -> None:
    be = FakeBackend({"GOOGLE_REFRESH": _LIVE_TOKEN})
    new = "1//new-refresh-token-abcdef"
    rc = ol._populate_secret(be, "GOOGLE_REFRESH", new, force=True)
    assert rc == 0
    assert be.written["GOOGLE_REFRESH"] == new


def test_populate_missing_secret_fails() -> None:
    be = FakeBackend({})
    rc = ol._populate_secret(be, "GOOGLE_REFRESH", _LIVE_TOKEN, force=False)
    assert rc == 1


def test_populate_write_conflict_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    be = FakeBackend({"GOOGLE_REFRESH": ""})

    def _conflict(
        _n: str, _v: str, _c: object = None, *, expected_current_value: object = None
    ) -> None:
        raise BackendWriteConflictError("changed")

    monkeypatch.setattr(be, "update", _conflict)
    rc = ol._populate_secret(be, "GOOGLE_REFRESH", _LIVE_TOKEN, force=False)
    assert rc == 1


# --- run_oauth end to end (device) ------------------------------------------


def _patch_backend(monkeypatch: pytest.MonkeyPatch, be: FakeBackend) -> None:
    from kow import config as cfg

    monkeypatch.setattr(cfg, "load_config", lambda _p: object())
    monkeypatch.setattr(cfg, "build_backend", lambda _c: (be, None))


def test_run_oauth_device_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    be = FakeBackend(
        {"GOOGLE_CLIENT_ID": "cid", "GOOGLE_CLIENT_SECRET": "sek", "GOOGLE_REFRESH": ""}
    )
    _patch_backend(monkeypatch, be)
    seq = [_device_start(), {"refresh_token": _LIVE_TOKEN}]
    monkeypatch.setattr(ol.time, "sleep", lambda _s: None)
    monkeypatch.setattr(ol, "_oauth_post", lambda *_a, **_k: seq.pop(0))
    rc = ol.run_oauth(_args())
    assert rc == 0
    assert be.written["GOOGLE_REFRESH"] == _LIVE_TOKEN


def test_run_oauth_rejects_malformed_token(monkeypatch: pytest.MonkeyPatch) -> None:
    be = FakeBackend(
        {"GOOGLE_CLIENT_ID": "cid", "GOOGLE_CLIENT_SECRET": "sek", "GOOGLE_REFRESH": ""}
    )
    _patch_backend(monkeypatch, be)
    seq = [_device_start(), {"refresh_token": "x"}]  # too short → malformed
    monkeypatch.setattr(ol.time, "sleep", lambda _s: None)
    monkeypatch.setattr(ol, "_oauth_post", lambda *_a, **_k: seq.pop(0))
    rc = ol.run_oauth(_args())
    assert rc == 1
    assert "GOOGLE_REFRESH" not in be.written


def test_run_oauth_never_prints_the_token(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    be = FakeBackend(
        {"GOOGLE_CLIENT_ID": "cid", "GOOGLE_CLIENT_SECRET": "sek", "GOOGLE_REFRESH": ""}
    )
    _patch_backend(monkeypatch, be)
    seq = [_device_start(), {"refresh_token": _LIVE_TOKEN, "access_token": "SECRET-ACCESS"}]
    monkeypatch.setattr(ol.time, "sleep", lambda _s: None)
    monkeypatch.setattr(ol, "_oauth_post", lambda *_a, **_k: seq.pop(0))
    ol.run_oauth(_args())
    out = capsys.readouterr()
    assert _LIVE_TOKEN not in out.out
    assert _LIVE_TOKEN not in out.err
    assert "SECRET-ACCESS" not in out.out
    assert "SECRET-ACCESS" not in out.err


def test_run_oauth_refuses_public_client_before_consent(monkeypatch: pytest.MonkeyPatch) -> None:
    # Silas H1: no client secret → the runtime can't consume the token, so refuse BEFORE any
    # browser/network consent is spent.
    be = FakeBackend({"GOOGLE_CLIENT_ID": "cid", "GOOGLE_REFRESH": ""})
    _patch_backend(monkeypatch, be)
    monkeypatch.setattr(ol.webbrowser, "open", lambda _u: pytest.fail("must not open browser"))
    monkeypatch.setattr(ol, "_oauth_post", lambda *_a, **_k: pytest.fail("must not reach network"))
    rc = ol.run_oauth(_args(client_secret_secret=None, device=True))
    assert rc == 1
    assert "GOOGLE_REFRESH" not in be.written


def test_run_oauth_device_without_endpoint_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    be = FakeBackend(
        {"GOOGLE_CLIENT_ID": "cid", "GOOGLE_CLIENT_SECRET": "sek", "GOOGLE_REFRESH": ""}
    )
    _patch_backend(monkeypatch, be)
    # no provider + device forced + no explicit device endpoint → clean failure
    rc = ol.run_oauth(_args(provider=None, device=True, token_endpoint="https://x.test/t"))
    assert rc == 1


# --- loopback integration (real ephemeral server, fake browser) -------------


def test_loopback_flow_success(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fake_browser(url: str) -> bool:
        q = parse_qs(urlparse(url).query)
        assert q["code_challenge_method"] == ["S256"]
        redirect = q["redirect_uri"][0]
        state = q["state"][0]

        def _hit() -> None:
            urllib.request.urlopen(f"{redirect}?code=AUTHCODE&state={state}", timeout=5).read()

        threading.Thread(target=_hit, daemon=True).start()
        return True

    monkeypatch.setattr(ol.webbrowser, "open", _fake_browser)
    monkeypatch.setattr(
        ol, "_exchange_code", lambda **_k: _LIVE_TOKEN
    )  # exchange itself covered separately
    got = ol._loopback_flow(
        authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
        token_endpoint="https://oauth2.googleapis.com/token",
        client_id="cid",
        client_secret=None,
        client_auth_basic=False,
        scopes="openid",
        resource=None,
        provider="google",
        callback_port=0,
    )
    assert got == _LIVE_TOKEN


def test_loopback_ignores_wrong_state_then_accepts_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    # A wrong-state hit must be IGNORED (not abort the flow — Silas L4); a subsequent
    # correct-state callback still completes it.
    def _browser(url: str) -> bool:
        q = parse_qs(urlparse(url).query)
        redirect, state = q["redirect_uri"][0], q["state"][0]

        def _hit() -> None:
            urllib.request.urlopen(f"{redirect}?code=BAD&state=WRONG", timeout=5).read()
            urllib.request.urlopen(f"{redirect}?code=GOOD&state={state}", timeout=5).read()

        threading.Thread(target=_hit, daemon=True).start()
        return True

    seen: dict[str, object] = {}
    monkeypatch.setattr(ol.webbrowser, "open", _browser)
    monkeypatch.setattr(ol, "_exchange_code", lambda **k: seen.update(k) or _LIVE_TOKEN)
    got = ol._loopback_flow(
        authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
        token_endpoint="https://oauth2.googleapis.com/token",
        client_id="cid",
        client_secret=None,
        client_auth_basic=False,
        scopes=None,
        resource=None,
        provider="google",
        callback_port=0,
    )
    assert got == _LIVE_TOKEN
    assert seen["code"] == "GOOD"  # the valid callback won; the wrong-state one was ignored


def test_loopback_times_out_without_callback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ol, "_LOOPBACK_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(ol.webbrowser, "open", lambda _u: True)  # browser opens; no callback fires
    monkeypatch.setattr(ol, "_exchange_code", lambda **_k: pytest.fail("must not exchange"))
    with pytest.raises(ol.OAuthFlowError, match="timed out"):
        ol._loopback_flow(
            authorization_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
            token_endpoint="https://oauth2.googleapis.com/token",
            client_id="cid",
            client_secret=None,
            client_auth_basic=False,
            scopes=None,
            resource=None,
            provider="google",
            callback_port=0,
        )


def test_loopback_vets_authorization_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    # H1/C1: the browser endpoint is SSRF/https-vetted before opening.
    monkeypatch.setattr(ol.webbrowser, "open", lambda _u: pytest.fail("must not open browser"))
    with pytest.raises(ol.OAuthFlowError):
        ol._loopback_flow(
            authorization_endpoint="http://accounts.google.com/o/oauth2/v2/auth",  # plain http
            token_endpoint="https://oauth2.googleapis.com/token",
            client_id="cid",
            client_secret=None,
            client_auth_basic=False,
            scopes=None,
            resource=None,
            provider="google",
            callback_port=0,
        )


def test_client_auth_basic_sets_header_not_body() -> None:
    params: dict[str, str] = {}
    headers = ol._client_auth(params, "cid", "sek-ret-value", basic=True)
    assert headers["Authorization"].startswith("Basic ")
    assert "client_secret" not in params  # basic → secret in header, not body


def test_client_auth_body_post_sets_body_not_header() -> None:
    params: dict[str, str] = {}
    headers = ol._client_auth(params, "cid", "sek-ret-value", basic=False)
    assert headers == {}
    assert params["client_secret"] == "sek-ret-value"


def test_device_flow_clamps_hostile_numerics(monkeypatch: pytest.MonkeyPatch) -> None:
    start = {
        "device_code": "d",
        "user_code": "U",
        "verification_uri": "https://v.test",
        "interval": "not-a-number",  # must not crash the cast
        "expires_in": 10**9,  # must be clamped, not an unbounded hammer
    }
    seq = [start, {"refresh_token": _LIVE_TOKEN}]
    slept: list[float] = []
    monkeypatch.setattr(ol.time, "sleep", lambda s: slept.append(s))
    monkeypatch.setattr(ol, "_oauth_post", lambda *_a, **_k: seq.pop(0))
    got = ol._device_flow(
        device_authorization_endpoint="https://oauth2.googleapis.com/device/code",
        token_endpoint="https://oauth2.googleapis.com/token",
        client_id="cid",
        client_secret=None,
        client_auth_basic=False,
        scopes=None,
        resource=None,
    )
    assert got == _LIVE_TOKEN
    assert slept and slept[0] == 5  # bad interval fell back to default, not a crash


def test_run_oauth_rejects_provider_with_explicit_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    be = FakeBackend(
        {"GOOGLE_CLIENT_ID": "cid", "GOOGLE_CLIENT_SECRET": "sek", "GOOGLE_REFRESH": ""}
    )
    _patch_backend(monkeypatch, be)
    rc = ol.run_oauth(_args(token_endpoint="https://evil.test/token"))  # provider=google + explicit
    assert rc == 1
    assert "GOOGLE_REFRESH" not in be.written


def test_run_oauth_rejects_out_of_range_callback_port(monkeypatch: pytest.MonkeyPatch) -> None:
    be = FakeBackend(
        {"GOOGLE_CLIENT_ID": "cid", "GOOGLE_CLIENT_SECRET": "sek", "GOOGLE_REFRESH": ""}
    )
    _patch_backend(monkeypatch, be)
    rc = ol.run_oauth(_args(callback_port=99999))
    assert rc == 1


# --- headless detection -----------------------------------------------------


# --- SMOKE: whole loopback OAuth flow end to end -----------------------------
# Run just this one in isolation with:  pytest tests/cli/test_oauth_login.py -k smoke
# Hermetic: real `run_oauth` dispatch, real ephemeral 127.0.0.1 callback server, real
# PKCE/state, real `_oauth_post` request-build + JSON parse, real vault-write dispatch.
# Only the socket egress (`_transport_open`), the SSRF DNS lookup, the browser, and the
# backend are stubbed — nothing in the credential path is bypassed.


class _FakeResp:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *_a: object) -> bool:
        return False


def test_oauth_login_smoke_end_to_end(monkeypatch: pytest.MonkeyPatch) -> None:
    be = FakeBackend(
        {"GOOGLE_CLIENT_ID": "cid", "GOOGLE_CLIENT_SECRET": "sek", "GOOGLE_REFRESH": ""}
    )
    _patch_backend(monkeypatch, be)
    # No DNS in a hermetic run — the SSRF prevet's getaddrinfo would fail closed; the guard
    # itself is unit-tested separately (test_prevet_*).
    monkeypatch.setattr(ol, "check_url_not_internal", lambda _u: None)
    token_response = (
        b'{"token_type":"Bearer","access_token":"AT-do-not-log",'
        b'"refresh_token":"' + _LIVE_TOKEN.encode() + b'"}'
    )
    monkeypatch.setattr(ol, "_transport_open", lambda _req, timeout: _FakeResp(token_response))

    def _browser(url: str) -> bool:
        q = parse_qs(urlparse(url).query)
        assert q["code_challenge_method"] == ["S256"]  # PKCE actually sent
        redirect, state = q["redirect_uri"][0], q["state"][0]

        def _hit() -> None:
            urllib.request.urlopen(f"{redirect}?code=SMOKE&state={state}", timeout=5).read()

        threading.Thread(target=_hit, daemon=True).start()
        return True

    monkeypatch.setattr(ol.webbrowser, "open", _browser)

    import contextlib
    import io

    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = ol.run_oauth(_args(device=False, loopback=True))

    assert rc == 0
    assert be.written["GOOGLE_REFRESH"] == _LIVE_TOKEN  # token reached the vault
    combined = out.getvalue() + err.getvalue()
    assert _LIVE_TOKEN not in combined and "AT-do-not-log" not in combined  # nothing leaked


def test_is_headless_true_under_ssh(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_CONNECTION", "1.2.3.4 5 6.7.8.9 22")
    assert ol._is_headless() is True


def test_is_headless_true_on_linux_without_display(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    monkeypatch.delenv("SSH_TTY", raising=False)
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(ol.sys, "platform", "linux")
    assert ol._is_headless() is True
