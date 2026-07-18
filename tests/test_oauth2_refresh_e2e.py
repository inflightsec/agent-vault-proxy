"""End-to-end OAuth2 refresh-token tests (ADR-0017 slice 9).

Drives the full addon pipeline against a real local HTTP server playing
the upstream token endpoint — production ``configure_from_path`` path,
real ``CachingSecretsClient`` TTL machinery, real ``AuditWriter`` on
disk, real ``DerivedTokenCache``, real ``decide()`` policy match.

TLS/CONNECT is NOT exercised here (mitmproxy's responsibility). The
token endpoint speaks plain HTTP via a ``urlopen`` translation shim;
the binding's ``token_url`` stays HTTPS so the config-load HTTPS
validator and the SSRF guard fire normally."""

from __future__ import annotations

import http.client
import http.server
import json
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from agent_vault_proxy.addon import AgentVaultProxyAddon
from tests import _oauth_helpers as oh
from tests._oauth_helpers import PLACEHOLDER, FakeBackend

# ---------------------------------------------------------------------------
# Mock upstream token endpoint — real HTTPServer, real network bytes
# ---------------------------------------------------------------------------


class _MockTokenEndpoint:
    # Real HTTP server scripting replies for the token endpoint. Tests
    # push (status, body) tuples onto `responses`; each POST /token
    # consumes the next one. `received` captures request bodies so tests
    # can assert what the addon sent on the wire.

    def __init__(self) -> None:
        self.responses: list[tuple[int, bytes]] = []
        self.received: list[dict[str, Any]] = []
        self._server: http.server.HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> int:
        endpoint = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("content-length", "0"))
                body = self.rfile.read(length) if length else b""
                endpoint.received.append(
                    {
                        "path": self.path,
                        "headers": dict(self.headers.items()),
                        "body": body,
                    }
                )
                if not endpoint.responses:
                    self.send_response(500)
                    self.end_headers()
                    return
                status, payload = endpoint.responses.pop(0)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_a: object) -> None:
                # Silence per-request server logs in test output.
                return

        self._server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self._server.server_port

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)


@pytest.fixture
def mock_token_endpoint() -> Iterator[_MockTokenEndpoint]:
    ep = _MockTokenEndpoint()
    ep.start()
    yield ep
    ep.stop()


@pytest.fixture(autouse=True)
def stub_ssrf_dns_public(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    oh.apply_public_ssrf_stub(monkeypatch)
    yield


# urlopen translator: rewrite the binding's HTTPS token_url to the local
# HTTP server so we exercise the real urllib code path against a real
# socket without standing up TLS in tests.


def _urlopen_to_local(port: int):
    def fake_urlopen(req: Any, timeout: float | None = None) -> Any:
        body = req.data or b""
        headers = dict(req.header_items())
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout or 10)
        conn.request("POST", "/token", body=body, headers=headers)
        raw = conn.getresponse()
        payload = raw.read()
        conn.close()
        status = raw.status
        if status >= 400:
            from urllib.error import HTTPError

            raise HTTPError(
                url=req.full_url,
                code=status,
                msg=raw.reason,
                hdrs=raw.headers,  # type: ignore[arg-type]
                fp=__import__("io").BytesIO(payload),
            )

        class _Resp:
            status = raw.status

            def read(self) -> bytes:
                return payload

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *_a: object) -> None:
                return None

        return _Resp()

    return fake_urlopen


# ---------------------------------------------------------------------------
# Fixture builder
# ---------------------------------------------------------------------------


@pytest.fixture
def addon_factory(tmp_path: Path):
    """Returns a factory that wires up a real addon via configure_from_path."""

    def _build(
        backend: object | None = None,
        write_back: bool = True,
    ) -> tuple[AgentVaultProxyAddon, Path]:
        audit_path = tmp_path / "audit.jsonl"
        cfg_path = tmp_path / "bindings.yaml"
        cfg_path.write_text(
            oh.oauth_yaml(
                audit_path,
                token_url="https://oauth2-test.example.com/token",
                write_back=write_back,
                methods="[GET, POST]",
                full=True,
            )
        )
        addon = AgentVaultProxyAddon()
        backend = backend or FakeBackend(
            {
                "GOOGLE_OAUTH_CLIENT_ID": "real-client-id-NEVER-LEAK",
                "GOOGLE_OAUTH_CLIENT_SECRET": "real-client-secret-NEVER-LEAK",
                "GOOGLE_OAUTH_REFRESH_TOKEN": "real-refresh-token-NEVER-LEAK",
            }
        )
        addon.configure_from_path(cfg_path, backend_override=backend)
        return addon, audit_path

    return _build


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# Silas finding #8: substring "secret bytes not in blob" is necessary but
# not sufficient — a future audit field that copied the refresh-token
# under a new key (base64, hashed, length-prefixed, unicode-escaped)
# would defeat substring search. This allowlist forces any new field
# through code review.
_ALLOWED_AUDIT_FIELDS: set[str] = {
    "v",
    "ts",
    "type",
    "request_id",
    "binding_name",
    "token_url_host",
    "outcome",
    "cache_ttl_effective_seconds",
    "used_default_expiry",
    "error_description",
    "refresh_token_secret",
    "error_type",
    "decision",
    "reason",
    "secret_name",
    "destination",
    "binding_source",
}


def _assert_audit_field_allowlist(events: list[dict[str, Any]]) -> None:
    for event in events:
        extra = set(event.keys()) - _ALLOWED_AUDIT_FIELDS
        assert not extra, (
            f"unexpected audit field(s) {extra} in event of type "
            f"{event.get('type')!r}: a new field may carry secret material; "
            "extend _ALLOWED_AUDIT_FIELDS only after reviewing"
        )


def _make_flow(headers: dict[str, str]) -> Any:
    return oh.make_request("www.googleapis.com", headers)


# ===========================================================================
# End-to-end scenarios
# ===========================================================================


def test_e2e_happy_path_plaintext_transport(
    addon_factory: Any, mock_token_endpoint: _MockTokenEndpoint
) -> None:
    """Agent request → real backend fetch → real urllib call to mock
    token endpoint → access token rendered into header → audit chain
    written to disk. Everything above the TLS layer (see module
    docstring for the what-this-covers / what-it-doesn't split)."""
    addon, audit_path = addon_factory()
    mock_token_endpoint.responses.append((200, oh.ok_body(access_token="at-FRESH-E2E")))

    flow = _make_flow({"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
        side_effect=_urlopen_to_local(mock_token_endpoint._server.server_port),
    ):
        addon.requestheaders(flow)

    # Header rewritten.
    assert flow.request.headers["Authorization"] == "Bearer at-FRESH-E2E"
    # Real upstream actually saw the form-encoded refresh-token grant body.
    assert len(mock_token_endpoint.received) == 1
    posted = mock_token_endpoint.received[0]["body"].decode()
    assert "grant_type=refresh_token" in posted
    assert "refresh_token=real-refresh-token-NEVER-LEAK" in posted
    assert "client_id=real-client-id-NEVER-LEAK" in posted
    # Audit chain on disk: token_exchange then inject_decision, allowed.
    events = oh.read_audit(audit_path)
    te = next(e for e in events if e["type"] == "token_exchange")
    deny_or_allow = next(e for e in events if e["type"] == "inject_decision")
    assert te["outcome"] == "success"
    assert te["binding_name"] == "GOOGLE_OAUTH"
    assert te["token_url_host"] == "oauth2-test.example.com"
    assert deny_or_allow["decision"] == "allowed"
    # No secret bytes in the audit log (substring) AND no unexpected
    # fields (allowlist — Silas finding #8 mitigation).
    blob = audit_path.read_text()
    assert "real-client-id-NEVER-LEAK" not in blob
    assert "real-client-secret-NEVER-LEAK" not in blob
    assert "real-refresh-token-NEVER-LEAK" not in blob
    assert "at-FRESH-E2E" not in blob
    _assert_audit_field_allowlist(events)


def test_e2e_cache_hit_skips_second_exchange(
    addon_factory: Any, mock_token_endpoint: _MockTokenEndpoint
) -> None:
    """Two back-to-back requests on the same binding inside the TTL window:
    only ONE upstream call. Verifies the derived-token cache plus the
    real CachingSecretsClient cooperate."""
    addon, audit_path = addon_factory()
    mock_token_endpoint.responses.append((200, oh.ok_body(access_token="at-CACHED")))

    port = mock_token_endpoint._server.server_port
    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
        side_effect=_urlopen_to_local(port),
    ):
        for _ in range(2):
            flow = _make_flow({"Authorization": f"Bearer {PLACEHOLDER}"})
            addon.http_connect(flow)
            addon.requestheaders(flow)
            assert flow.request.headers["Authorization"] == "Bearer at-CACHED"

    # ONE upstream POST despite TWO agent requests.
    assert len(mock_token_endpoint.received) == 1
    events = oh.read_audit(audit_path)
    assert sum(1 for e in events if e["type"] == "token_exchange") == 1
    assert sum(1 for e in events if e["type"] == "inject_decision") == 2


def test_e2e_rotation_persists_to_vault(
    addon_factory: Any, mock_token_endpoint: _MockTokenEndpoint
) -> None:
    """The upstream rotates the refresh token. The slice-7 write-back
    path persists the new value into the in-memory backend; the cache
    flushes so a re-read returns the new value."""
    backend = FakeBackend(
        {
            "GOOGLE_OAUTH_CLIENT_ID": "cid",
            "GOOGLE_OAUTH_CLIENT_SECRET": "csec",
            "GOOGLE_OAUTH_REFRESH_TOKEN": "rtok-ORIGINAL",
        }
    )
    addon, audit_path = addon_factory(backend=backend)
    mock_token_endpoint.responses.append(
        (200, oh.rotation_body(access_token="at-R1", refresh_token="rtok-ROTATED-1"))
    )

    flow = _make_flow({"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    port = mock_token_endpoint._server.server_port
    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
        side_effect=_urlopen_to_local(port),
    ):
        addon.requestheaders(flow)

    assert flow.request.headers["Authorization"] == "Bearer at-R1"
    # Vault now holds the rotated refresh token.
    assert backend.values["GOOGLE_OAUTH_REFRESH_TOKEN"] == "rtok-ROTATED-1"
    assert backend.update_count == 1
    # Audit shape: token_exchange:success → refresh_token_rotated:pending
    # → refresh_token_rotated:success → inject_decision:allowed (the
    # pending record is fsynced BEFORE the vault PUT — hardening series).
    events = oh.read_audit(audit_path)
    interesting = [
        e
        for e in events
        if e["type"] in ("token_exchange", "refresh_token_rotated", "inject_decision")
    ]
    types = [e["type"] for e in interesting]
    assert types == [
        "token_exchange",
        "refresh_token_rotated",
        "refresh_token_rotated",
        "inject_decision",
    ]
    rot = [e for e in events if e["type"] == "refresh_token_rotated"]
    assert [e["outcome"] for e in rot] == ["pending", "success"]
    # Rotated bytes NEVER appear in the audit (substring + allowlist).
    blob = audit_path.read_text()
    assert "rtok-ORIGINAL" not in blob
    assert "rtok-ROTATED-1" not in blob
    _assert_audit_field_allowlist(events)


def test_e2e_invalid_grant_denies_request(
    addon_factory: Any, mock_token_endpoint: _MockTokenEndpoint
) -> None:
    """Upstream returns 400 + ``invalid_grant`` JSON. Real urllib raises
    HTTPError; the addon categorises, audits, and denies the agent
    request with 503."""
    addon, audit_path = addon_factory()
    err_body = json.dumps({"error": "invalid_grant", "error_description": "Token revoked"}).encode()
    mock_token_endpoint.responses.append((400, err_body))

    flow = _make_flow({"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    port = mock_token_endpoint._server.server_port
    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
        side_effect=_urlopen_to_local(port),
    ):
        addon.requestheaders(flow)

    assert flow.response is not None
    assert flow.response.status_code == 503
    events = oh.read_audit(audit_path)
    te = next(e for e in events if e["type"] == "token_exchange")
    deny = next(e for e in events if e["type"] == "inject_decision")
    assert te["outcome"] == "token_endpoint_error:invalid_grant"
    assert te.get("error_description") == "Token revoked"
    assert deny["decision"] == "denied"
    assert deny["reason"].startswith("token_exchange_failed:")


def test_e2e_request_forwarded_unmodified_when_no_placeholder(
    addon_factory: Any, mock_token_endpoint: _MockTokenEndpoint
) -> None:
    """A bound host but no placeholder in any configured header MUST
    forward verbatim — no token endpoint call, no audit_decision event
    of either polarity (forward_unmodified is silent by design).

    Silas finding #5 mitigation: assert the exact set of request
    headers is unchanged (catches the regression where a future
    pre-warm-cache feature might add headers on no-placeholder paths),
    plus a small sleep to drain any deferred upstream POSTs.
    """
    import time

    addon, _audit_path = addon_factory()
    original_headers = {"Authorization": "Bearer some-other-unrelated-bearer"}
    flow = _make_flow(original_headers)
    headers_before = {k.lower(): v for k, v in flow.request.headers.items()}
    addon.http_connect(flow)
    port = mock_token_endpoint._server.server_port
    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
        side_effect=_urlopen_to_local(port),
    ):
        addon.requestheaders(flow)

    # Drain any deferred work that a future pre-warm-cache path might
    # have scheduled. Silas #5: synchronous-only assertion missed this.
    # nosemgrep: python.lang.best-practice.sleep.arbitrary-sleep
    time.sleep(0.05)

    # No upstream call (no exchange triggered — sync OR deferred).
    assert len(mock_token_endpoint.received) == 0
    # No flow response set — request continues to upstream verbatim.
    assert flow.response is None
    # Exact request header set unchanged — Authorization bytes AND
    # no new headers added.
    headers_after = {k.lower(): v for k, v in flow.request.headers.items()}
    assert headers_after == headers_before


def test_e2e_doctor_probe_against_live_server(
    mock_token_endpoint: _MockTokenEndpoint,
    tmp_path: Path,
    capsys: Any,
) -> None:
    """``avp doctor --probe-oauth --exchange`` against the live mock,
    going through the REAL production ``build_backend`` codepath (no
    patch): the YAML declares a ``static`` backend pointed at an
    inline secrets file, ``build_backend`` constructs it, the probe
    runs through it. ``refresh_token_write_back: false`` keeps the
    writable check at WARN (operator opted out) so the rollup is OK
    when the upstream rotates during the probe.

    Silas finding #6 (HIGH) mitigation: the original revision patched
    ``build_backend`` so the test would pass even if production
    backend construction were broken; this version proves the real
    construction path works end-to-end.
    """
    from agent_vault_proxy.cli.doctor import run_doctor

    # Write the static-backend secrets file with the required 0600 perms
    # (StaticSecretsBackend refuses world-readable files; the warning
    # banner-free path also wants 0700 parent + 0600 file).
    secrets_path = tmp_path / "static-secrets.yaml"
    secrets_path.write_text(
        "secrets:\n"
        '  GOOGLE_OAUTH_CLIENT_ID: "static-cid"\n'
        '  GOOGLE_OAUTH_CLIENT_SECRET: "static-csec"\n'
        '  GOOGLE_OAUTH_REFRESH_TOKEN: "static-rtok-DOCTOR"\n'
    )
    secrets_path.chmod(0o600)

    audit_path = tmp_path / "audit.jsonl"
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(
        f"""
version: 1
binding_source: file
secrets:
  GOOGLE_OAUTH:
    placeholder: "{PLACEHOLDER}"
    inject:
      type: oauth2_refresh
      token_url: https://oauth2-test.example.com/token
      client_auth_method: body_post
      client_id_secret: GOOGLE_OAUTH_CLIENT_ID
      client_secret_secret: GOOGLE_OAUTH_CLIENT_SECRET
      refresh_token_secret: GOOGLE_OAUTH_REFRESH_TOKEN
      refresh_token_write_back: false
    bindings:
      - host: www.googleapis.com
        methods: [GET, POST]
audit:
  path: {audit_path}
  fail_on_unwritable: true
backend:
  type: static
  config:
    type: static
    path: {secrets_path}
unmatched_destination_policy: deny
"""
    )

    mock_token_endpoint.responses.append(
        (200, oh.rotation_body(access_token="at-DOC", refresh_token="rtok-ROTATED-BY-PROBE"))
    )
    port = mock_token_endpoint._server.server_port
    with patch(
        "agent_vault_proxy.injectors.oauth2_refresh._transport_open",
        side_effect=_urlopen_to_local(port),
    ):
        rc = run_doctor(
            ca_cert_path="/nonexistent/cert",
            ca_key_path="/nonexistent/key",
            config_path=str(config_path),
            probe_oauth=True,
            binding_filter="GOOGLE_OAUTH",
            do_exchange=True,
        )

    captured = capsys.readouterr()
    combined = captured.out + captured.err
    # WARN on rotation, not FAIL — operator must know they need to
    # manually update the vault, but the probe itself succeeded.
    assert "WARN" in combined
    assert "rotat" in combined.lower()
    # Static secrets file untouched — doctor never writes back.
    assert "static-rtok-DOCTOR" in secrets_path.read_text()
    assert "rtok-ROTATED-BY-PROBE" not in secrets_path.read_text()
    # WARN does not flip the exit code.
    assert rc == 0


def test_e2e_build_backend_constructs_from_real_config(tmp_path: Path) -> None:
    """Companion to the doctor test (Silas #6): proves that the YAML
    fixture's ``backend:`` block actually constructs successfully
    through the production ``build_backend`` path — without any
    patches. A regression here would make ``avp doctor`` blow up in
    production while the patched doctor test stays green."""
    from agent_vault_proxy.config import build_backend, load_config

    secrets_path = tmp_path / "static-secrets.yaml"
    secrets_path.write_text('secrets:\n  X: "y"\n')
    secrets_path.chmod(0o600)
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(
        f"""
version: 1
binding_source: file
secrets:
  X:
    placeholder: "x-PLACEHOLDER-01HXY1234567890AB"
    inject:
      header: Authorization
      format: "Bearer {{X}}"
    bindings:
      - host: example.com
audit:
  path: {tmp_path / "audit.jsonl"}
  fail_on_unwritable: true
backend:
  type: static
  config:
    type: static
    path: {secrets_path}
"""
    )
    cfg = load_config(config_path)
    backend, _ = build_backend(cfg)
    assert backend is not None
    assert backend.fetch("X") == "y"
