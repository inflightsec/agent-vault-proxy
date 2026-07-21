"""ADR-0030 — oauth2_client_credentials injector end to end through the addon.

Drives a full RFC 6749 §4.4 exchange against a mocked token endpoint (the shared
`_token_transport.transport_open` seam), proving: fetch id+secret → exchange →
cache → inject the access token; the cache hit skips a second exchange; a failed
exchange fails closed with 503; and the client secret never reaches the audit log.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

import pytest

from agent_vault_proxy.addon import AgentVaultProxyAddon
from tests import _oauth_helpers as oh
from tests._oauth_helpers import FakeBackend, FakeResp, make_request

_PH = "cc-PLACEHOLDER-01HXY1234567890ABCD"
_HOST = "api.example.com"
_TRANSPORT = "agent_vault_proxy.injectors._token_transport.transport_open"


@pytest.fixture(autouse=True)
def _ssrf(monkeypatch: pytest.MonkeyPatch) -> None:
    # Make oauth.example.com resolve to a public IP so the SSRF guard passes.
    oh.apply_public_ssrf_stub(monkeypatch)


def _addon(tmp_path: Path, backend: FakeBackend) -> tuple[AgentVaultProxyAddon, Path]:
    audit = tmp_path / "audit.jsonl"
    cfg = tmp_path / "bindings.yaml"
    cfg.write_text(
        f"""
version: 1
binding_source: file
audit:
  path: {audit}
secrets:
  CC:
    placeholder: "{_PH}"
    inject:
      type: oauth2_client_credentials
      token_url: https://oauth.example.com/token
      client_id_secret: CC_CLIENT_ID
      client_secret_secret: CC_CLIENT_SECRET
      scopes: read
    bindings:
      - host: {_HOST}
"""
    )
    addon = AgentVaultProxyAddon()
    addon.configure_from_path(str(cfg), backend_override=backend)
    return addon, audit


def _cc_body(access_token: str = "at-CC", expires_in: int = 3600) -> bytes:
    return json.dumps(
        {"access_token": access_token, "token_type": "Bearer", "expires_in": expires_in}
    ).encode()


def test_cc_exchange_and_inject(tmp_path: Path) -> None:
    backend = FakeBackend({"CC_CLIENT_ID": "cid", "CC_CLIENT_SECRET": "csec-secret"})
    addon, audit_path = _addon(tmp_path, backend)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    with patch(_TRANSPORT, return_value=FakeResp(_cc_body())):
        addon.requestheaders(flow)

    assert flow.request.headers["Authorization"] == "Bearer at-CC"
    assert _PH not in flow.request.headers["Authorization"]
    log = audit_path.read_text()
    assert "csec-secret" not in log
    assert "at-CC" not in log  # the minted access token is not audited either
    events = [json.loads(ln) for ln in log.splitlines() if ln.strip()]
    assert any(e.get("type") == "token_exchange" and e.get("outcome") == "success" for e in events)
    assert any(e.get("decision") == "allowed" and e.get("secret_name") == "CC" for e in events)


def test_cc_cache_hit_skips_second_exchange(tmp_path: Path) -> None:
    backend = FakeBackend({"CC_CLIENT_ID": "cid", "CC_CLIENT_SECRET": "csec"})
    addon, _ = _addon(tmp_path, backend)
    calls = 0

    def _side(req: object, timeout: float | None = None) -> FakeResp:
        nonlocal calls
        calls += 1
        return FakeResp(_cc_body())

    with patch(_TRANSPORT, side_effect=_side):
        for _ in range(2):
            flow = make_request(_HOST, {"Authorization": _PH})
            addon.http_connect(flow)
            addon.requestheaders(flow)
            assert flow.request.headers["Authorization"] == "Bearer at-CC"
    assert calls == 1  # second request served from the token cache


def test_cc_exchange_failure_denies_503(tmp_path: Path) -> None:
    backend = FakeBackend({"CC_CLIENT_ID": "cid", "CC_CLIENT_SECRET": "csec"})
    addon, audit_path = _addon(tmp_path, backend)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    err = HTTPError(
        "https://oauth.example.com/token",
        401,
        "Unauthorized",
        {},  # type: ignore[arg-type]
        io.BytesIO(b'{"error":"invalid_client"}'),
    )
    with patch(_TRANSPORT, side_effect=err):
        addon.requestheaders(flow)

    assert flow.response is not None
    assert flow.response.status_code == 503
    assert flow.request.headers["Authorization"] == _PH  # unexchanged
    events = [json.loads(ln) for ln in audit_path.read_text().splitlines() if ln.strip()]
    assert any(
        e.get("type") == "token_exchange" and e.get("outcome") == "token_endpoint_error:401"
        for e in events
    )


def test_cc_missing_secret_denies_503(tmp_path: Path) -> None:
    backend = FakeBackend({"CC_CLIENT_ID": "cid"})  # no CC_CLIENT_SECRET
    addon, _ = _addon(tmp_path, backend)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    with patch(_TRANSPORT, return_value=FakeResp(_cc_body())):
        addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 503
    assert flow.request.headers["Authorization"] == _PH
