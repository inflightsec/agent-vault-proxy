"""ADR-0030 — github_app injector end to end through the addon.

Mints a real RS256 App JWT (from a generated RSA key) and drives the installation
access-token exchange against a mocked GitHub endpoint (the shared
`_token_transport.transport_open` seam), proving: fetch key → mint App JWT →
exchange → cache → inject the installation token; a failed exchange and a
malformed key both fail closed with 503; the private key never reaches the audit.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from kow.addon import AgentVaultProxyAddon
from tests import _oauth_helpers as oh
from tests._oauth_helpers import FakeBackend, FakeResp, make_request

_PH = "gha-PLACEHOLDER-01HXY1234567890ABCD"
_HOST = "api.github.com"
_TRANSPORT = "kow.injectors._token_transport.transport_open"


@pytest.fixture(autouse=True)
def _ssrf(monkeypatch: pytest.MonkeyPatch) -> None:
    oh.apply_public_ssrf_stub(monkeypatch)


def _rsa_pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


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
  GHA:
    placeholder: "{_PH}"
    inject:
      type: github_app
      app_id: "123456"
      installation_id: "789"
      private_key_secret: GHA_KEY
    bindings:
      - host: {_HOST}
"""
    )
    addon = AgentVaultProxyAddon()
    addon.configure_from_path(str(cfg), backend_override=backend)
    return addon, audit


def _token_body(token: str = "ghs_installtoken", expires_at: str = "2099-01-01T00:00:00Z") -> bytes:
    return json.dumps({"token": token, "expires_at": expires_at}).encode()


def test_github_app_mints_and_injects(tmp_path: Path) -> None:
    pem = _rsa_pem()
    backend = FakeBackend({"GHA_KEY": pem})
    addon, audit_path = _addon(tmp_path, backend)
    flow = make_request(_HOST, {"Authorization": _PH}, path="/repos/o/r/issues")
    addon.http_connect(flow)
    with patch(_TRANSPORT, return_value=FakeResp(_token_body())):
        addon.requestheaders(flow)

    assert flow.request.headers["Authorization"] == "token ghs_installtoken"
    assert _PH not in flow.request.headers["Authorization"]
    log = audit_path.read_text()
    assert pem not in log
    assert "ghs_installtoken" not in log  # minted token isn't audited
    events = [json.loads(ln) for ln in log.splitlines() if ln.strip()]
    assert any(e.get("type") == "token_exchange" and e.get("outcome") == "success" for e in events)
    assert any(e.get("decision") == "allowed" and e.get("secret_name") == "GHA" for e in events)


def test_github_app_cache_hit_skips_second_exchange(tmp_path: Path) -> None:
    backend = FakeBackend({"GHA_KEY": _rsa_pem()})
    addon, _ = _addon(tmp_path, backend)
    calls = 0

    def _side(req: object, timeout: float | None = None) -> FakeResp:
        nonlocal calls
        calls += 1
        return FakeResp(_token_body())

    with patch(_TRANSPORT, side_effect=_side):
        for _ in range(2):
            flow = make_request(_HOST, {"Authorization": _PH})
            addon.http_connect(flow)
            addon.requestheaders(flow)
            assert flow.request.headers["Authorization"] == "token ghs_installtoken"
    assert calls == 1


def test_github_app_exchange_failure_denies_503(tmp_path: Path) -> None:
    backend = FakeBackend({"GHA_KEY": _rsa_pem()})
    addon, _ = _addon(tmp_path, backend)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    err = HTTPError(
        "https://api.github.com/app/installations/789/access_tokens",
        401,
        "Bad credentials",
        {},  # type: ignore[arg-type]
        io.BytesIO(b'{"message":"Bad credentials"}'),
    )
    with patch(_TRANSPORT, side_effect=err):
        addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 503
    assert flow.request.headers["Authorization"] == _PH


def test_github_app_malformed_key_denies_503(tmp_path: Path) -> None:
    # A non-PEM key fails App-JWT minting -> fail closed, no network call.
    backend = FakeBackend({"GHA_KEY": "-----NOT A PEM-----"})
    addon, _ = _addon(tmp_path, backend)
    flow = make_request(_HOST, {"Authorization": _PH})
    addon.http_connect(flow)
    with patch(_TRANSPORT, return_value=FakeResp(_token_body())) as m:
        addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 503
    assert flow.request.headers["Authorization"] == _PH
    m.assert_not_called()  # mint failed before any egress
