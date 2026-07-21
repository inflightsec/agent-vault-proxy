"""ADR-0028 — HMAC + JWT-bearer injectors end to end through the addon.

Both ride the same computed-injector `request`-hook seam SigV4 established. These
prove the wiring: a placeholder in the target header toward a bound host is
detected, deferred to the request hook, signed there, and applied — with the
signing key never in the audit log. Signer correctness is pinned separately by
public vectors in test_hmac_jwt_signers.py.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

from agent_vault_proxy.addon import AgentVaultProxyAddon
from agent_vault_proxy.injectors.hmac_signer import hmac_sign
from tests._oauth_helpers import FakeBackend, make_request

_HOST = "api.example.com"
_PH = "signed-PLACEHOLDER-01HXY1234567890"


def _addon(
    tmp_path: Path, backend: FakeBackend, inject_yaml: str
) -> tuple[AgentVaultProxyAddon, Path]:
    audit = tmp_path / "audit.jsonl"
    cfg = tmp_path / "bindings.yaml"
    cfg.write_text(
        f"""
version: 1
binding_source: file
audit:
  path: {audit}
secrets:
  SIGNED:
    placeholder: "{_PH}"
    inject:
{inject_yaml}
    bindings:
      - host: {_HOST}
"""
    )
    addon = AgentVaultProxyAddon()
    addon.configure_from_path(str(cfg), backend_override=backend)
    return addon, audit


def _run(addon: AgentVaultProxyAddon, flow: object) -> None:
    addon.http_connect(flow)  # type: ignore[arg-type]
    addon.requestheaders(flow)  # type: ignore[arg-type]
    addon.request(flow)  # type: ignore[arg-type]


# --- HMAC ------------------------------------------------------------------


def test_hmac_signs_request_end_to_end(tmp_path: Path) -> None:
    key = "super-secret-hmac-key"
    backend = FakeBackend({"HMAC_KEY": key})
    addon, audit_path = _addon(
        tmp_path,
        backend,
        """      type: hmac
      secret_key_secret: HMAC_KEY
      signing_string: "{method} {path} {body_sha256}"
      header: X-Signature""",
    )
    flow = make_request(_HOST, {"X-Signature": _PH}, method="POST", path="/v1/pay")
    flow.request.content = b'{"amount":100}'

    _run(addon, flow)

    sig = flow.request.headers["X-Signature"]
    assert _PH not in sig
    # Recompute the exact expected signature (no {timestamp} -> deterministic).
    body_hash = hashlib.sha256(b'{"amount":100}').hexdigest()
    expected = hmac_sign(
        key=key,
        signing_string=f"POST /v1/pay {body_hash}",
        algorithm="sha256",
        encoding="hex",
    )
    assert sig == expected
    assert backend.fetches == ["HMAC_KEY"]
    log = audit_path.read_text()
    assert key not in log
    events = [json.loads(ln) for ln in log.splitlines() if ln.strip()]
    assert any(e.get("decision") == "allowed" and e.get("secret_name") == "SIGNED" for e in events)


def test_hmac_timestamp_header_is_emitted(tmp_path: Path) -> None:
    backend = FakeBackend({"HMAC_KEY": "k"})
    addon, _ = _addon(
        tmp_path,
        backend,
        """      type: hmac
      secret_key_secret: HMAC_KEY
      signing_string: "{method} {timestamp}"
      header: X-Signature
      timestamp_header: X-Timestamp
      encoding: base64""",
    )
    flow = make_request(_HOST, {"X-Signature": _PH}, method="GET", path="/")
    _run(addon, flow)
    assert "X-Timestamp" in flow.request.headers
    assert flow.request.headers["X-Timestamp"].isdigit()
    # base64 signature, not the placeholder
    assert flow.request.headers["X-Signature"] != _PH


def test_hmac_missing_key_denies_503(tmp_path: Path) -> None:
    backend = FakeBackend({})  # no HMAC_KEY
    addon, _ = _addon(
        tmp_path,
        backend,
        """      type: hmac
      secret_key_secret: HMAC_KEY
      signing_string: "{method}"
      header: X-Signature""",
    )
    flow = make_request(_HOST, {"X-Signature": _PH}, method="GET", path="/")
    _run(addon, flow)
    assert flow.response is not None
    assert flow.response.status_code == 503
    assert flow.request.headers["X-Signature"] == _PH  # unsigned


# --- JWT bearer ------------------------------------------------------------


def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def test_jwt_bearer_hs256_end_to_end(tmp_path: Path) -> None:
    key = "jwt-shared-secret"
    backend = FakeBackend({"JWT_KEY": key})
    addon, audit_path = _addon(
        tmp_path,
        backend,
        """      type: jwt_bearer
      signing_key_secret: JWT_KEY
      algorithm: HS256
      issuer: avp
      subject: svc-account
      audience: https://api.example.com
      ttl_seconds: 120""",
    )
    flow = make_request(_HOST, {"Authorization": _PH}, method="GET", path="/v1/data")

    _run(addon, flow)

    auth = flow.request.headers["Authorization"]
    assert auth.startswith("Bearer ")
    assert _PH not in auth
    token = auth[len("Bearer ") :]
    header_b64, payload_b64, sig_b64 = token.split(".")

    # Header + claims are what the operator declared.
    assert json.loads(_b64url_decode(header_b64)) == {"alg": "HS256", "typ": "JWT"}
    claims = json.loads(_b64url_decode(payload_b64))
    assert claims["iss"] == "avp"
    assert claims["sub"] == "svc-account"
    assert claims["aud"] == "https://api.example.com"
    assert claims["exp"] == claims["iat"] + 120

    # The HS256 signature verifies against the vault key.
    expected_sig = hmac.new(
        key.encode(), f"{header_b64}.{payload_b64}".encode(), hashlib.sha256
    ).digest()
    assert _b64url_decode(sig_b64) == expected_sig

    assert key not in audit_path.read_text()


def test_jwt_bearer_missing_key_denies_503(tmp_path: Path) -> None:
    backend = FakeBackend({})
    addon, _ = _addon(
        tmp_path,
        backend,
        """      type: jwt_bearer
      signing_key_secret: JWT_KEY
      algorithm: HS256
      issuer: avp""",
    )
    flow = make_request(_HOST, {"Authorization": _PH}, method="GET", path="/")
    _run(addon, flow)
    assert flow.response is not None
    assert flow.response.status_code == 503
    assert flow.request.headers["Authorization"] == _PH
