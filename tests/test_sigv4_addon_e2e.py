"""ADR-0027 Slice 2 — SigV4 injector end to end through the addon.

Proves the request-path wiring: a placeholder planted in Authorization toward a
bound AWS host is detected at requestheaders, deferred to the request hook (SigV4
needs the buffered body), signed there, and applied — with the credential values
never reaching the audit log. Signature *correctness* is pinned separately by the
AWS get-vanilla vector in test_sigv4_signer.py; this pins the wiring.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_vault_proxy.addon import AgentVaultProxyAddon
from agent_vault_proxy.config import Config
from tests._oauth_helpers import FakeBackend, make_request

_PH = "aws-sig-PLACEHOLDER-01HXY1234567890"
_HOST = "s3.us-east-1.amazonaws.com"
# AWS's own public example credentials (not real secrets).
_AK = "AKIDEXAMPLE"
_SK = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"


def _write_config(tmp_path: Path, *, session_token: bool = False) -> Path:
    audit = tmp_path / "audit.jsonl"
    st = "\n      session_token_secret: AWS_SESSION_TOKEN" if session_token else ""
    cfg = tmp_path / "bindings.yaml"
    cfg.write_text(
        f"""
version: 1
binding_source: file
audit:
  path: {audit}
secrets:
  AWS_S3:
    placeholder: "{_PH}"
    inject:
      type: sigv4
      region: us-east-1
      service: s3
      access_key_id_secret: AWS_ACCESS_KEY_ID
      secret_access_key_secret: AWS_SECRET_ACCESS_KEY{st}
    bindings:
      - host: {_HOST}
"""
    )
    return cfg


def _addon(tmp_path: Path, backend: FakeBackend, **kw: bool) -> tuple[AgentVaultProxyAddon, Path]:
    cfg = _write_config(tmp_path, **kw)
    addon = AgentVaultProxyAddon()
    addon.configure_from_path(str(cfg), backend_override=backend)
    return addon, tmp_path / "audit.jsonl"


def _run(addon: AgentVaultProxyAddon, flow: object) -> None:
    addon.http_connect(flow)  # type: ignore[arg-type]
    addon.requestheaders(flow)  # type: ignore[arg-type]  # detect + stash
    addon.request(flow)  # type: ignore[arg-type]  # body buffered -> sign


def test_sigv4_signs_request_end_to_end(tmp_path: Path) -> None:
    backend = FakeBackend({"AWS_ACCESS_KEY_ID": _AK, "AWS_SECRET_ACCESS_KEY": _SK})
    addon, audit_path = _addon(tmp_path, backend)
    flow = make_request(_HOST, {"Authorization": _PH}, method="GET", path="/")

    _run(addon, flow)

    auth = flow.request.headers["Authorization"]
    # A well-formed SigV4 header replaced the placeholder.
    assert auth.startswith("AWS4-HMAC-SHA256 ")
    assert f"Credential={_AK}/" in auth
    assert "/us-east-1/s3/aws4_request" in auth
    assert "SignedHeaders=host;x-amz-date" in auth
    assert "Signature=" in auth
    assert _PH not in auth
    assert "x-amz-date" in flow.request.headers
    # The credentials were actually fetched.
    assert set(backend.fetches) == {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}

    # Audit: one allowed inject_decision; NO credential value anywhere in the log.
    log = audit_path.read_text()
    events = [json.loads(ln) for ln in log.splitlines() if ln.strip()]
    allowed = [
        e for e in events if e.get("type") == "inject_decision" and e.get("decision") == "allowed"
    ]
    assert len(allowed) == 1
    assert allowed[0]["reason"] == "binding_matched"
    assert allowed[0]["secret_name"] == "AWS_S3"
    assert _SK not in log
    assert _AK not in log  # even the access key id (non-secret) isn't logged


def test_sigv4_session_token_is_applied_and_signed(tmp_path: Path) -> None:
    backend = FakeBackend(
        {
            "AWS_ACCESS_KEY_ID": _AK,
            "AWS_SECRET_ACCESS_KEY": _SK,
            "AWS_SESSION_TOKEN": "FQoG-SESSION-TOKEN",
        }
    )
    addon, _ = _addon(tmp_path, backend, session_token=True)
    flow = make_request(_HOST, {"Authorization": _PH}, method="GET", path="/")

    _run(addon, flow)

    assert flow.request.headers["x-amz-security-token"] == "FQoG-SESSION-TOKEN"
    assert "x-amz-security-token" in flow.request.headers["Authorization"]  # in SignedHeaders


def test_sigv4_missing_credential_denies_503(tmp_path: Path) -> None:
    # Backend is missing AWS_SECRET_ACCESS_KEY -> fail closed, no signature.
    backend = FakeBackend({"AWS_ACCESS_KEY_ID": _AK})
    addon, audit_path = _addon(tmp_path, backend)
    flow = make_request(_HOST, {"Authorization": _PH}, method="GET", path="/")

    _run(addon, flow)

    assert flow.response is not None
    assert flow.response.status_code == 503
    # Placeholder was NOT replaced with a signature.
    assert flow.request.headers["Authorization"] == _PH
    events = [json.loads(ln) for ln in audit_path.read_text().splitlines() if ln.strip()]
    denied = [e for e in events if e.get("decision") == "denied"]
    assert denied and denied[-1]["reason"].startswith("secret_unavailable:")


def test_sigv4_and_body_injector_on_same_host_rejected_at_load(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    with pytest.raises(ValidationError, match="different hosts"):
        Config.model_validate(
            {
                "version": 1,
                "audit": {"path": str(audit)},
                "secrets": {
                    "AWS_S3": {
                        "placeholder": _PH,
                        "inject": {
                            "type": "sigv4",
                            "region": "us-east-1",
                            "service": "s3",
                            "access_key_id_secret": "AWS_ACCESS_KEY_ID",
                            "secret_access_key_secret": "AWS_SECRET_ACCESS_KEY",
                        },
                        "bindings": [{"host": _HOST}],
                    },
                    "BODY_SEC": {
                        "placeholder": "body_PLACEHOLDER_01HXY1234567890",
                        "inject": {"type": "body", "format": "{BODY_SEC}"},
                        "bindings": [{"host": _HOST}],
                    },
                },
            }
        )
