"""The request-hook signer dispatch must fail closed, never fail open.

Two hardening properties (surfaced by an adversarial cross-model review of the
0.9.0 signing seam):

* **C2 — reload race.** ``requestheaders`` stashes an ALLOWED signing verdict on
  ``flow.metadata['avp_signing']`` and defers the actual signing to the
  ``request`` hook (sigv4/hmac hash the buffered body). If a config reload nulls
  the runtime state between the two hooks, the body hook must **deny (503)**, not
  forward the placeholder-bearing request unsigned.

* **C3 — unrecognized signer.** Only sigv4/hmac/jwt stash ``avp_signing`` and
  ``policy.decide`` sets exactly one injector, so the dispatch is exhaustive
  today. But the branch must be explicit: a future body-signer added to the stash
  path but not the dispatch must be **denied**, never silently misrouted to the
  JWT resolver.

Both properties assert the 503 AND the ``deny`` audit record (reason + no secret
material) — a denial the operator can't see in the audit log is only half a
fail-closed.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_vault_proxy.addon import AgentVaultProxyAddon
from agent_vault_proxy.policy import Decision
from tests._oauth_helpers import FakeBackend, make_request

_PH = "aws-sig-PLACEHOLDER-01HXY1234567890"
_HOST = "s3.us-east-1.amazonaws.com"
_AK = "AKIDEXAMPLE"
_SK = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"


def _sigv4_addon(tmp_path: Path) -> tuple[AgentVaultProxyAddon, Path]:
    audit_path = tmp_path / "audit.jsonl"
    cfg = tmp_path / "bindings.yaml"
    cfg.write_text(
        f"""
version: 1
binding_source: file
audit:
  path: {audit_path}
secrets:
  AWS_S3:
    placeholder: "{_PH}"
    inject:
      type: sigv4
      region: us-east-1
      service: s3
      access_key_id_secret: AWS_ACCESS_KEY_ID
      secret_access_key_secret: AWS_SECRET_ACCESS_KEY
    bindings:
      - host: {_HOST}
"""
    )
    backend = FakeBackend({"AWS_ACCESS_KEY_ID": _AK, "AWS_SECRET_ACCESS_KEY": _SK})
    addon = AgentVaultProxyAddon()
    addon.configure_from_path(str(cfg), backend_override=backend)
    return addon, audit_path


def _deny_events(audit_path: Path) -> list[dict]:
    if not audit_path.exists():
        return []
    events = [json.loads(ln) for ln in audit_path.read_text().splitlines() if ln.strip()]
    return [e for e in events if e.get("type") == "deny"]


def test_request_fails_closed_when_signing_state_lost(tmp_path: Path) -> None:
    """C2: runtime state lost between stash and body hook -> 503, not unsigned forward."""
    addon, audit_path = _sigv4_addon(tmp_path)
    flow = make_request(_HOST, {"Authorization": _PH}, method="GET", path="/")
    addon.http_connect(flow)  # type: ignore[arg-type]
    addon.requestheaders(flow)  # type: ignore[arg-type]  # stashes avp_signing
    assert flow.metadata.get("avp_signing") is not None

    # Simulate a config reload that nulls the runtime client before the body hook.
    addon.client = None
    addon.request(flow)  # type: ignore[arg-type]

    assert flow.response is not None
    assert flow.response.status_code == 503
    # The request was denied, not forwarded: the header still carries the
    # (non-secret) placeholder — no real credential ever reached the wire.
    assert flow.request.headers["Authorization"] == _PH
    # And the denial is auditable (audit was still live in this race).
    denies = _deny_events(audit_path)
    assert any(e.get("reason") == "signing_state_unavailable" for e in denies)
    # No secret material in the audit record.
    assert _SK not in audit_path.read_text()


def test_request_fails_closed_on_unrecognized_signing_injector(tmp_path: Path) -> None:
    """C3: a stashed signing decision matching no known injector -> 503, not JWT."""
    addon, audit_path = _sigv4_addon(tmp_path)
    flow = make_request(_HOST, {"Authorization": _PH}, method="GET", path="/")
    addon.http_connect(flow)  # type: ignore[arg-type]

    # A Decision that reached the request hook but matches none of sigv4/hmac/jwt
    # (stand-in for a future body-signer wired into the stash path but not the
    # dispatch). All *_injector fields default to None.
    bogus = Decision(decision="allowed")
    flow.metadata["avp_signing"] = (bogus, "req-fail-closed", _HOST)
    addon.request(flow)  # type: ignore[arg-type]

    assert flow.response is not None
    assert flow.response.status_code == 503
    denies = _deny_events(audit_path)
    assert any(e.get("reason") == "unrecognized_signing_injector" for e in denies)
