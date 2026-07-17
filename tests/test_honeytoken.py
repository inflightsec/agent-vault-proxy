"""Honeytoken tripwire — config flag + audit emission (ADR-0019 §5).

A honeytoken is a canary secret: the operator flags a binding `honeytoken: true`
and plants its placeholder somewhere tempting. Any use of that placeholder —
injected, denied, scope-violated, or aimed at the wrong destination — makes the
proxy emit a follow-up `honeytoken_triggered` event so a fleet collector can
alert on one unambiguous type. This file pins:

  * the `honeytoken` config flag (default false, accepts true, typos rejected)
  * the follow-up event fires AFTER the inject_decision, on allowed AND denied
    paths, and never for a non-honeytoken secret or a non-inject_decision event
  * the follow-up preserves audit minimization (no secret / header / body / query)
  * the contract version was bumped to v3
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_vault_proxy.audit import (
    AUDIT_CONTRACT_VERSION,
    EVENT_HONEYTOKEN_TRIGGERED,
    AuditWriter,
)
from agent_vault_proxy.config import SecretSpec


def _read(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


_BASE_SPEC = {
    "placeholder": "PLACEHOLDER_DECOY_000000000000",
    "inject": {"type": "header", "header": "Authorization", "format": "Bearer {DECOY}"},
    "bindings": [{"host": "trap.example.com"}],
}


# ─── config flag ────────────────────────────────────────────────────────────


def test_honeytoken_defaults_false() -> None:
    assert SecretSpec.model_validate(_BASE_SPEC).honeytoken is False


def test_honeytoken_accepts_true() -> None:
    assert SecretSpec.model_validate({**_BASE_SPEC, "honeytoken": True}).honeytoken is True


def test_honeytoken_typo_rejected_by_strict_model() -> None:
    """`extra=forbid` catches a misspelled flag — a silent no-op honeytoken
    would be worse than a load error (operator thinks the trap is armed)."""
    with pytest.raises(ValidationError):
        SecretSpec.model_validate({**_BASE_SPEC, "honeytokenn": True})


# ─── audit emission ─────────────────────────────────────────────────────────


def test_contract_version_bumped_for_honeytoken() -> None:
    """ADR-0019 added the honeytoken_triggered event → contract v3."""
    assert AUDIT_CONTRACT_VERSION >= 3


def test_triggered_event_follows_inject_decision(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    w = AuditWriter(str(p), honeytoken_names=frozenset({"DECOY"}))
    w.emit(
        {
            "type": "inject_decision",
            "request_id": "req-1",
            "decision": "allowed",
            "reason": "binding_matched",
            "secret_name": "DECOY",
            "binding_source": "file",
            "destination": {"host": "trap.example.com", "port": 443, "path_prefix": "/x"},
        }
    )
    events = _read(p)
    assert [e["type"] for e in events] == ["inject_decision", EVENT_HONEYTOKEN_TRIGGERED]
    ht = events[1]
    assert ht["request_id"] == "req-1"
    assert ht["binding_name"] == "DECOY"
    assert ht["dest_host"] == "trap.example.com"
    assert ht["underlying_reason"] == "binding_matched"
    assert ht["v"] == AUDIT_CONTRACT_VERSION


def test_not_emitted_for_non_honeytoken_secret(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    w = AuditWriter(str(p), honeytoken_names=frozenset({"DECOY"}))
    w.emit(
        {
            "type": "inject_decision",
            "request_id": "req-2",
            "decision": "allowed",
            "reason": "binding_matched",
            "secret_name": "REAL_KEY",
            "binding_source": "file",
            "destination": {"host": "api.example.com", "port": 443},
        }
    )
    assert [e["type"] for e in _read(p)] == ["inject_decision"]


def test_fires_on_denied_path_with_deny_reason(tmp_path: Path) -> None:
    """The tripwire fires on a denied decision too — the exfil-attempt shape
    (placeholder aimed at a non-bound host) carries through as
    underlying_reason."""
    p = tmp_path / "audit.jsonl"
    w = AuditWriter(str(p), honeytoken_names=frozenset({"DECOY"}))
    w.emit(
        {
            "type": "inject_decision",
            "request_id": "req-3",
            "decision": "denied",
            "reason": "destination_not_in_binding",
            "secret_name": "DECOY",
            "destination": {"host": "evil.example.com", "port": 443},
        }
    )
    ht = _read(p)[-1]
    assert ht["type"] == EVENT_HONEYTOKEN_TRIGGERED
    assert ht["underlying_reason"] == "destination_not_in_binding"
    assert ht["dest_host"] == "evil.example.com"


def test_follow_up_preserves_minimization(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    w = AuditWriter(str(p), honeytoken_names=frozenset({"DECOY"}))
    w.emit(
        {
            "type": "inject_decision",
            "request_id": "req-4",
            "decision": "allowed",
            "reason": "binding_matched",
            "secret_name": "DECOY",
            "binding_source": "file",
            "destination": {"host": "trap.example.com", "port": 443, "path_prefix": "/x"},
        }
    )
    ht = _read(p)[-1]
    blob = json.dumps(ht).lower()
    assert "authorization" not in blob
    assert "body" not in blob
    assert "query" not in blob
    # Exactly the whitelisted keys — nothing leaks through the ** spread.
    assert set(ht.keys()) == {
        "ts",
        "v",
        "type",
        "request_id",
        "binding_name",
        "dest_host",
        "underlying_reason",
    }


def test_non_inject_decision_never_triggers(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    w = AuditWriter(str(p), honeytoken_names=frozenset({"DECOY"}))
    w.emit({"type": "upstream_response", "request_id": "req-5", "status": 200})
    w.emit({"type": "proxy_restart"})
    assert [e["type"] for e in _read(p)] == ["upstream_response", "proxy_restart"]


def test_no_honeytokens_configured_is_noop(tmp_path: Path) -> None:
    """Default construction (no honeytoken names) never emits the follow-up —
    the feature is inert until an operator arms a trap."""
    p = tmp_path / "audit.jsonl"
    w = AuditWriter(str(p))
    w.emit(
        {
            "type": "inject_decision",
            "request_id": "req-6",
            "decision": "allowed",
            "reason": "binding_matched",
            "secret_name": "DECOY",
            "binding_source": "file",
            "destination": {"host": "trap.example.com", "port": 443},
        }
    )
    assert [e["type"] for e in _read(p)] == ["inject_decision"]
