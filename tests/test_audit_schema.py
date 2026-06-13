"""Audit JSON contract version + binding_source field (ADR-0011 item 6).

Adding binding_source to inject_decision is a contract-version bump
(AGENTS.md hard constraint #3). This file pins:
  * the contract version is exposed + bumped past the pre-ADR value
  * the audit log NEVER records header values, bodies, or query strings
    (the invariant that must survive the schema change)
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_vault_proxy.audit import (
    AUDIT_CONTRACT_VERSION,
    REASON_INVALID_BINDING_METADATA,
    REASON_NO_BINDING_IN_NOTES,
    AuditWriter,
)


def test_no_binding_reason_is_distinct_from_malformed() -> None:
    """ADR-0011 item 6: a NEW reason `no_binding_in_notes`, distinct from
    `invalid_binding_metadata`. The two must not collapse to one string."""
    assert REASON_NO_BINDING_IN_NOTES == "no_binding_in_notes"
    assert REASON_INVALID_BINDING_METADATA == "invalid_binding_metadata"
    assert REASON_NO_BINDING_IN_NOTES != REASON_INVALID_BINDING_METADATA


def _read(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def test_contract_version_is_at_least_2() -> None:
    """Pre-ADR contract was v1 (docs §4.2 `version: 1`). Adding
    binding_source bumps it; pin >= 2 so a downgrade is a visible failure."""
    assert AUDIT_CONTRACT_VERSION >= 2


def test_emitted_event_carries_no_secret_payload(tmp_path: Path) -> None:
    """Belt-and-suspenders: the writer itself never adds header values /
    bodies / query strings. The caller is responsible for not passing them,
    but this test pins that a representative inject_decision event stays
    minimal."""
    p = tmp_path / "audit.jsonl"
    w = AuditWriter(str(p))
    w.emit(
        {
            "type": "inject_decision",
            "request_id": "req-1",
            "decision": "allowed",
            "reason": "binding_matched",
            "secret_name": "FOO",
            "binding_source": "bws_notes",
            "destination": {"host": "api.example.com", "port": 443, "path_prefix": "/v1/x"},
        }
    )
    events = _read(p)
    assert len(events) == 1
    ev = events[0]
    blob = json.dumps(ev)
    # No raw header value / body / query string keys.
    assert "authorization" not in blob.lower()
    assert "body" not in blob.lower()
    assert "query" not in blob.lower()
    assert ev["binding_source"] == "bws_notes"


def test_writer_stamps_contract_version_on_every_record(tmp_path: Path) -> None:
    """Operators parsing the stream need to know which contract shape they
    are reading. Every record carries the version stamp."""
    p = tmp_path / "audit.jsonl"
    w = AuditWriter(str(p))
    w.emit({"type": "proxy_restart"})
    events = _read(p)
    assert events[0]["v"] == AUDIT_CONTRACT_VERSION
