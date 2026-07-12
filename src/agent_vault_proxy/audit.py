from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from typing import Any

# Audit JSON contract version (AGENTS.md hard constraint #3). Operators parse
# this stream; any field added/removed/renamed bumps this AND updates
# docs/architecture.md §4.4. Stamped on every record as `v`.
#   v1 -> pre-ADR-0011 baseline (implicit; records had no `v` stamp).
#   v2 -> ADR-0011: add `binding_source` to inject_decision; new reason
#         `no_binding_in_notes`.
#   v3 -> ADR-0019: add the `honeytoken_triggered` event, emitted as a
#         follow-up to any inject_decision whose secret is flagged
#         `honeytoken: true`. No new fields on any existing event.
AUDIT_CONTRACT_VERSION = 3

# inject_decision `reason` for a secret whose BWS note carries no binding
# (empty/missing note, or a mapping with no `host`). Distinct from
# `invalid_binding_metadata` (a MALFORMED note) so operators can tell
# "operator hasn't bound this secret yet" from "operator typo'd the note".
# Both fail closed; only the audit reason differs. (ADR-0011 item 6.)
REASON_NO_BINDING_IN_NOTES = "no_binding_in_notes"
REASON_INVALID_BINDING_METADATA = "invalid_binding_metadata"

# ADR-0019 §5: the follow-up event type emitted when an inject_decision fires
# on a binding the operator flagged `honeytoken: true`. Carries only fields
# already present on the triggering inject_decision — same minimization
# contract (no secret material, no header/body/query).
EVENT_HONEYTOKEN_TRIGGERED = "honeytoken_triggered"


class AuditWriter:
    def __init__(
        self,
        path: str,
        fail_on_unwritable: bool = True,
        *,
        honeytoken_names: frozenset[str] = frozenset(),
    ) -> None:
        self.path = path
        self.fail_on_unwritable = fail_on_unwritable
        # Secret names the operator flagged `honeytoken: true` (ADR-0019 §5).
        # An inject_decision naming one auto-emits a follow-up
        # `honeytoken_triggered` event so the fleet collector can alert on a
        # single unambiguous type. Read-only after construction; a config
        # reload builds a fresh AuditWriter (see addon.configure_from_path).
        self._honeytoken_names = honeytoken_names
        self._lock = threading.Lock()

    def emit(self, event: dict[str, Any]) -> None:
        # Write the primary record (fsynced) first, then — if it is an
        # inject_decision naming a honeytoken secret — the follow-up
        # `honeytoken_triggered` event. The follow-up comes AFTER the
        # inject_decision (ADR-0019 §5) and gets its own synchronous fsync,
        # so both are durable before control returns to the request hook;
        # G6's audit-before-bytes-leave ordering is per-record and preserved.
        self._emit_record(event)
        follow_up = self._maybe_honeytoken_event(event)
        if follow_up is not None:
            self._emit_record(follow_up)

    def _emit_record(self, event: dict[str, Any]) -> None:
        record = {
            "ts": datetime.now(UTC).isoformat(timespec="microseconds"),
            "v": AUDIT_CONTRACT_VERSION,
            **event,
        }
        line = json.dumps(record, separators=(",", ":")) + "\n"
        with self._lock:
            try:
                with open(self.path, "a") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
            except OSError:
                if self.fail_on_unwritable:
                    raise

    def _maybe_honeytoken_event(self, event: dict[str, Any]) -> dict[str, Any] | None:
        """Build the follow-up ``honeytoken_triggered`` payload for an
        inject_decision naming a honeytoken secret, else ``None``.

        Every field is a strict subset of the triggering event —
        ``request_id``, the secret name (as ``binding_name``), the destination
        host, and the triggering ``reason`` (as ``underlying_reason``). No
        secret material, header, body, or query string is introduced; the
        §4.4 minimization contract is preserved verbatim (ADR-0019 §5).
        ``_emit_record`` stamps ``ts`` + ``v``.
        """
        if not self._honeytoken_names:
            return None
        if event.get("type") != "inject_decision":
            return None
        secret_name = event.get("secret_name")
        if secret_name is None or secret_name not in self._honeytoken_names:
            return None
        destination = event.get("destination")
        dest_host = destination.get("host") if isinstance(destination, dict) else None
        return {
            "type": EVENT_HONEYTOKEN_TRIGGERED,
            "request_id": event.get("request_id"),
            "binding_name": secret_name,
            "dest_host": dest_host,
            "underlying_reason": event.get("reason"),
        }
