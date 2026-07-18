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

# ADR-0024: a notes/annotation-supplied host was rejected by the file-side
# `notes_host_allowlist` (annotations may only NARROW scope, never add a
# host — the GSM confused-deputy structural fix). Distinct from
# `invalid_binding_metadata` (malformed note) so operators can tell "someone
# tried to route a secret somewhere un-approved" from "operator typo'd".
REASON_HOST_NOT_IN_ALLOWLIST = "host_not_in_allowlist"

# ADR-0019 §5: the follow-up event type emitted when an inject_decision fires
# on a binding the operator flagged `honeytoken: true`. Carries only fields
# already present on the triggering inject_decision — same minimization
# contract (no secret material, no header/body/query).
EVENT_HONEYTOKEN_TRIGGERED = "honeytoken_triggered"

# ADR-0023: the CLOSED set of audit event types AVP may ever write. `emit()`
# refuses any type outside this set, so a NEW event type cannot be shipped
# without being added here CONSCIOUSLY — and that is the point where PR review
# forces it to (a) carry no secret material and (b) gain stateful no-leak
# coverage (test_addon*_noleak_stateful.py, whose invariant scans the whole
# audit stream for secret bytes).
#
# Scope, stated honestly: this guard is TYPE-level, not field-level. It does not
# by itself stop a value-bearing field being added to a *known* type — that is
# caught by the no-leak state machines (which scan for secret bytes regardless of
# field) plus the declared field allowlist pinned in test_audit_event_type_contract.py.
# The three layers together are the "no secret in the audit" guarantee; this
# frozenset is the type-closure layer. (A future hardening is typed event builders
# or a field allowlist enforced here — see ADR-0023, deferred as it needs the
# full optional-field enumeration and a careful pass over the G6 fsync path.)
# Keep in sync with docs/adrs/ADR-0023 and the emit call sites.
AUDIT_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "inject_decision",
        "deny",
        "token_exchange",
        "refresh_token_rotated",
        EVENT_HONEYTOKEN_TRIGGERED,
        "proxy_restart",
        "upstream_response",
    }
)


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
        # ADR-0023 choke-point contract guard. Refuse any event whose `type`
        # is not in the declared closed set. This is the single structural
        # rule that keeps the audit stream provably free of unclassified
        # records: every permitted type is covered by a stateful no-leak test
        # that scans the whole stream for secret bytes, so a type that reaches
        # this writer is guaranteed to be one that has been vetted to carry no
        # secret material. Fail-closed and consistent with AVP's posture — an
        # unrecognised type is a programming error (a new emit site that skipped
        # the contract), and surfacing it loudly at the choke point is strictly
        # safer than silently writing a record whose minimization nobody vetted.
        # All current emit sites use a listed type, so this never fires on the
        # existing hot paths.
        event_type = event.get("type")
        if event_type not in AUDIT_EVENT_TYPES:
            raise ValueError(
                f"audit event type {event_type!r} is not in AUDIT_EVENT_TYPES; "
                "refusing to write an unclassified audit record. Add the type to "
                "AUDIT_EVENT_TYPES in audit.py and bring it under no-leak test "
                "coverage (see ADR-0023)."
            )
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
