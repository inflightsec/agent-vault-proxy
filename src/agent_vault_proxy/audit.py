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
AUDIT_CONTRACT_VERSION = 2

# inject_decision `reason` for a secret whose BWS note carries no binding
# (empty/missing note, or a mapping with no `host`). Distinct from
# `invalid_binding_metadata` (a MALFORMED note) so operators can tell
# "operator hasn't bound this secret yet" from "operator typo'd the note".
# Both fail closed; only the audit reason differs. (ADR-0011 item 6.)
REASON_NO_BINDING_IN_NOTES = "no_binding_in_notes"
REASON_INVALID_BINDING_METADATA = "invalid_binding_metadata"


class AuditWriter:
    def __init__(self, path: str, fail_on_unwritable: bool = True) -> None:
        self.path = path
        self.fail_on_unwritable = fail_on_unwritable
        self._lock = threading.Lock()

    def emit(self, event: dict[str, Any]) -> None:
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
