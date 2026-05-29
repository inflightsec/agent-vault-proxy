from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from typing import Any


class AuditWriter:
    def __init__(self, path: str, fail_on_unwritable: bool = True) -> None:
        self.path = path
        self.fail_on_unwritable = fail_on_unwritable
        self._lock = threading.Lock()

    def emit(self, event: dict[str, Any]) -> None:
        record = {
            "ts": datetime.now(UTC).isoformat(timespec="microseconds"),
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
