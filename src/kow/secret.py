"""``Secret`` — the wrapper that keeps resolved credential bytes off every
rendering path.

A resolved secret used to travel as a bare ``str``, so any ``f"{value}"``,
``repr()``, log record, exception message or traceback frame was a leak site and
the only defence was every author remembering not to interpolate. ``Secret``
makes that structural: the value comes out through ``.reveal()`` and nowhere
else. Pickling raises, so it cannot cross a process boundary by accident.

``.reveal()`` is deliberately ugly. It marks the exact line where the bytes
become visible, which is the line a reviewer should look at.
"""

from __future__ import annotations

import hmac
from typing import Any, NoReturn

REDACTED = "<Secret redacted>"


class Secret:
    """An opaque credential value. ``reveal()`` is the only way out."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError(f"Secret takes str, got {type(value).__name__}")
        self._value = value

    def reveal(self) -> str:
        """Return the real bytes. Call this as late as possible."""
        return self._value

    def __repr__(self) -> str:
        return REDACTED

    def __str__(self) -> str:
        return REDACTED

    def __format__(self, _spec: str) -> str:
        # Ignores the format spec on purpose — "{:>80}" must not pad the value
        # into existence.
        return REDACTED

    def __bool__(self) -> bool:
        return bool(self._value)

    def __len__(self) -> int:
        return len(self._value)

    def __eq__(self, other: object) -> bool:
        # Secret-to-Secret only. Comparing against a bare str is refused so a
        # caller cannot probe the value one guess at a time.
        if not isinstance(other, Secret):
            return NotImplemented
        return hmac.compare_digest(self._value, other._value)

    def __hash__(self) -> int:
        # Hashing the value would let it leak through a dict key's hash in a
        # crash dump; identity is enough for the one use (set membership).
        return object.__hash__(self)

    def __reduce__(self) -> NoReturn:
        raise TypeError("Secret is not picklable — it must not cross a process boundary")

    def __copy__(self) -> NoReturn:
        raise TypeError("Secret is not copyable — pass the same object")

    def __deepcopy__(self, _memo: Any) -> NoReturn:
        raise TypeError("Secret is not copyable — pass the same object")


def reveal(value: Secret | str) -> str:
    """Unwrap a ``Secret``, or pass a plain ``str`` through.

    Bridges call sites that still receive either during the migration.
    """
    return value.reveal() if isinstance(value, Secret) else value
