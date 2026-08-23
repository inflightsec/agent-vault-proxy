"""Shared test doubles.

Each of these was previously redefined, near-identically, in several test
modules. That duplication is not free: the ``Secret`` migration had to rewrite
every copy mechanically and broke two of them in the process. One definition per
double, imported where needed.
"""

from __future__ import annotations

from typing import Any

from kow.secret import Secret

__all__ = ["FakeNotesListBackend"]


class FakeNotesListBackend:
    """Backend exposing list + fetch + fetch_with_meta, keyed ``name -> (value, note)``.

    ``fetch_with_meta`` returns ``(Secret, note)``, matching the declared
    protocol in ``kow.backends.fetch_with_meta``. The per-module copies this
    replaced returned the raw string, quietly violating their own annotation.
    """

    def __init__(self, secrets: dict[str, tuple[str, str | None]]) -> None:
        self._secrets = secrets

    def list_secret_names(self) -> list[str]:
        return list(self._secrets)

    def fetch(self, name: str, ctx: Any = None) -> Secret:
        return Secret(self._secrets[name][0])

    def fetch_with_meta(self, name: str, ctx: Any = None) -> tuple[Secret, str | None]:
        value, note = self._secrets[name]
        return Secret(value), note
