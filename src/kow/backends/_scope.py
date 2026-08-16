"""Shared namespace-scoping + self_check primitives for prefix-bounded backends.

Extracted from the byte-identical copies in ``aws.py`` and ``gsm.py`` so the
``secret_prefix`` boundary has exactly one implementation — two copies of a
security predicate means one gets patched and the other does not. Pure
functions, not a base class: inheritance here would fight the ``SecretsBackend``
Protocol. ``tests/backends/test_scope_contract.py`` runs one table against every
caller.
"""

from __future__ import annotations

import logging
from typing import Any


class HttpError(Exception):
    """Internal: a non-2xx HTTP response. Carries the code + parsed body so the
    caller maps it to a protocol exception."""

    def __init__(self, status: int, body: dict[str, Any] | None) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status
        self.body = body


def assert_in_scope(name: str, prefix: str | None) -> None:
    """Defence-in-depth: refuse to touch a name outside ``prefix``.

    Even if the backend identity is broader than intended, the access boundary
    holds. A falsy prefix means unbounded — the caller opted out via config.
    """
    if prefix and not name.startswith(prefix):
        from kow.backends import SecretNotFoundError

        raise SecretNotFoundError(
            f"secret {name!r} is outside secret_prefix {prefix!r}; refusing to "
            "fetch out-of-namespace (defence-in-depth)"
        )


def refuse_or_warn(mode: str, msg: str, log: logging.Logger) -> None:
    """Shared self_check failure branch: deny → raise (refuse to start);
    warn → log and continue. ``mode`` is never ``off`` here. ``log`` is the
    caller's logger so records keep their originating module name."""
    from kow.backends import BackendUnavailableError

    if mode == "deny":
        raise BackendUnavailableError(f"{msg} [self_check=deny → refusing to start]")
    log.warning("%s [self_check=warn → continuing]", msg)
