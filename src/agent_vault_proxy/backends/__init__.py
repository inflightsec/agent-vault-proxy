"""Secrets-backend Protocol, exceptions, and registry.

A backend's only job is to translate a logical secret name into a current
value. Caching, retry, and audit are wrapped around the backend by the
caller (the addon, via CachingSecretsClient).

To add a new backend:
    1. Create src/agent_vault_proxy/backends/<vendor>.py implementing the
       SecretsBackend protocol with a paired pydantic config model.
    2. Call register_backend("<vendor>", <BackendCls>, <ConfigCls>) at
       module import time (typically at the bottom of the new file).
    3. Import the module from agent_vault_proxy/backends/__init__.py so
       the registration runs at startup.
    4. Update bindings.example.yaml + docs/adapter-architecture.md.

See docs/adapter-architecture.md for the full design rationale.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol, runtime_checkable

from pydantic import BaseModel


class SecretNotFoundError(Exception):
    """The backend confirms no secret exists under that name."""


class BackendUnavailableError(Exception):
    """Transient backend failure: network, auth-expired-and-reauth-failed,
    vault sealed, rate-limited. Caller should NOT cache the failure;
    next attempt may succeed."""


class BackendAuthLostError(BackendUnavailableError):
    """Backend detected that its credentials are no longer valid (token
    revoked, account disabled). Distinct from generic BackendUnavailableError
    so the caching layer can flush its entries for this backend rather
    than continue serving cached values from a revoked credential.

    Implementation note: the cache-wide flush hook is planned but not yet
    wired (see docs/adapter-architecture.md pre-mortem mode 8). For now,
    raising this is informationally useful but treated identically to
    BackendUnavailableError by the cache.
    """


@dataclass(frozen=True)
class FetchContext:
    """Optional per-request context passed to backend.fetch.

    Backends ignore fields they don't use. Present in the protocol from
    day one so adding context-aware backends later isn't a breaking
    signature change.
    """

    destination_host: str | None = None
    destination_method: str | None = None
    destination_path: str | None = None
    request_id: str | None = None


@runtime_checkable
class SecretsBackend(Protocol):
    """A secrets backend fetches one named secret. Implementations handle
    their own auth lifecycle, identifier translation, and transient retries.

    Contract:
        - __init__(config) does NO I/O. First I/O is on first fetch().
        - fetch(name, ctx=None) returns the secret string.
        - fetch raises SecretNotFoundError when the backend confirms no
          such name exists. Distinct from auth/transport failures.
        - fetch raises BackendUnavailableError on transient failures.
        - repr() does NOT include token bytes (use SecretStr in config).
        - May be called from multiple threads; backend must be thread-safe
          OR documented as single-threaded (caching layer serializes).
    """

    def fetch(self, name: str, ctx: FetchContext | None = None) -> str: ...


# Registry: maps backend.type discriminator string → (BackendCls, ConfigCls).
# Populated by register_backend() calls at import time.
#
# Pentester L-B: external code reads through BACKEND_REGISTRY (a read-only
# MappingProxyType view) but cannot mutate it — registration MUST go through
# register_backend() so the duplicate check fires. The private dict is the
# mutable backing store.
_registry: dict[str, tuple[type[SecretsBackend], type[BaseModel]]] = {}
BACKEND_REGISTRY: Mapping[str, tuple[type[SecretsBackend], type[BaseModel]]] = MappingProxyType(
    _registry
)


def _normalize_name(name: str) -> str:
    """Pentester L-A: bare .lower() doesn't fold compatibility variants
    (e.g., full-width "ＢＷＳ" survives .lower() as a different string from
    "bws", letting an attacker register a visually-identical duplicate).
    NFKC normalization + casefold collapses compat variants to their
    canonical form before the dedup check."""
    return unicodedata.normalize("NFKC", name).casefold()


def register_backend(
    name: str,
    backend_cls: type[SecretsBackend],
    config_cls: type[BaseModel],
) -> None:
    """Register a backend under a unique name.

    Name is NFKC-normalized + casefolded + checked for duplicates at
    registration time. Duplicate registration raises ValueError loudly —
    silent override would be a registry-collision attack vector (see
    Pentester finding H3 in docs/adapter-architecture.md).

    Concurrency (Oracle C9): registration is expected at module-import
    time (single-threaded). Reading via BACKEND_REGISTRY at runtime is
    safe (the MappingProxyType wraps a dict whose contents don't change
    after startup). Calling register_backend() from multiple threads or
    after startup is unsupported.
    """
    if not isinstance(name, str):
        raise TypeError(f"backend name must be str, got {type(name).__name__}")
    normalized = _normalize_name(name).strip()
    # Oracle C8: reject empty/whitespace-only names. Without this,
    # register_backend("", ...) or register_backend("   ", ...) silently
    # registers an unreachable backend (no one can write `type: ""` in YAML).
    if not normalized:
        raise ValueError(
            f"backend name {name!r} normalizes to empty/whitespace; choose a non-empty identifier"
        )
    if normalized in _registry:
        existing_cls = _registry[normalized][0]
        raise ValueError(
            f"backend name '{normalized}' already registered to "
            f"{existing_cls.__module__}.{existing_cls.__name__}; "
            f"refusing to overwrite with {backend_cls.__module__}.{backend_cls.__name__}"
        )
    _registry[normalized] = (backend_cls, config_cls)


def _reset_registry_for_tests() -> None:
    """Test-only: clear the registry between tests so register-twice
    errors don't fire across tests. Re-registers built-in backends
    explicitly (re-import wouldn't run module-top-level code again).

    Prefer the `isolated_registry` pytest fixture (in
    tests/backends/test_protocol_contract.py) over calling this directly —
    the fixture ensures the registry is restored even if the test body
    raises mid-way (Pentester finding D-A).
    """
    _registry.clear()
    from agent_vault_proxy.backends.bws import BitwardenBackend, BwsConfig
    from agent_vault_proxy.backends.static import StaticSecretsBackend, StaticSecretsConfig

    register_backend("bws", BitwardenBackend, BwsConfig)
    register_backend("static", StaticSecretsBackend, StaticSecretsConfig)


# Import backend modules at package import time so their register_backend()
# calls run. Order doesn't matter (each registers under a unique name).
from agent_vault_proxy.backends import bws as _bws_module  # noqa: E402, F401
from agent_vault_proxy.backends import static as _static_module  # noqa: E402, F401

__all__ = [
    "BACKEND_REGISTRY",
    "BackendAuthLostError",
    "BackendUnavailableError",
    "FetchContext",
    "SecretNotFoundError",
    "SecretsBackend",
    "register_backend",
]
