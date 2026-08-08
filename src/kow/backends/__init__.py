"""Secrets-backend Protocol, exceptions, and registry.

A backend's only job is to translate a logical secret name into a current
value. Caching, retry, and audit are wrapped around the backend by the
caller (the addon, via CachingSecretsClient).

To add a new backend:
    1. Create src/kow/backends/<vendor>.py implementing the
       SecretsBackend protocol with a paired pydantic config model.
    2. Call register_backend("<vendor>", <BackendCls>, <ConfigCls>) at
       module import time (typically at the bottom of the new file).
    3. Import the module from kow/backends/__init__.py so
       the registration runs at startup.
    4. Update bindings.example.yaml + docs/adapter-architecture.md.

See docs/adapter-architecture.md for the full design rationale.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
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


@contextmanager
def require(backend: str, package: str, extra: str, *, note: str = "") -> Iterator[None]:
    """Guard an optional backend's lazy third-party import.

    Wrap the backend's ``import`` in this context so a missing optional
    dependency becomes one actionable :class:`BackendUnavailableError` with a
    uniform install hint (both pip and pipx), instead of a raw ImportError.

        with require("aws", "botocore", "aws"):
            import botocore.session

    ``note`` appends backend-specific context (e.g. the Bitwarden SDK's
    proprietary-license caveat) after the first line.
    """
    try:
        yield
    except ImportError as e:  # pragma: no cover — dep-not-installed path
        raise BackendUnavailableError(
            f"the {backend} backend needs the '{package}' package, which is not "
            f"installed.{note}\n"
            f"  pip install 'agent-vault-proxy[{extra}]'\n"
            f"  pipx inject agent-vault-proxy {package}   # if AVP was installed with pipx"
        ) from e


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

    ``fetch_with_meta`` (ADR-0011) is OPTIONAL. A backend that carries
    per-secret binding metadata (BWS in its ``notes`` field) implements it
    to return ``(value, note)``; backends with no notes concept omit it and
    callers use the module-level :func:`fetch_with_meta` helper, which
    falls back to ``(fetch(...), None)``. Keeping it off the required
    surface means static.py and every third-party adapter stay working
    unchanged under the Protocol change.
    """

    def fetch(self, name: str, ctx: FetchContext | None = None) -> str: ...


def fetch_with_meta(
    backend: SecretsBackend,
    name: str,
    ctx: FetchContext | None = None,
) -> tuple[str, str | None]:
    """Return ``(value, note)`` for ``name``.

    Dispatch: if ``backend`` implements its own ``fetch_with_meta`` (bws
    does, reading the secret's notes field), use it. Otherwise fall back to
    ``(backend.fetch(name, ctx), None)`` — the safe default for backends
    with no notes concept. This is the single call site the BWS-notes
    binding loader uses, so adding a notes-aware backend never requires
    touching the loader, and a non-notes backend never breaks it.

    Note normalisation (empty/whitespace -> None) is the backend's
    responsibility (see BitwardenBackend.fetch_with_meta); the fallback
    path has no note to normalise.
    """
    own = getattr(type(backend), "fetch_with_meta", None)
    # Guard against this very function being picked up if a backend aliases
    # the name to the module helper — compare against this function object.
    if callable(own) and own is not fetch_with_meta:
        # bitwarden-sdk-backed backend has no type stubs for this method;
        # the cast keeps the helper's (str, str | None) contract at the
        # boundary rather than leaking Any to every caller.
        result: tuple[str, str | None] = backend.fetch_with_meta(name, ctx)  # type: ignore[attr-defined]
        return result
    return backend.fetch(name, ctx), None


class BackendCannotListError(Exception):
    """Raised by :func:`list_secret_names` when the backend has no way to
    enumerate secret names. ``avp env`` and the daemon's BWS-notes placeholder
    map both REQUIRE enumeration; a backend that can't list can't drive either,
    and we fail loud rather than silently producing an empty env file (which
    would look like "no secrets" instead of "this backend can't list")."""


class BackendNotWritableError(BackendUnavailableError):
    """The backend has no ``update`` method (read-only adapter), or its
    update path is structurally unavailable. Subclasses
    :class:`BackendUnavailableError` so the addon's existing fail-closed
    catch-all already does the right thing for write-back paths — the
    OAuth2 refresh-token rotation audit branch (slice 7) catches this
    specifically to emit ``refresh_token_rotated:write_back_unavailable``.
    """


class BackendWriteConflictError(BackendUnavailableError):
    """The backend's CURRENT value no longer matches the value the caller
    read before deriving its update (operator-side rotation mid-flight).
    Refusing the write prevents clobbering a manual rotation with a value
    derived from the superseded credential (ADR-0017 hardening series).
    Subclasses :class:`BackendUnavailableError` so untouched fail-closed
    catch-alls keep doing the right thing; the OAuth2 write-back path
    catches it specifically to audit ``refresh_token_rotated:
    write_back_conflict``."""


def update_secret(
    backend: SecretsBackend,
    name: str,
    value: str,
    ctx: FetchContext | None = None,
    *,
    expected_current_value: str | None = None,
) -> None:
    """Persist ``value`` under ``name`` via ``backend``.

    Dispatch: if ``backend`` implements its own ``update`` (BWS does;
    third-party writable adapters can), call it. Otherwise raise
    :class:`BackendNotWritableError` — the same opt-in shape
    :func:`fetch_with_meta` uses, so adding a writable backend never
    requires touching the dispatch helper, and a read-only backend
    never silently no-ops a write.

    ``expected_current_value``: optional write precondition. Passed to
    the backend ONLY when set, so writable backends that don't support
    preconditions (and simple test stubs) keep their two-positional
    signature. Backends that do support it raise
    :class:`BackendWriteConflictError` on mismatch.

    The Static test backend stays intentionally read-only; production
    callers wanting in-memory write-back should use a stub backend
    declared writable.
    """
    own = getattr(type(backend), "update", None)
    if not callable(own):
        raise BackendNotWritableError(
            f"backend {type(backend).__name__} does not implement update(); "
            "this is a read-only adapter"
        )
    if expected_current_value is None:
        backend.update(name, value, ctx)  # type: ignore[attr-defined]
    else:
        backend.update(  # type: ignore[attr-defined]
            name, value, ctx, expected_current_value=expected_current_value
        )


def list_secret_names(backend: SecretsBackend) -> list[str]:
    """Return every secret name the backend can enumerate.

    Like :func:`fetch_with_meta`, this dispatches to the backend's own
    ``list_secret_names`` when present (bws + static implement it) and
    raises :class:`BackendCannotListError` otherwise. Kept as a single
    helper so the ``avp env`` projection and the daemon's placeholder-map
    builder share one enumeration contract — adding a listable backend never
    requires touching either caller.
    """
    own = getattr(type(backend), "list_secret_names", None)
    if callable(own) and own is not list_secret_names:
        result: list[str] = backend.list_secret_names()  # type: ignore[attr-defined]
        return result
    raise BackendCannotListError(
        f"backend {type(backend).__name__} cannot enumerate secret names; "
        "`avp env` and BWS-notes binding mode require a listable backend "
        "(bws, static)."
    )


def list_secret_notes(backend: SecretsBackend) -> dict[str, str | None]:
    """Return ``{secret_name: note | None}`` for every enumerable secret,
    WITHOUT fetching values when the backend supports it.

    Dispatch: a backend that can surface per-secret metadata without a value
    read (GSM reads ``avp-binding`` annotations from the free ListSecrets pass)
    implements ``list_secret_notes``. Backends that can't fall back to
    ``list_secret_names`` + ``fetch_with_meta`` — which DOES read each value —
    preserving existing bws/static behaviour. A backend failure propagates so
    notes activation fails closed at configure() rather than serving a partial
    binding view."""
    own = getattr(type(backend), "list_secret_notes", None)
    if callable(own) and own is not list_secret_notes:
        result: dict[str, str | None] = backend.list_secret_notes()  # type: ignore[attr-defined]
        return result
    return {name: fetch_with_meta(backend, name)[1] for name in list_secret_names(backend)}


# Registry: maps backend.type discriminator string → (BackendCls, ConfigCls).
# Populated by register_backend() calls at import time.
#
# external code reads through BACKEND_REGISTRY (a read-only
# MappingProxyType view) but cannot mutate it — registration MUST go through
# register_backend() so the duplicate check fires. The private dict is the
# mutable backing store.
_registry: dict[str, tuple[type[SecretsBackend], type[BaseModel]]] = {}
BACKEND_REGISTRY: Mapping[str, tuple[type[SecretsBackend], type[BaseModel]]] = MappingProxyType(
    _registry
)


def _normalize_name(name: str) -> str:
    """bare .lower() doesn't fold compatibility variants
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
    design-doc reference in docs/adapter-architecture.md).

    Concurrency: registration is expected at module-import
    time (single-threaded). Reading via BACKEND_REGISTRY at runtime is
    safe (the MappingProxyType wraps a dict whose contents don't change
    after startup). Calling register_backend() from multiple threads or
    after startup is unsupported.
    """
    if not isinstance(name, str):
        raise TypeError(f"backend name must be str, got {type(name).__name__}")
    normalized = _normalize_name(name).strip()
    # reject empty/whitespace-only names. Without this,
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
    raises mid-way.
    """
    _registry.clear()
    from kow.backends.aws import AwsConfig, AwsSecretsManagerBackend
    from kow.backends.bws import BitwardenBackend, BwsConfig
    from kow.backends.gsm import GsmBackend, GsmConfig
    from kow.backends.static import StaticSecretsBackend, StaticSecretsConfig

    register_backend("aws-secrets-manager", AwsSecretsManagerBackend, AwsConfig)
    register_backend("bws", BitwardenBackend, BwsConfig)
    register_backend("gsm", GsmBackend, GsmConfig)
    register_backend("static", StaticSecretsBackend, StaticSecretsConfig)


# Import backend modules at package import time so their register_backend()
# calls run. Order doesn't matter (each registers under a unique name).
from kow.backends import aws as _aws_module  # noqa: E402, F401
from kow.backends import bws as _bws_module  # noqa: E402, F401
from kow.backends import gsm as _gsm_module  # noqa: E402, F401
from kow.backends import static as _static_module  # noqa: E402, F401

__all__ = [
    "BACKEND_REGISTRY",
    "BackendAuthLostError",
    "BackendCannotListError",
    "BackendNotWritableError",
    "BackendUnavailableError",
    "FetchContext",
    "SecretNotFoundError",
    "SecretsBackend",
    "fetch_with_meta",
    "list_secret_names",
    "list_secret_notes",
    "register_backend",
    "update_secret",
]
