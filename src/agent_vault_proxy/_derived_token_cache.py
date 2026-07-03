"""Cache for OAuth2-derived access tokens (ADR-0017 slice 4).

Sibling of :mod:`agent_vault_proxy.caching` — NOT a namespace inside
``CachingSecretsClient``. Vault secrets are fetched on demand under a
single shared TTL; access tokens are minted at request time, each with
its own per-token lifetime from the upstream's ``expires_in``. Mixing
them in one client makes ``flush()`` / ``list_secret_names`` /
audit-attribution semantics ambiguous, so the separation is structural.

Cache key incorporates every input that materially affects the token's
validity — binding name, token URL, scopes, client id, refresh token
value. Any rotation or config-reload that changes one of those produces
a different key, so a stale token cannot be served after the inputs
that minted it have changed (Oracle finding C4).

The salt is per-instance and process-local; serialising the cache
across restarts is deliberately out of scope.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future
from dataclasses import dataclass


@dataclass(frozen=True)
class KeyInputs:
    """The complete set of inputs that determine cache identity.

    Any change to any of these fields produces a different key. The
    dataclass is frozen so callers can't accidentally mutate inputs
    after a put().
    """

    binding_name: str
    token_url: str
    scopes: str | None
    client_id_value: str
    refresh_token_value: str


@dataclass(frozen=True)
class _Entry:
    value: str
    expires_at: float
    binding_name: str  # for flush_binding lookup


# Type alias for the fetch callable — returns (value, expires_at).
FetchFn = Callable[[], tuple[str, float]]


class DerivedTokenCache:
    """In-memory access-token cache with per-entry TTL and inflight dedup.

    Threading: every operation takes ``self._lock``. Inflight futures
    (one per cache key in mid-fetch) let concurrent dedup_or_fetch
    callers wait on a single upstream exchange instead of fanning out
    N requests for the same binding.

    Memory hardening: the G10 invariants from the parent doc apply —
    cache lives in RAM only, no swap (mlock applied to the process
    arena at startup, not per-buffer here), zero-on-flush is
    best-effort under Python's immutable-string model. The cache
    intentionally has no persistence path.
    """

    def __init__(self) -> None:
        # 32-byte salt = 256-bit HMAC key. ``secrets.token_bytes`` reads
        # from the OS CSPRNG and is the canonical Python primitive for
        # this.
        self._salt = secrets.token_bytes(32)
        self._lock = threading.Lock()
        self._entries: dict[str, _Entry] = {}
        self._inflight: dict[str, Future[tuple[str, float]]] = {}

    # -- key derivation ----------------------------------------------------

    def _key_for(self, inputs: KeyInputs) -> str:
        """Stable, salted key for cache lookup.

        HMAC-SHA256 over a length-prefixed serialisation of every
        field. Length prefixes prevent ambiguity if two field values
        concatenate to look like a different combination.
        """
        parts = [
            inputs.binding_name,
            inputs.token_url,
            inputs.scopes or "",
            inputs.client_id_value,
            inputs.refresh_token_value,
        ]
        body = b"\x00".join(f"{len(p)}:{p}".encode() for p in parts)
        return hmac.new(self._salt, body, hashlib.sha256).hexdigest()

    # -- read / write surface ---------------------------------------------

    def get(self, inputs: KeyInputs) -> str | None:
        """Return the cached value if present AND unexpired, else None.
        Expiry check uses ``time.time()`` at call time — no jitter,
        no clock skew compensation here (the safety margin lives on
        the put side via ``expires_at`` already accounting for it).
        """
        key = self._key_for(inputs)
        now = time.time()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if now >= entry.expires_at:
                # Lazy eviction — return None, leave the entry; the
                # next put() for the same key overwrites it. Bounded
                # because the key space is bounded by configured
                # bindings, not by request volume.
                return None
            return entry.value

    def put(self, inputs: KeyInputs, value: str, *, expires_at: float) -> None:
        """Insert ``value`` with the caller-supplied absolute expiry.

        Proactively evicts already-expired entries to keep the dict
        bounded across rotations: the cache key incorporates the
        refresh token value, so a rotation produces a new key and
        leaves the old one dead-weight until flush. The sweep is O(N)
        but N is bounded by configured bindings × in-flight rotations,
        which stays small in practice.
        """
        key = self._key_for(inputs)
        now = time.time()
        with self._lock:
            expired = [k for k, e in self._entries.items() if e.expires_at <= now]
            for k in expired:
                del self._entries[k]
            self._entries[key] = _Entry(
                value=value,
                expires_at=expires_at,
                binding_name=inputs.binding_name,
            )

    def flush(self) -> None:
        """Drop every entry. Best-effort zeroing: rebind ``value`` to
        an empty string before the dict clears so the original bytes
        are at least no longer reachable through the Entry. Python
        strings are immutable so the *original* bytes may persist
        until GC; the G10 invariants (no swap, no core dumps,
        process-isolation) carry the actual at-rest defence.
        """
        with self._lock:
            for key in list(self._entries.keys()):
                # Rebind to a zero-value entry first so any reference
                # held mid-iteration sees the cleared shape; then drop.
                self._entries[key] = _Entry(value="", expires_at=0.0, binding_name="")
                del self._entries[key]

    def flush_binding(self, binding_name: str) -> None:
        """Drop every entry whose binding matches. Used by the
        rotation-detection path when a refresh response signals
        invalidation of the cached access token."""
        with self._lock:
            for key in list(self._entries.keys()):
                if self._entries[key].binding_name == binding_name:
                    del self._entries[key]

    # -- inflight dedup ---------------------------------------------------

    def dedup_or_fetch(self, inputs: KeyInputs, fetch_fn: FetchFn) -> str:
        """Return a value for ``inputs``, ensuring at most one
        concurrent invocation of ``fetch_fn`` per cache key.

        Lifecycle:
          - Cache hit: return cached value, never call ``fetch_fn``.
          - Cache miss + no inflight: this caller is the leader; it
            calls ``fetch_fn``, populates the cache, sets the future.
          - Cache miss + inflight exists: caller waits on the future.
            Successful future resolution returns the value; failed
            resolution propagates the exception to every waiter.

        **Re-entrancy.** ``fetch_fn`` MUST NOT call back into
        ``dedup_or_fetch`` for the same ``KeyInputs`` on the same
        thread — that path is a self-deadlock (the leader waits on
        its own unset future). The OAuth2 token-exchange call site
        in slice 5 does not recurse; this docstring pins the
        assumption.
        """
        key = self._key_for(inputs)
        now = time.time()

        with self._lock:
            entry = self._entries.get(key)
            if entry is not None and now < entry.expires_at:
                return entry.value
            inflight = self._inflight.get(key)
            if inflight is not None:
                # Wait outside the lock — drop now, re-pick the future
                # reference into a local.
                wait_for = inflight
            else:
                wait_for = None
                new_fut: Future[tuple[str, float]] = Future()
                self._inflight[key] = new_fut

        if wait_for is not None:
            value, _expires = wait_for.result()
            return value

        # Leader path — we own the inflight slot. Wrap fetch in try
        # so any failure (network, parse, 4xx) propagates to waiters.
        try:
            value, expires_at = fetch_fn()
        except BaseException as e:
            with self._lock:
                fut = self._inflight.pop(key, None)
            if fut is not None:
                fut.set_exception(e)
            raise
        # Write cache + set future under lock.
        with self._lock:
            self._entries[key] = _Entry(
                value=value,
                expires_at=expires_at,
                binding_name=inputs.binding_name,
            )
            fut = self._inflight.pop(key, None)
        if fut is not None:
            fut.set_result((value, expires_at))
        return value
