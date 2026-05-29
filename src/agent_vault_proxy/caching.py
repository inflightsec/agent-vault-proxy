"""Generic TTL+jitter+LRU cache around any SecretsBackend.

Decoupled from any single backend so every backend gets identical caching
semantics without re-implementing.

Singleflight: concurrent get(name) calls for the same name trigger
backend.fetch exactly once; other waiters block on the same Future.
Prevents re-auth stampede when many threads observe token expiry
simultaneously (Pentester finding M2 — see docs/adapter-architecture.md).
"""

from __future__ import annotations

import contextlib
import secrets
import threading
import time
from collections import OrderedDict
from concurrent.futures import Future
from dataclasses import dataclass

from agent_vault_proxy.backends import (
    BackendUnavailableError,
    FetchContext,
    SecretsBackend,
)


class _StaleAfterFlushError(BackendUnavailableError):
    """Raised by the singleflight leader when flush() bumped the generation
    counter during the fetch. The fetched value is from a credential that
    the operator just rotated, so neither the cache nor any caller should
    use it. Inherits from BackendUnavailableError so existing caller
    `except BackendUnavailableError` handlers treat it as a transient,
    retriable failure (Oracle C1)."""


@dataclass
class CacheEntry:
    value: str
    # Absolute expiry deadline (time.time() basis). Each entry gets its
    # own deadline = fetched_at + ttl ± jitter, so concurrent secrets
    # don't all expire at the same wall-clock tick and stampede the backend.
    expires_at: float
    # LRU tiebreaker: oldest-fetched evicted first when at max_entries.
    fetched_at: float


class CachingSecretsClient:
    def __init__(
        self,
        backend: SecretsBackend,
        ttl_seconds: int = 300,
        jitter_seconds: int = 30,
        max_entries: int = 100,
    ) -> None:
        self._backend = backend
        self.ttl_seconds = ttl_seconds
        self.jitter_seconds = jitter_seconds
        self.max_entries = max_entries
        # OrderedDict for O(1) LRU: move_to_end on read, popitem(last=False) on overflow.
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        # Singleflight: name → in-flight Future for the next fetch result.
        # Concurrent get(name) calls find the Future and block on it.
        self._inflight: dict[str, Future[str]] = {}
        self._lock = threading.Lock()
        # Bumped on every flush(). Leaders capture this under lock at fetch
        # start; if it differs at write-back time, an operator flush happened
        # mid-fetch and our value is stale relative to the rotated credential
        # — skip the cache write (Pentester finding H-A). Waiters that
        # already captured the Future still receive the value (one stale
        # read flows; the sticky stale cache entry is what would be the bug).
        self._generation = 0

    def get(self, name: str, ctx: FetchContext | None = None) -> str:  # noqa: C901
        # Complexity inherent: singleflight + generation-counter + LRU + race
        # handling in one critical path. Splitting into helpers would obscure
        # the lock-discipline invariants. See Pentester finding M-A / H-A for
        # why each branch exists.
        now = time.time()
        waiting_on: Future[str] | None = None
        new_fut: Future[str] | None = None
        fetch_generation = 0
        with self._lock:
            entry = self._cache.get(name)
            if entry and now < entry.expires_at:
                # LRU bump — recently-read entries are protected from eviction.
                self._cache.move_to_end(name)
                return entry.value

            # Cache miss / stale. Singleflight check: if another thread is
            # already fetching this name, wait on its Future instead of
            # starting a duplicate fetch.
            existing = self._inflight.get(name)
            if existing is not None:
                waiting_on = existing
            else:
                # Install a new in-flight marker BEFORE we drop the lock.
                # Other threads arriving between now and our fetch will see
                # this and block on our Future.
                new_fut = Future()
                self._inflight[name] = new_fut
                fetch_generation = self._generation

        if waiting_on is not None:
            # Wait on someone else's in-flight fetch. Their result.
            return waiting_on.result()

        assert new_fut is not None  # mypy: covered by branch above

        # We're the leader for this name. Do the actual fetch outside the lock
        # so we don't block other names' callers. try/finally guarantees the
        # _inflight slot is cleared and waiters are notified even on
        # BaseException (KeyboardInterrupt/SystemExit) — without this,
        # ^C mid-fetch would orphan the Future and hang every subsequent
        # get(name) caller forever (Pentester finding M-A).
        #
        # Oracle C4 note: catching BaseException means a SIGINT/SystemExit
        # raised by backend.fetch propagates not only to OUR thread but
        # also (via the Future) to every other thread blocked on this name.
        # Acceptable: the alternative is hanging those waiters forever.
        # Operators should send signals to the process group, not a single
        # worker thread, if they want clean shutdown.
        leader_exception: BaseException | None = None
        value: str | None = None
        cache_writable = False
        try:
            value = self._backend.fetch(name, ctx)
        except BaseException as e:
            leader_exception = e
            raise
        finally:
            with self._lock:
                # Only release the slot if it's still OURS — flush() may have
                # cleared _inflight mid-fetch, in which case a different
                # Future may now occupy the name and we must not evict it.
                if self._inflight.get(name) is new_fut:
                    self._inflight.pop(name, None)

                cache_writable = leader_exception is None and self._generation == fetch_generation
                if cache_writable:
                    # No flush happened during our fetch — safe to cache.
                    # The `name in cache` check handles the refresh path
                    # (existing entry getting replaced) — don't evict to make
                    # room for an entry that's about to displace itself.
                    now = time.time()
                    while name not in self._cache and len(self._cache) >= self.max_entries:
                        self._cache.popitem(last=False)
                    assert value is not None  # mypy: cache_writable ⇒ value set
                    self._cache[name] = CacheEntry(
                        value=value,
                        expires_at=self._jittered_expiry(now),
                        fetched_at=now,
                    )
                    self._cache.move_to_end(name)
                # else (exception, or flush happened) — do not cache; waiters
                # are notified below.

            # Notify waiters OUTSIDE the lock so their .result() callbacks
            # don't run while we hold it. Oracle C5: a stray InvalidStateError
            # here (someone cancelled new_fut — today not possible, but
            # defensive against future instrumentation) must not mask the
            # leader's own raise. Waiter notification is best-effort.
            with contextlib.suppress(Exception):
                if leader_exception is not None:
                    new_fut.set_exception(leader_exception)
                elif not cache_writable:
                    # Oracle C1: flush bumped the generation while we were
                    # fetching. Tell waiters the value is stale so they
                    # retry under the new credential, rather than receive
                    # the value the operator just rotated away from.
                    new_fut.set_exception(
                        _StaleAfterFlushError(
                            f"value for {name!r} invalidated by flush during fetch; retry"
                        )
                    )
                else:
                    assert value is not None
                    new_fut.set_result(value)

        if not cache_writable:
            # Oracle C1: symmetric behavior — the leader's own caller also
            # raises rather than receiving the stale value. Without this,
            # waiters retry but the leader silently returns the rotated-out
            # secret to its caller.
            raise _StaleAfterFlushError(
                f"value for {name!r} invalidated by flush during fetch; retry"
            )
        assert value is not None
        return value

    def composite_fetch(
        self,
        names: list[str],
        ctx: FetchContext | None = None,
    ) -> dict[str, str]:
        """Atomically fetch multiple secrets under a single generation snapshot.

        Used by the addon's composite-binding code path. Steps map to the
        design doc (avp-composite-secrets-design.md §4.3):

         5. Capture ``gen_start = self._generation`` BEFORE the first fetch.
         6. Fetch each name in order. Empty value triggers
            BackendUnavailableError (Silas F4 — never compose partial
            credentials). Per-fetch failures propagate as-is.
         8. Re-check ``self._generation == gen_start``. Mismatch raises
            ``_StaleAfterFlushError`` so the caller restarts the whole
            assembly under the new credential — covers the race where one
            underlying value was served from cache, then flushed before
            the next underlying value was fetched (Silas F2).

        The single-secret ``get`` already protects the case where a flush
        happens DURING a backend fetch (existing H-A). The post-check here
        covers the case where a flush happens BETWEEN successful gets
        within the composite assembly — that's a gap the per-fetch check
        alone can't close.
        """
        if not names:
            raise ValueError("composite_fetch requires at least one name")

        with self._lock:
            gen_start = self._generation

        values: dict[str, str] = {}
        for name in names:
            value = self.get(name, ctx)
            if not value:
                raise BackendUnavailableError(
                    f"composite component {name!r} returned empty value; "
                    f"cannot compose partial credentials"
                )
            values[name] = value

        with self._lock:
            if self._generation != gen_start:
                raise _StaleAfterFlushError(
                    f"composite fetch for {sorted(values)} invalidated by "
                    f"flush during assembly; retry"
                )

        return values

    def flush(self, name: str | None = None) -> None:
        with self._lock:
            # Bump generation so any leader currently mid-fetch detects the
            # flush at write-back time and skips caching its now-stale value
            # (Pentester finding H-A). Clearing _inflight also frees new
            # callers to start a fresh fetch rather than blocking on the
            # stale leader's Future.
            self._generation += 1
            if name is None:
                self._cache.clear()
                self._inflight.clear()
                # Tell the backend (if it implements flush_name_map) that
                # any cached lookup state should also be dropped.
                flush_name_map = getattr(self._backend, "flush_name_map", None)
                if callable(flush_name_map):
                    flush_name_map()
            else:
                self._cache.pop(name, None)
                self._inflight.pop(name, None)

    def _jittered_expiry(self, now: float) -> float:
        # `secrets.randbelow` is a CSPRNG; we don't need that strength here
        # but it's a stdlib one-liner that doesn't shadow the `secrets`
        # module name we already import.
        #
        # Clamp jitter to ttl/2 so a misconfigured (jitter > ttl) setup
        # can't produce a negative effective TTL = instant expiry.
        if self.jitter_seconds <= 0 or self.ttl_seconds <= 1:
            return now + self.ttl_seconds
        jitter = min(self.jitter_seconds, self.ttl_seconds // 2)
        offset = secrets.randbelow(2 * jitter + 1) - jitter
        return now + self.ttl_seconds + offset
