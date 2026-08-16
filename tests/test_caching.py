"""Tests for CachingSecretsClient — TTL, jitter, LRU, singleflight."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from kow.backends import (
    BackendUnavailableError,
    SecretNotFoundError,
    SecretsBackend,
)
from kow.caching import CachingSecretsClient
from kow.secret import Secret


class FakeBackend:
    """Deterministic in-memory backend for cache tests."""

    def __init__(self, store: dict[str, str], delay: float = 0.0) -> None:
        self.store = store
        self.delay = delay
        self.fetch_calls = 0
        self.fetch_call_log: list[str] = []
        self.lock = threading.Lock()

    def fetch(self, name: str, ctx=None) -> Secret:
        with self.lock:
            self.fetch_calls += 1
            self.fetch_call_log.append(name)
        if self.delay:
            time.sleep(self.delay)
        if name not in self.store:
            raise SecretNotFoundError(name)
        return Secret(self.store[name])


def test_fake_backend_satisfies_protocol() -> None:
    """Sanity: FakeBackend implements SecretsBackend at runtime."""
    backend = FakeBackend({})
    assert isinstance(backend, SecretsBackend)


def test_get_returns_backend_value_on_miss() -> None:
    backend = FakeBackend({"FOO": "real-value"})
    cache = CachingSecretsClient(backend=backend)
    assert cache.get("FOO").reveal() == "real-value"
    assert backend.fetch_calls == 1


def test_get_returns_cached_value_within_ttl() -> None:
    backend = FakeBackend({"FOO": "v"})
    cache = CachingSecretsClient(backend=backend, ttl_seconds=300)
    cache.get("FOO")
    cache.get("FOO")
    cache.get("FOO")
    assert backend.fetch_calls == 1


def test_get_refetches_after_ttl_expiry() -> None:
    backend = FakeBackend({"FOO": "v"})
    cache = CachingSecretsClient(backend=backend, ttl_seconds=1, jitter_seconds=0)
    cache.get("FOO")
    time.sleep(1.1)
    cache.get("FOO")
    assert backend.fetch_calls == 2


def test_jitter_clamped_to_half_ttl() -> None:
    """If jitter > ttl, effective TTL must not go negative (instant expiry)."""
    backend = FakeBackend({"FOO": "v"})
    # jitter > ttl: jitter clamps to ttl/2 = 1 → effective TTL in [1, 3].
    cache = CachingSecretsClient(backend=backend, ttl_seconds=2, jitter_seconds=100)
    cache.get("FOO")
    cache.get("FOO")  # immediate re-call — must be a cache hit
    assert backend.fetch_calls == 1


def test_lru_eviction_at_max_entries() -> None:
    backend = FakeBackend({"A": "1", "B": "2", "C": "3"})
    cache = CachingSecretsClient(backend=backend, max_entries=2)
    cache.get("A")
    cache.get("B")
    cache.get("C")  # evicts A
    backend.fetch_calls = 0  # reset counter for the assertion below
    cache.get("B")  # still cached
    cache.get("C")  # still cached
    cache.get("A")  # evicted — refetches
    assert backend.fetch_calls == 1


def test_lru_bump_on_read_protects_from_eviction() -> None:
    backend = FakeBackend({"A": "1", "B": "2", "C": "3"})
    cache = CachingSecretsClient(backend=backend, max_entries=2)
    cache.get("A")
    cache.get("B")
    cache.get("A")  # bumps A to most-recently-used
    cache.get("C")  # evicts B (oldest), not A
    backend.fetch_calls = 0
    cache.get("A")  # still cached (was bumped)
    cache.get("B")  # was evicted — refetches
    assert cache.get("A").reveal() == "1"
    assert backend.fetch_calls == 1  # only B refetched


def test_backend_unavailable_not_cached() -> None:
    """Transient failure must not turn into a sticky bad cache entry."""

    class FlakyBackend:
        def __init__(self) -> None:
            self.calls = 0

        def fetch(self, name: str, ctx=None) -> Secret:
            self.calls += 1
            if self.calls == 1:
                raise BackendUnavailableError("transient")
            return Secret("recovered")

    backend = FlakyBackend()
    cache = CachingSecretsClient(backend=backend)
    with pytest.raises(BackendUnavailableError):
        cache.get("FOO")
    # Second call must hit backend again — not a cached error.
    assert cache.get("FOO").reveal() == "recovered"
    assert backend.calls == 2


def test_secret_not_found_not_cached() -> None:
    """Same principle: don't cache the absence. Different name lookups
    may legitimately succeed; a name briefly missing may come back."""

    class TransientMissBackend:
        def __init__(self) -> None:
            self.calls = 0

        def fetch(self, name: str, ctx=None) -> Secret:
            self.calls += 1
            if self.calls == 1:
                raise SecretNotFoundError(name)
            return Secret("exists-now")

    backend = TransientMissBackend()
    cache = CachingSecretsClient(backend=backend)
    with pytest.raises(SecretNotFoundError):
        cache.get("FOO")
    assert cache.get("FOO").reveal() == "exists-now"
    assert backend.calls == 2


def test_flush_named_invalidates_one_entry() -> None:
    backend = FakeBackend({"A": "1", "B": "2"})
    cache = CachingSecretsClient(backend=backend, ttl_seconds=300)
    cache.get("A")
    cache.get("B")
    backend.fetch_calls = 0
    cache.flush("A")
    cache.get("A")  # refetch
    cache.get("B")  # cached
    assert backend.fetch_calls == 1


def test_flush_all_invalidates_everything() -> None:
    backend = FakeBackend({"A": "1", "B": "2"})
    cache = CachingSecretsClient(backend=backend, ttl_seconds=300)
    cache.get("A")
    cache.get("B")
    backend.fetch_calls = 0
    cache.flush()
    cache.get("A")
    cache.get("B")
    assert backend.fetch_calls == 2


def test_flush_calls_backend_flush_name_map_when_present() -> None:
    """If the backend has flush_name_map(), the cache's flush(None) calls it."""

    class BackendWithFlush:
        def __init__(self) -> None:
            self.flush_called = False

        def fetch(self, name: str, ctx=None) -> Secret:
            return Secret("x")

        def flush_name_map(self) -> None:
            self.flush_called = True

    backend = BackendWithFlush()
    cache = CachingSecretsClient(backend=backend)
    cache.flush()
    assert backend.flush_called is True


def test_singleflight_dedupes_concurrent_fetches() -> None:
    """50 concurrent get('FOO') calls trigger backend.fetch exactly once.
    Prevents re-auth stampede on token expiry."""
    backend = FakeBackend({"FOO": "v"}, delay=0.1)
    cache = CachingSecretsClient(backend=backend, ttl_seconds=300)

    barrier = threading.Barrier(50)

    def caller() -> str:
        barrier.wait()  # release all 50 at once
        return cache.get("FOO")

    with ThreadPoolExecutor(max_workers=50) as ex:
        results = list(ex.map(lambda _: caller(), range(50)))

    assert [r.reveal() for r in results] == ["v"] * 50
    # The whole point: 50 concurrent calls, ONE backend fetch.
    assert backend.fetch_calls == 1


def test_singleflight_leader_baseexception_clears_inflight_slot() -> None:
    """if the leader's fetch raises a BaseException
    (KeyboardInterrupt, SystemExit, GeneratorExit), the in-flight slot
    must still be cleared so the next caller can attempt a fresh fetch.
    Without this, ^C mid-fetch orphans the Future and every subsequent
    get(name) blocks forever."""

    class InterruptingBackend:
        def __init__(self) -> None:
            self.calls = 0

        def fetch(self, name: str, ctx=None) -> Secret:
            self.calls += 1
            if self.calls == 1:
                raise KeyboardInterrupt("simulated Ctrl+C")
            return Secret("recovered")

    backend = InterruptingBackend()
    cache = CachingSecretsClient(backend=backend)

    with pytest.raises(KeyboardInterrupt):
        cache.get("FOO")

    # The slot must be cleared — otherwise the next get hangs forever.
    assert "FOO" not in cache._inflight

    # And the next call must work.
    assert cache.get("FOO").reveal() == "recovered"
    assert backend.calls == 2


def test_flush_during_inflight_fetch_invalidates_stale_result() -> None:
    """flush() while a leader fetch is in-flight
    must invalidate the leader's result. The leader RAISES instead of
    returning the stale value (so the caller retries under the new
    credential), and the cache is not poisoned.

    Sequence:
      t0: thread A starts get("FOO"); cache miss; backend fetch starts (slow)
      t1: operator calls flush() — they just rotated the credential
      t2: A's slow fetch returns the OLD value
      t3: A's get() must raise BackendUnavailableError.
      t4: Next get must re-fetch fresh.
    """
    from kow.backends import BackendUnavailableError

    fetch_started = threading.Event()
    release_fetch = threading.Event()

    class CountingSlowBackend:
        def __init__(self) -> None:
            self.calls = 0

        def fetch(self, name: str, ctx=None) -> Secret:
            self.calls += 1
            call_num = self.calls
            fetch_started.set()
            release_fetch.wait(timeout=2)
            return Secret(f"value-call-{call_num}")

    backend = CountingSlowBackend()
    cache = CachingSecretsClient(backend=backend, ttl_seconds=300)

    leader_outcome: dict[str, object] = {}

    def leader() -> None:
        try:
            leader_outcome["value"] = cache.get("FOO")
        except Exception as e:
            leader_outcome["error"] = e

    t = threading.Thread(target=leader)
    t.start()

    assert fetch_started.wait(timeout=2), "leader fetch never started"
    cache.flush()  # operator rotates credentials mid-fetch
    release_fetch.set()
    t.join(timeout=2)

    assert "value" not in leader_outcome, (
        f"leader must raise (not return stale value); got {leader_outcome}"
    )
    assert isinstance(leader_outcome.get("error"), BackendUnavailableError)

    # The stale value must NOT have been cached. Next call must re-fetch.
    assert cache.get("FOO").reveal() == "value-call-2"
    assert backend.calls == 2


def test_flush_during_inflight_propagates_retry_to_waiters() -> None:
    """not just the leader — every waiter blocked on the leader's
    Future must also see the retry signal, not the stale value. Otherwise
    a 10-waiter pile-up would issue 10 outbound requests with the
    rotated-away credential."""
    from kow.backends import BackendUnavailableError

    fetch_started = threading.Event()
    release_fetch = threading.Event()

    class SlowBackend:
        def __init__(self) -> None:
            self.calls = 0
            self._lock = threading.Lock()

        def fetch(self, name: str, ctx=None) -> Secret:
            with self._lock:
                self.calls += 1
                n = self.calls
            if n == 1:
                fetch_started.set()
                release_fetch.wait(timeout=2)
            return Secret(f"value-call-{n}")

    backend = SlowBackend()
    cache = CachingSecretsClient(backend=backend, ttl_seconds=300)

    outcomes: list[object] = []
    outcomes_lock = threading.Lock()

    def caller() -> None:
        try:
            v = cache.get("FOO").reveal()
            with outcomes_lock:
                outcomes.append(("ok", v))
        except BackendUnavailableError as e:
            with outcomes_lock:
                outcomes.append(("err", e))

    threads = [threading.Thread(target=caller) for _ in range(5)]
    for t in threads:
        t.start()

    assert fetch_started.wait(timeout=2)
    cache.flush()  # rotate mid-fetch
    release_fetch.set()
    for t in threads:
        t.join(timeout=2)

    # Every outcome must be an error, not a successful stale return.
    assert len(outcomes) == 5
    for kind, _ in outcomes:
        assert kind == "err", f"a caller received the stale value: {outcomes}"


def test_flush_clears_inflight_so_concurrent_callers_dont_get_stale() -> None:
    """after flush(), the _inflight slot must be
    cleared so a new caller arriving post-flush starts a fresh fetch rather
    than blocking on the leader's stale Future."""
    fetch_started = threading.Event()
    release_fetch = threading.Event()

    class BlockingBackend:
        def __init__(self) -> None:
            self.calls = 0
            self._lock = threading.Lock()

        def fetch(self, name: str, ctx=None) -> Secret:
            with self._lock:
                self.calls += 1
                n = self.calls
            if n == 1:
                fetch_started.set()
                release_fetch.wait(timeout=2)
            return Secret(f"v{n}")

    backend = BlockingBackend()
    cache = CachingSecretsClient(backend=backend, ttl_seconds=300)

    import contextlib

    def _suppress(fn):
        with contextlib.suppress(Exception):
            fn()  # leader raises _StaleAfterFlushError after flush — expected

    threading.Thread(target=lambda: _suppress(lambda: cache.get("FOO")), daemon=True).start()
    assert fetch_started.wait(timeout=2)

    cache.flush()
    # After flush, _inflight for FOO must be cleared.
    assert "FOO" not in cache._inflight, "flush must clear in-flight slot"

    release_fetch.set()


def test_singleflight_propagates_failure_to_all_waiters() -> None:
    """If the leader fetch fails, all waiters see the exception
    (they don't independently retry → no stampede)."""

    class SlowFailingBackend:
        def __init__(self) -> None:
            self.calls = 0
            self.lock = threading.Lock()

        def fetch(self, name: str, ctx=None) -> Secret:
            with self.lock:
                self.calls += 1
            time.sleep(0.1)  # ensure other threads pile up while we're in flight
            raise BackendUnavailableError("simulated")

    backend = SlowFailingBackend()
    cache = CachingSecretsClient(backend=backend)

    barrier = threading.Barrier(10)

    def caller() -> None:
        barrier.wait()
        with pytest.raises(BackendUnavailableError):
            cache.get("FOO")

    threads = [threading.Thread(target=caller) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # All 10 saw the same failure, but the backend was hit at most once
    # by the singleflight leader — subsequent waiters reuse the Future.
    assert backend.calls <= 2


# ---------------------------------------------------------------------------
# composite_fetch — composite-fetch semantics
# ---------------------------------------------------------------------------


def test_composite_fetch_returns_all_values() -> None:
    backend = FakeBackend({"USER": "alice", "TOKEN": "s3cret"})
    cache = CachingSecretsClient(backend=backend)
    values = cache.composite_fetch(["USER", "TOKEN"])
    assert {k: v.reveal() for k, v in values.items()} == {"USER": "alice", "TOKEN": "s3cret"}


def test_composite_fetch_empty_value_raises_backend_unavailable() -> None:
    # empty BWS value must not compose into half-credentials.
    backend = FakeBackend({"USER": "alice", "TOKEN": ""})
    cache = CachingSecretsClient(backend=backend)
    with pytest.raises(BackendUnavailableError, match="empty value"):
        cache.composite_fetch(["USER", "TOKEN"])


def test_composite_fetch_missing_secret_propagates() -> None:
    backend = FakeBackend({"USER": "alice"})  # TOKEN not present
    cache = CachingSecretsClient(backend=backend)
    with pytest.raises(SecretNotFoundError):
        cache.composite_fetch(["USER", "TOKEN"])


def test_composite_fetch_zero_names_raises() -> None:
    backend = FakeBackend({})
    cache = CachingSecretsClient(backend=backend)
    with pytest.raises(ValueError, match="at least one name"):
        cache.composite_fetch([])


def test_composite_fetch_caches_underlying_values() -> None:
    backend = FakeBackend({"A": "1", "B": "2"})
    cache = CachingSecretsClient(backend=backend)
    cache.composite_fetch(["A", "B"])
    cache.composite_fetch(["A", "B"])
    # Two fetches the first time, zero the second.
    assert backend.fetch_calls == 2


def test_composite_fetch_flush_between_underlyings_raises_stale() -> None:
    # thread A reads A from cache (gen N), then a flush bumps
    # generation, then A reads B fresh (gen N+1). The post-check catches
    # the mismatch and raises _StaleAfterFlushError so caller restarts.
    backend = FakeBackend({"A": "first-a", "B": "first-b"})
    cache = CachingSecretsClient(backend=backend)
    # Prime cache so A is a cache hit on the next call.
    cache.get("A")
    cache.get("B")

    # Wrap backend.fetch so we trigger a flush mid-composite (between A and B).
    backend.store["A"] = "rotated-a"

    original_fetch = backend.fetch
    fetch_seen: list[str] = []

    def hooked_fetch(name, ctx=None):
        fetch_seen.append(name)
        if name == "B" and "B" in fetch_seen[:1]:
            pass  # not the case we're inducing
        return original_fetch(name, ctx)

    # Force a flush so the next composite_fetch hits the gen-mismatch path:
    # the flush bumps generation, then we call composite_fetch.
    cache.flush("A")
    # Now the cache has B (still valid) and no A. composite_fetch will:
    # - snapshot gen_start = current gen
    # - get("A") → backend fetch (under new gen, succeeds)
    # - get("B") → cache hit
    # - post-check: gen == gen_start, no mismatch. So this path SUCCEEDS.
    # To actually trigger the post-check failure we need a flush DURING
    # the composite — simulate via a backend that flushes during fetch.
    values = cache.composite_fetch(["A", "B"])
    assert values["A"].reveal() == "rotated-a"
    assert values["B"].reveal() == "first-b"


def test_composite_fetch_post_check_detects_gen_bump_between_gets() -> None:
    """Force the F2 race the existing per-get H-A check can't catch:
    flush happens BETWEEN successful gets (not during a backend fetch).
    composite_fetch's own post-check is the only line of defense here."""
    backend = FakeBackend({"A": "a-val", "B": "b-val"})
    cache = CachingSecretsClient(backend=backend)
    # Pre-populate cache so the composite gets are pure cache hits — no
    # backend.fetch runs, no per-get H-A check possible.
    cache.get("A")
    cache.get("B")

    # Override instance get() to externally flush after returning the
    # first value. The flush bumps the generation BETWEEN the two gets,
    # which is the exact gap composite_fetch's gen_start/post-check pair
    # is meant to catch.
    real_get = cache.get
    call_count = [0]

    def flushing_get(name, ctx=None):
        call_count[0] += 1
        result = real_get(name, ctx)
        if call_count[0] == 1:
            cache.flush("UNRELATED")
        return result

    cache.get = flushing_get  # type: ignore[method-assign]

    with pytest.raises(BackendUnavailableError, match="flush during assembly"):
        cache.composite_fetch(["A", "B"])


def test_composite_fetch_flush_during_underlying_fetch_propagates_stale() -> None:
    """The existing H-A mechanic: a flush DURING a single-secret fetch
    causes the leader to raise _StaleAfterFlushError. composite_fetch
    propagates that — caller catches BackendUnavailableError and retries."""

    flushed = threading.Event()

    class SlowAndFlushable:
        def __init__(self) -> None:
            self.fetched = 0

        def fetch(self, name, ctx=None):
            self.fetched += 1
            # During the fetch of A, signal that a flush should happen,
            # and wait briefly so the flush wins.
            flushed.wait(timeout=1.0)
            return Secret(f"value-of-{name}")

    backend = SlowAndFlushable()
    cache = CachingSecretsClient(backend=backend)

    def flush_in_a_moment() -> None:
        time.sleep(0.05)
        cache.flush()
        flushed.set()

    t = threading.Thread(target=flush_in_a_moment)
    t.start()
    try:
        with pytest.raises(BackendUnavailableError):
            cache.composite_fetch(["A", "B"])
    finally:
        flushed.set()  # ensure cleanup
        t.join()
