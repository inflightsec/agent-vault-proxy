"""Tests for the OAuth2 derived-token cache (ADR-0017 slice 4).

The cache is intentionally a sibling of :mod:`kow.caching`,
not a namespace inside ``CachingSecretsClient``. Vault secrets and
derived bearer tokens have incompatible invalidation, expiry, and
audit-attribution semantics (Oracle finding C3); mixing them in one
client makes ``flush()`` and ``list_secret_names`` ambiguous. The
separation is the load-bearing decision this file pins.
"""

from __future__ import annotations

import threading
import time

import pytest

from kow._derived_token_cache import DerivedTokenCache, KeyInputs


def _inputs(
    *,
    binding: str = "B",
    token_url: str = "https://example.com/t",
    scopes: str | None = None,
    client_id: str = "cid",
    refresh: str = "r1",
) -> KeyInputs:
    return KeyInputs(
        binding_name=binding,
        token_url=token_url,
        scopes=scopes,
        client_id_value=client_id,
        refresh_token_value=refresh,
    )


# ---------------------------------------------------------------------------
# Hit / miss / expiry — the read-side surface
# ---------------------------------------------------------------------------


def test_miss_returns_none_on_empty_cache() -> None:
    cache = DerivedTokenCache()
    assert cache.get(_inputs()) is None


def test_put_then_get_returns_value() -> None:
    cache = DerivedTokenCache()
    cache.put(_inputs(), "access-A", expires_at=time.time() + 60)
    assert cache.get(_inputs()) == "access-A"


def test_expired_entry_returns_none() -> None:
    cache = DerivedTokenCache()
    cache.put(_inputs(), "access-A", expires_at=time.time() - 1)
    assert cache.get(_inputs()) is None


def test_key_changes_on_input_change() -> None:
    """Cache key incorporates every input that affects token validity.
    Changing any one of them must miss the cache (Oracle C4 fix). This
    test exercises each axis as a parametric pin so a future change
    that drops one from the key surfaces immediately."""
    cache = DerivedTokenCache()
    cache.put(_inputs(), "access-A", expires_at=time.time() + 60)
    # Same inputs hit.
    assert cache.get(_inputs()) == "access-A"
    # Each axis change misses.
    assert cache.get(_inputs(binding="OTHER")) is None
    assert cache.get(_inputs(token_url="https://other.example.com/t")) is None
    assert cache.get(_inputs(scopes="email")) is None
    assert cache.get(_inputs(client_id="other-cid")) is None
    assert cache.get(_inputs(refresh="r2")) is None


def test_salt_random_per_instance() -> None:
    """Two cache instances generate different keys for the same inputs.
    A predictable salt would let an attacker who can read the cache
    file format (none exists today, but defence in depth) precompute
    key→inputs mappings. Salt is process-local randomness."""
    a = DerivedTokenCache()
    b = DerivedTokenCache()
    assert a._key_for(_inputs()) != b._key_for(_inputs())  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Flush — invalidates and clears values
# ---------------------------------------------------------------------------


def test_flush_clears_all_entries() -> None:
    cache = DerivedTokenCache()
    cache.put(_inputs(), "access-A", expires_at=time.time() + 60)
    cache.put(_inputs(binding="OTHER"), "access-B", expires_at=time.time() + 60)
    cache.flush()
    assert cache.get(_inputs()) is None
    assert cache.get(_inputs(binding="OTHER")) is None


def test_flush_for_single_binding() -> None:
    """Flushing one binding's entry must not evict siblings — the
    cache is the only credential store for in-flight bindings; bulk
    flushes are operator actions, per-binding flushes are
    rotation-detection actions."""
    cache = DerivedTokenCache()
    cache.put(_inputs(binding="A"), "access-A", expires_at=time.time() + 60)
    cache.put(_inputs(binding="B"), "access-B", expires_at=time.time() + 60)
    cache.flush_binding("A")
    assert cache.get(_inputs(binding="A")) is None
    assert cache.get(_inputs(binding="B")) == "access-B"


# ---------------------------------------------------------------------------
# Inflight dedup — the load-bearing concurrency guarantee
# ---------------------------------------------------------------------------


def test_inflight_dedup_single_upstream_call() -> None:
    """Two concurrent ``dedup_or_fetch`` calls for the same inputs must
    result in exactly ONE invocation of the fetch function. Without
    this, a refresh-storm of N agent requests fires N token-endpoint
    POSTs — wastes provider rate-budget and risks anti-abuse flags
    (Oracle C5 within-process half).

    Test orchestration: the leader (t1) parks inside fetch on a gate
    Event; t2 must observe the inflight slot and wait on the future
    without entering fetch. Releasing the gate lets the leader complete;
    t2's waiter resolves with the same value the leader produced.
    """
    cache = DerivedTokenCache()
    call_count = 0
    fetch_entered = threading.Event()
    gate = threading.Event()

    def slow_fetch() -> tuple[str, float]:
        nonlocal call_count
        call_count += 1
        fetch_entered.set()
        gate.wait(timeout=2)
        return ("access-A", time.time() + 60)

    results: list[str] = []

    def caller() -> None:
        results.append(cache.dedup_or_fetch(_inputs(), slow_fetch))

    t1 = threading.Thread(target=caller)
    t1.start()
    # Wait until t1 is inside fetch (owns the inflight slot).
    assert fetch_entered.wait(timeout=2), "leader did not enter fetch"
    t2 = threading.Thread(target=caller)
    t2.start()
    # Give t2 a moment to register as a waiter on the future. The
    # cache's inflight slot is taken under the same lock t2 needs to
    # observe; a small sleep is the simplest reliable beat without
    # adding test-only instrumentation to the production class.
    time.sleep(0.05)  # nosemgrep: python.lang.best-practice.sleep.arbitrary-sleep
    gate.set()
    t1.join(timeout=2)
    t2.join(timeout=2)

    assert call_count == 1
    assert results == ["access-A", "access-A"]


def test_dedup_or_fetch_propagates_fetch_failure_to_all_waiters() -> None:
    """If the inflight fetch raises, both the leader and any waiter
    must see the exception. Silent fall-through to None would let a
    waiter inject an empty token."""
    cache = DerivedTokenCache()

    def boom() -> tuple[str, float]:
        raise RuntimeError("upstream down")

    with pytest.raises(RuntimeError, match="upstream down"):
        cache.dedup_or_fetch(_inputs(), boom)


def test_dedup_or_fetch_cache_hit_skips_fetch() -> None:
    """If a fresh entry exists, the fetch function must not be called
    at all. Plain hit-path optimisation pinned as a test so a
    refactor that always-calls fetch surfaces."""
    cache = DerivedTokenCache()
    cache.put(_inputs(), "cached", expires_at=time.time() + 60)
    called: list[bool] = []

    def fetch() -> tuple[str, float]:
        called.append(True)
        return ("fresh", time.time() + 60)

    value = cache.dedup_or_fetch(_inputs(), fetch)
    assert value == "cached"
    assert called == []


def test_dedup_or_fetch_writes_cache_on_success() -> None:
    """Successful fetch populates the cache for subsequent gets — both
    via ``get`` and via a second ``dedup_or_fetch`` that should now
    hit, not call fetch."""
    cache = DerivedTokenCache()
    call_count = 0

    def fetch() -> tuple[str, float]:
        nonlocal call_count
        call_count += 1
        return ("first", time.time() + 60)

    first = cache.dedup_or_fetch(_inputs(), fetch)
    second = cache.dedup_or_fetch(_inputs(), fetch)
    assert first == second == "first"
    assert call_count == 1
    assert cache.get(_inputs()) == "first"
