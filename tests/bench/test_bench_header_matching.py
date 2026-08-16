"""Hot-path benchmark: per-request header placeholder matching.

``policy.find_header_placeholder_matches`` runs on EVERY request. This module
records the cost as the secret count grows and pins correctness; it asserts on
RESULTS, never on wall-clock, so it cannot flake on a loaded machine. Run with
``-s`` to see the table.
"""

from __future__ import annotations

import time

from kow.policy import find_header_placeholder_matches

from .conftest import build_config, header_getter

SIZES = (10, 100, 1000)
_ITERATIONS = 200


def _time_us(fn, iterations: int = _ITERATIONS) -> float:
    fn()  # warm
    start = time.perf_counter()
    for _ in range(iterations):
        fn()
    return (time.perf_counter() - start) / iterations * 1_000_000


def test_bench_matching_cost_by_secret_count(capsys) -> None:
    """Report µs/request for a request carrying ONE real placeholder."""
    rows = []
    for n in SIZES:
        config = build_config(n)
        target = f"SECRET_{n - 1:05d}"
        spec = config.secrets[target]
        header = spec.inject.header
        get = header_getter({header: f"Bearer {spec.placeholder}"})

        matches = find_header_placeholder_matches(config, get)
        assert len(matches) == 1, f"n={n}: expected exactly one match"
        assert matches[0][0] == target

        rows.append((n, _time_us(lambda c=config, g=get: find_header_placeholder_matches(c, g))))

    with capsys.disabled():
        print("\n  secrets |   µs/request")
        print("  --------+-------------")
        for n, us in rows:
            print(f"  {n:7d} | {us:10.1f}")


def test_bench_miss_path_cost(capsys) -> None:
    """The common case: a request that matches NOTHING still pays full scan."""
    rows = []
    for n in SIZES:
        config = build_config(n)
        get = header_getter({"Authorization": "Bearer not-a-placeholder"})
        assert find_header_placeholder_matches(config, get) == []
        rows.append((n, _time_us(lambda c=config, g=get: find_header_placeholder_matches(c, g))))

    with capsys.disabled():
        print("\n  secrets |   µs/request (no match)")
        print("  --------+------------------------")
        for n, us in rows:
            print(f"  {n:7d} | {us:10.1f}")


def test_bench_with_prebuilt_index(capsys) -> None:
    """The deployed path: index built once per config snapshot, not per request."""
    from kow.policy import build_header_index

    rows = []
    for n in SIZES:
        config = build_config(n)
        index = build_header_index(config)
        target = f"SECRET_{n - 1:05d}"
        spec = config.secrets[target]
        hit = header_getter({spec.inject.header: f"Bearer {spec.placeholder}"})
        miss = header_getter({"Authorization": "Bearer not-a-placeholder"})

        # Same answers as the unindexed scan — the index is an accelerator only.
        assert find_header_placeholder_matches(
            config, hit, header_index=index
        ) == find_header_placeholder_matches(config, hit)
        assert find_header_placeholder_matches(config, miss, header_index=index) == []

        rows.append(
            (
                n,
                _time_us(
                    lambda c=config, g=hit, i=index: find_header_placeholder_matches(
                        c, g, header_index=i
                    )
                ),
                _time_us(
                    lambda c=config, g=miss, i=index: find_header_placeholder_matches(
                        c, g, header_index=i
                    )
                ),
            )
        )

    with capsys.disabled():
        print("\n  secrets |  µs hit |  µs miss  (prebuilt index)")
        print("  --------+---------+---------")
        for n, hit_us, miss_us in rows:
            print(f"  {n:7d} | {hit_us:7.1f} | {miss_us:7.1f}")
