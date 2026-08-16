"""Systematic concurrency / race audit of kow.

Motivation: a cold-start follower race in the OAuth2 resolver
(``exchange_result_holder[0]`` IndexError on every follower of a cold
refresh-storm, pinned by ``tests/test_addon_oauth2_concurrent.py``) proved
the concurrent surface is under-probed. This module attacks the remaining
shared-mutable-state surfaces with real threads + barriers — not theory —
and records a verdict per surface.

Verdict summary (see each section's docstring for the repro):

  1. Config reload torn view (addon.configure_from_path vs requestheaders)
       -> SAFE (observable): no crash, no cross-secret leak, no torn/empty
          injected value under a reload storm. The ``_capture_state``
          snapshot is INCOMPLETE (attribution maps + ``_token_cache`` are
          re-read from ``self`` mid-request, not frozen), but in file mode
          the maps are empty and the config-published-last ordering plus
          fail-closed fetch keep the observable behavior clean.
  2. DerivedTokenCache.dedup_or_fetch  -> SAFE (fully lock-guarded).
  3. AuditWriter.emit                  -> SAFE (no torn lines; per-record
          lock). Honeytoken follow-up is a SEPARATE lock acquisition, so a
          third thread's record MAY interleave between an inject_decision
          and its honeytoken_triggered follow-up — ordering (follow-up
          after primary) holds per-thread, adjacency does not. Benign:
          both carry request_id for correlation.
  4. OauthResolver._write_back_last    -> RACE-FOUND (low severity):
          the per-binding write-back rate-limit is an UNLOCKED check-then-set
          (oauth2_refresh.py:690 read, :700 write). Concurrent rotations of
          the SAME binding can all pass the interval floor and each issue a
          vault PUT. Neutralised for correctness by the CAS precondition
          (expected_current_value) which turns the extra PUTs into
          write_back_conflict, but the rate-limit control itself is bypassable.
          Distinct-binding concurrency is structurally safe (GIL-atomic dict
          ops). See test_writeback_rate_limit_toctou_same_binding (xfail).
  5. CachingSecretsClient              -> SAFE (generation counter +
          singleflight; already heavily covered in test_caching.py — these
          add get/update interleave + LRU-under-load stress).

Run: .venv/bin/pytest -q tests/test_concurrency_audit.py
"""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from kow._derived_token_cache import DerivedTokenCache, KeyInputs
from kow.audit import AuditWriter
from kow.backends import (
    BackendUnavailableError,
    BackendWriteConflictError,
    FetchContext,
    SecretNotFoundError,
)
from kow.caching import CachingSecretsClient
from kow.config import Oauth2RefreshInjector
from kow.injectors.oauth2_refresh import OauthResolver
from kow.secret import Secret
from tests import _oauth_helpers as oh

# ===========================================================================
# Surface 1: config reload torn view
# ===========================================================================
#
# addon.configure_from_path atomically swaps a BUNDLE of state
# (_placeholder_to_name, _no_binding_names, _invalid_names,
# _allowlist_rejected_names, _header_handler.allowlist_rejected_hosts,
# client, audit, config, _token_cache). requestheaders() snapshots only
# (config, client, audit, companion_headers) via _capture_state; the
# attribution maps and _token_cache are re-read from ``self`` mid-request.
#
# Attack: hammer requestheaders() on N threads while a flipper thread
# reloads the config between two DIFFERENT (config, backend) pairs that
# bind the SAME host with DIFFERENT secret names/placeholders/values.
#
# Security invariant under test: a request carrying placeholder P_A must
# NEVER get secret B's material injected (cross-secret leak), must never
# crash, and must never emit a torn/empty value. A torn view (old config
# decides P_A -> secret A, new client lacks secret A) must fail CLOSED
# (503), not leak.


def _header_config_yaml(*, audit_path: Path, secret_name: str, placeholder: str, host: str) -> str:
    return f"""
version: 1
secrets:
  {secret_name}:
    placeholder: "{placeholder}"
    inject:
      header: "Authorization"
      format: "Token {{{secret_name}}}"
    bindings:
      - host: "{host}"
unmatched_destination_policy: deny
audit:
  path: {audit_path}
  fail_on_unwritable: false
"""


class _ValueBackend:
    """Backend that only knows the secrets in ``values``; anything else
    raises SecretNotFoundError (so a torn view fetching a secret this
    backend does not hold fails CLOSED)."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = dict(values)

    def fetch(self, name: str, ctx: FetchContext | None = None) -> Secret:
        if name not in self._values:
            raise SecretNotFoundError(name)
        return Secret(self._values[name])


def test_config_reload_no_cross_secret_leak_or_crash(tmp_path: Path) -> None:  # noqa: C901 — threaded reload harness; branches are the concurrency scenario, not logic
    """Reload storm vs request storm. Two configs bind the SAME host with
    DIFFERENT secret name/placeholder/value; each backend holds ONLY its
    own secret. Assert: no request thread raises; a request whose
    placeholder resolves under the live config injects that config's value
    (never the other secret's); a torn view fails closed (503), never
    leaks. This directly exercises the incomplete-snapshot window."""
    from kow.addon import AgentVaultProxyAddon

    host = "api.example.com"
    p_a = "avp-A-PLACEHOLDER-01HXY1234567890ABCD"
    p_b = "avp-B-PLACEHOLDER-01HXY1234567890WXYZ"
    val_a = "AAAA-secretA-value"
    val_b = "BBBB-secretB-value"

    cfg_a = tmp_path / "a.yaml"
    cfg_b = tmp_path / "b.yaml"
    cfg_a.write_text(
        _header_config_yaml(
            audit_path=tmp_path / "audit_a.jsonl",
            secret_name="TOKA",
            placeholder=p_a,
            host=host,
        )
    )
    cfg_b.write_text(
        _header_config_yaml(
            audit_path=tmp_path / "audit_b.jsonl",
            secret_name="TOKB",
            placeholder=p_b,
            host=host,
        )
    )
    backend_a = _ValueBackend({"TOKA": val_a})
    backend_b = _ValueBackend({"TOKB": val_b})

    addon = AgentVaultProxyAddon()
    addon.configure_from_path(cfg_a, backend_override=backend_a)

    stop = threading.Event()
    errors: list[BaseException] = []
    # Records: (placeholder_sent, injected_authorization_or_None, resp_status)
    observations: list[tuple[str, str | None, int | None]] = []
    obs_lock = threading.Lock()

    def flipper() -> None:
        toggle = True
        while not stop.is_set():
            try:
                if toggle:
                    addon.configure_from_path(cfg_b, backend_override=backend_b)
                else:
                    addon.configure_from_path(cfg_a, backend_override=backend_a)
                toggle = not toggle
            except BaseException as e:  # noqa: BLE001
                errors.append(e)
                return

    def requester(placeholder: str) -> None:
        try:
            for _ in range(40):
                flow = oh.make_request(
                    host, {"Authorization": f"Bearer {placeholder}"}, path="/v1/thing"
                )
                addon.http_connect(flow)
                addon.requestheaders(flow)
                auth = flow.request.headers.get("Authorization")
                status = flow.response.status_code if flow.response is not None else None
                with obs_lock:
                    observations.append((placeholder, auth, status))
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    flip_thread = threading.Thread(target=flipper)
    flip_thread.start()
    req_threads = [
        threading.Thread(target=requester, args=(p,)) for p in (p_a, p_b, p_a, p_b, p_a, p_b)
    ]
    for t in req_threads:
        t.start()
    for t in req_threads:
        t.join(timeout=30)
    stop.set()
    flip_thread.join(timeout=30)

    assert not errors, f"a thread raised under reload storm: {errors!r}"
    assert observations, "no requests were observed"

    injected = 0
    for placeholder, auth, status in observations:
        assert auth is not None  # Authorization header always present
        # THE anti-leak invariant: the value belonging to the OTHER secret
        # must never appear under this placeholder.
        if placeholder == p_a:
            assert val_b not in auth, f"secret B leaked under placeholder A: {auth!r}"
        else:
            assert val_a not in auth, f"secret A leaked under placeholder B: {auth!r}"
        if auth.startswith("Token "):
            injected += 1
            # A real injection only ever carries THIS placeholder's value.
            expected = val_a if placeholder == p_a else val_b
            assert auth == f"Token {expected}", f"unexpected injected value {auth!r}"
        else:
            # Not injected: either forwarded verbatim (placeholder still
            # present, config didn't know it) or a fail-closed 5xx. Never a
            # crash, never a partial "Token " with garbage.
            assert placeholder in auth or status in (500, 502, 503)
    # The happy path must have actually run concurrently with the reloads,
    # else the test is vacuous.
    assert injected > 0, "no successful injection observed; test would be vacuous"


# ===========================================================================
# Surface 2: DerivedTokenCache.dedup_or_fetch
# ===========================================================================


def _ki(*, binding: str = "B", refresh: str = "r1") -> KeyInputs:
    return KeyInputs(
        binding_name=binding,
        token_url="https://example.com/t",
        scopes=None,
        client_id_value="cid",
        refresh_token_value=refresh,
    )


def test_dedup_many_same_key_single_upstream_call() -> None:
    """24 threads released together on ONE key -> exactly ONE fetch; every
    caller receives the leader's value. Extends the N=2 pin to a real
    storm."""
    cache = DerivedTokenCache()
    n = 24
    barrier = threading.Barrier(n)
    fetch_calls = 0
    fetch_lock = threading.Lock()

    def slow_fetch() -> tuple[str, float]:
        nonlocal fetch_calls
        with fetch_lock:
            fetch_calls += 1
        time.sleep(0.05)
        return ("access-A", time.time() + 60)

    results: list[str] = []
    res_lock = threading.Lock()

    def caller() -> None:
        barrier.wait(timeout=5)
        v = cache.dedup_or_fetch(_ki(), slow_fetch)
        with res_lock:
            results.append(v)

    with ThreadPoolExecutor(max_workers=n) as ex:
        list(ex.map(lambda _: caller(), range(n)))

    assert fetch_calls == 1, f"expected 1 upstream exchange, got {fetch_calls}"
    assert results == ["access-A"] * n


def test_dedup_distinct_keys_fetch_independently() -> None:
    """N distinct keys concurrently -> N independent fetches, each caller
    gets its own key's value. No cross-key contamination."""
    cache = DerivedTokenCache()
    n = 16
    barrier = threading.Barrier(n)
    seen: dict[str, str] = {}
    seen_lock = threading.Lock()

    def caller(i: int) -> None:
        binding = f"B{i}"
        barrier.wait(timeout=5)

        def fetch() -> tuple[str, float]:
            time.sleep(0.01)
            return (f"tok-{binding}", time.time() + 60)

        v = cache.dedup_or_fetch(_ki(binding=binding), fetch)
        with seen_lock:
            seen[binding] = v

    with ThreadPoolExecutor(max_workers=n) as ex:
        list(ex.map(caller, range(n)))

    assert seen == {f"B{i}": f"tok-B{i}" for i in range(n)}


def test_dedup_leader_failure_propagates_to_all_waiters() -> None:
    """One leader parks in fetch; many followers pile on the future; the
    leader raises. EVERY waiter (and the leader) must see the exception —
    no waiter silently returns None (which would inject an empty token)."""
    cache = DerivedTokenCache()
    entered = threading.Event()
    release = threading.Event()
    fetch_calls = 0
    fetch_lock = threading.Lock()

    def failing_fetch() -> tuple[str, float]:
        nonlocal fetch_calls
        with fetch_lock:
            fetch_calls += 1
        entered.set()
        release.wait(timeout=2)
        raise RuntimeError("upstream down")

    outcomes: list[str] = []
    out_lock = threading.Lock()

    def caller() -> None:
        try:
            cache.dedup_or_fetch(_ki(), failing_fetch)
            with out_lock:
                outcomes.append("ok")  # must never happen
        except RuntimeError:
            with out_lock:
                outcomes.append("err")
        except BaseException:  # noqa: BLE001
            with out_lock:
                outcomes.append("other")

    leader = threading.Thread(target=caller)
    leader.start()
    assert entered.wait(timeout=2), "leader never entered fetch"
    followers = [threading.Thread(target=caller) for _ in range(10)]
    for t in followers:
        t.start()
    time.sleep(0.05)  # let followers register as waiters
    release.set()
    leader.join(timeout=3)
    for t in followers:
        t.join(timeout=3)

    assert fetch_calls == 1, f"followers must not re-fetch; got {fetch_calls}"
    assert outcomes == ["err"] * 11, f"a waiter did not see the failure: {outcomes}"


def test_dedup_get_put_expiry_stress_no_corruption() -> None:
    """Concurrent get + dedup_or_fetch + expiry churn on one key. Assert
    every returned value is a well-formed token (never a torn/partial), the
    cache never wedges, and no unhandled exception escapes."""
    cache = DerivedTokenCache()
    errors: list[BaseException] = []
    err_lock = threading.Lock()

    def churn(i: int) -> None:
        try:
            for j in range(100):
                # Alternate very-short and normal expiry to race the lazy
                # eviction in get() against dedup writes.
                ttl = 0.001 if (j % 3 == 0) else 5.0

                def fetch(_ttl: float = ttl) -> tuple[str, float]:
                    return ("tok-shared", time.time() + _ttl)

                v = cache.dedup_or_fetch(_ki(), fetch)
                assert v == "tok-shared"
                got = cache.get(_ki())
                assert got in (None, "tok-shared")
        except BaseException as e:  # noqa: BLE001
            with err_lock:
                errors.append(e)

    with ThreadPoolExecutor(max_workers=12) as ex:
        list(ex.map(churn, range(12)))

    assert not errors, f"dedup/get stress raised: {errors!r}"


# ===========================================================================
# Surface 3: AuditWriter.emit
# ===========================================================================


def _read_lines(path: Path) -> list[str]:
    return [ln for ln in path.read_text().splitlines() if ln]


def test_audit_no_torn_lines_under_parallel_emit(tmp_path: Path) -> None:
    """Many threads emitting concurrently must produce ONLY complete,
    individually-valid JSON lines — no interleaved/torn bytes. The whole
    open+write+flush+fsync runs under _lock, so this should hold."""
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditWriter(str(audit_path))
    n_threads = 16
    per_thread = 50
    barrier = threading.Barrier(n_threads)

    def emitter(tid: int) -> None:
        barrier.wait(timeout=5)
        for i in range(per_thread):
            audit.emit(
                {
                    "type": "deny",
                    "reason": "unmatched_destination",
                    "request_id": f"t{tid}-{i}",
                    "destination": {"host": f"h{tid}.example.com", "port": 443},
                }
            )

    with ThreadPoolExecutor(max_workers=n_threads) as ex:
        list(ex.map(emitter, range(n_threads)))

    lines = _read_lines(audit_path)
    assert len(lines) == n_threads * per_thread
    ids = set()
    for ln in lines:
        rec = json.loads(ln)  # raises if a line is torn
        assert rec["type"] == "deny"
        ids.add(rec["request_id"])
    # Every emit landed exactly once, none clobbered/merged.
    assert len(ids) == n_threads * per_thread


def test_audit_honeytoken_followup_intact_under_concurrency(tmp_path: Path) -> None:
    """Under parallel emits, every inject_decision naming a honeytoken
    secret still gets exactly one honeytoken_triggered follow-up, all lines
    are valid JSON, and each follow-up correlates by request_id. (Adjacency
    of the pair is NOT guaranteed — a third thread's record may slip
    between them — but correctness of counts/correlation is.)"""
    audit_path = tmp_path / "audit.jsonl"
    audit = AuditWriter(str(audit_path), honeytoken_names=frozenset({"HT"}))
    n_threads = 12
    per_thread = 40
    barrier = threading.Barrier(n_threads)

    def emitter(tid: int) -> None:
        barrier.wait(timeout=5)
        for i in range(per_thread):
            audit.emit(
                {
                    "type": "inject_decision",
                    "request_id": f"t{tid}-{i}",
                    "decision": "denied",
                    "reason": "binding_matched",
                    "secret_name": "HT",
                    "destination": {"host": "trap.example.com", "port": 443},
                }
            )

    with ThreadPoolExecutor(max_workers=n_threads) as ex:
        list(ex.map(emitter, range(n_threads)))

    total = n_threads * per_thread
    recs = [json.loads(ln) for ln in _read_lines(audit_path)]
    primary_ids = {r["request_id"] for r in recs if r["type"] == "inject_decision"}
    followups = [r for r in recs if r["type"] == "honeytoken_triggered"]
    followup_ids = {r["request_id"] for r in followups}

    assert len(recs) == 2 * total, "every primary must have exactly one follow-up"
    assert len(primary_ids) == total
    assert len(followups) == total
    # Each follow-up correlates to a real primary and carries no extra id.
    assert followup_ids == primary_ids


# ===========================================================================
# Surface 4: OauthResolver._write_back_last rate-limit map  (RACE-FOUND)
# ===========================================================================


def _make_injector(**overrides: object) -> Oauth2RefreshInjector:
    kwargs: dict[str, object] = {
        "type": "oauth2_refresh",
        "provider": "google",
        "client_id_secret": "CID",
        "client_secret_secret": "CSEC",
        "refresh_token_secret": "RT",
    }
    kwargs.update(overrides)
    return Oauth2RefreshInjector(**kwargs)  # type: ignore[arg-type]


class _CountingRotationClient:
    """Duck-typed CachingSecretsClient for _handle_rotation: counts every
    update_secret invocation that REACHES the backend, mirrors the CAS
    precondition (BackendWriteConflictError when expected != stored)."""

    def __init__(self, store: dict[str, str]) -> None:
        self.store = dict(store)
        self.attempts = 0
        self.writes: list[tuple[str, str]] = []
        self._lock = threading.Lock()

    def update_secret(
        self,
        name: str,
        value: str,
        ctx: object = None,
        *,
        expected_current_value: str | None = None,
    ) -> None:
        with self._lock:
            self.attempts += 1
            if (
                expected_current_value is not None
                and self.store.get(name) != expected_current_value
            ):
                raise BackendWriteConflictError(f"secret {name!r} changed since read")
            self.writes.append((name, value))
            self.store[name] = value


def test_writeback_rate_limit_holds_under_concurrency_same_binding(tmp_path: Path) -> None:
    """Same binding, N concurrent rotations, default 60s interval floor.

    Regression guard for concurrency-audit surface 4: the check-then-set on
    ``OauthResolver._write_back_last`` was an unlocked TOCTOU that let all N
    rotations pass the floor. With the map guarded by a lock, exactly ONE PUT
    is admitted within the window regardless of interleaving; the other N-1
    audit ``write_back_rate_limited``. All threads are released at a single
    barrier so they genuinely contend on the lock (no barrier-inside-``get``,
    which would deadlock against the fix)."""
    n = 8
    audit = AuditWriter(str(tmp_path / "aud.jsonl"))
    resolver = OauthResolver()
    client = _CountingRotationClient({"RT": "rtok-OLD-00000000"})
    barrier = threading.Barrier(n)
    injector = _make_injector()  # write_back_min_interval_seconds default = 60
    errors: list[BaseException] = []

    def worker(i: int) -> None:
        try:
            barrier.wait(timeout=5)
            resolver._handle_rotation(
                client=client,  # type: ignore[arg-type]
                audit=audit,
                request_id=f"req-{i}",
                secret_name="BINDING",
                oauth_injector=injector,
                new_refresh_token=f"rtok-NEW-{i:08d}",
                old_refresh_token="rtok-OLD-00000000",
            )
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert not errors, f"rotation worker raised: {errors!r}"
    # The floor holds under concurrency: exactly one PUT reaches the backend.
    assert client.attempts == 1, (
        f"rate-limit floor bypassed under concurrency: {client.attempts} PUTs "
        f"reached the backend within the window (expected 1)"
    )


def test_writeback_distinct_bindings_no_corruption(tmp_path: Path) -> None:
    """Distinct bindings mutate distinct dict keys concurrently. CPython
    dict ops are individually GIL-atomic, so this must be corruption-free:
    each binding PUTs exactly once, the map ends with N live entries, and
    every store value is the rotated one. (SAFE regression guard.)"""
    n = 16
    audit = AuditWriter(str(tmp_path / "aud.jsonl"))
    resolver = OauthResolver()
    client = _CountingRotationClient({f"RT{i}": f"rtok-OLD-{i:08d}" for i in range(n)})
    barrier = threading.Barrier(n)
    errors: list[BaseException] = []

    def worker(i: int) -> None:
        try:
            barrier.wait(timeout=5)
            resolver._handle_rotation(
                client=client,  # type: ignore[arg-type]
                audit=audit,
                request_id=f"req-{i}",
                secret_name=f"BINDING{i}",
                oauth_injector=_make_injector(refresh_token_secret=f"RT{i}"),
                new_refresh_token=f"rtok-NEW-{i:08d}",
                old_refresh_token=f"rtok-OLD-{i:08d}",
            )
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert not errors, f"rotation worker raised: {errors!r}"
    assert client.attempts == n
    assert len(resolver._write_back_last) == n, "distinct-key map corrupted"
    assert {client.store[f"RT{i}"] for i in range(n)} == {f"rtok-NEW-{i:08d}" for i in range(n)}


# ===========================================================================
# Surface 5: CachingSecretsClient generation counter / flush vs get/update
# ===========================================================================


class _MutableBackend:
    """In-memory backend whose value can be rotated mid-flight."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = dict(values)
        self._lock = threading.Lock()
        self.fetch_calls = 0

    def fetch(self, name: str, ctx: FetchContext | None = None) -> Secret:
        with self._lock:
            self.fetch_calls += 1
            if name not in self._values:
                raise SecretNotFoundError(name)
            return Secret(self._values[name])

    def update(
        self,
        name: str,
        value: str,
        ctx: FetchContext | None = None,
        *,
        expected_current_value: str | None = None,
    ) -> None:
        with self._lock:
            self._values[name] = value

    def current(self, name: str) -> str:
        with self._lock:
            return self._values[name]


def test_get_and_update_secret_interleaved_no_stale_cache(tmp_path: Path) -> None:  # noqa: C901 — threaded reader/writer harness; branches are the concurrency scenario
    """Readers hammer get(name) while writers rotate the value via
    update_secret (which flushes + bumps the generation). Invariants:
      - no reader ever returns a value that was never written;
      - no reader/writer thread raises (a mid-fetch flush surfaces as a
        retriable _StaleAfterFlushError, which readers absorb + retry);
      - after quiescence the cache serves the FINAL backend value (the
        generation counter guarantees no sticky stale entry)."""
    values_written = {"v-init"}
    values_lock = threading.Lock()
    backend = _MutableBackend({"TOK": "v-init"})
    cache = CachingSecretsClient(backend, ttl_seconds=300, jitter_seconds=0)

    stop = threading.Event()
    errors: list[BaseException] = []
    err_lock = threading.Lock()

    def reader() -> None:
        try:
            while not stop.is_set():
                try:
                    v = cache.get("TOK").reveal()
                except BackendUnavailableError:
                    # _StaleAfterFlushError (flush raced our fetch) — retry.
                    continue
                with values_lock:
                    known = v in values_written
                assert known, f"reader saw a value never written: {v!r}"
        except BaseException as e:  # noqa: BLE001
            with err_lock:
                errors.append(e)

    def writer(wid: int) -> None:
        try:
            for i in range(30):
                nv = f"v-{wid}-{i}"
                with values_lock:
                    values_written.add(nv)
                cache.update_secret("TOK", nv)
                time.sleep(0.001)
        except BaseException as e:  # noqa: BLE001
            with err_lock:
                errors.append(e)

    readers = [threading.Thread(target=reader) for _ in range(6)]
    writers = [threading.Thread(target=writer, args=(w,)) for w in range(3)]
    for t in readers + writers:
        t.start()
    for t in writers:
        t.join(timeout=30)
    stop.set()
    for t in readers:
        t.join(timeout=30)

    assert not errors, f"get/update interleave raised: {errors!r}"
    # No sticky stale entry: post-quiescence read equals the live backend.
    final = cache.get("TOK").reveal()
    assert final == backend.current("TOK")


def test_concurrent_distinct_keys_lru_no_corruption() -> None:
    """Many threads fetch many distinct keys against a small max_entries,
    driving constant LRU eviction (OrderedDict popitem/move_to_end) under
    contention. Assert every value is correct and the cache never exceeds
    its bound (no corruption of the OrderedDict)."""
    n_keys = 200
    backend = _MutableBackend({f"K{i}": f"val-{i}" for i in range(n_keys)})
    cache = CachingSecretsClient(backend, ttl_seconds=300, jitter_seconds=0, max_entries=16)
    errors: list[BaseException] = []
    err_lock = threading.Lock()

    def worker(seed: int) -> None:
        try:
            for r in range(300):
                i = (seed * 7 + r * 13) % n_keys
                assert cache.get(f"K{i}").reveal() == f"val-{i}"
        except BaseException as e:  # noqa: BLE001
            with err_lock:
                errors.append(e)

    with ThreadPoolExecutor(max_workers=12) as ex:
        list(ex.map(worker, range(12)))

    assert not errors, f"LRU-under-load raised: {errors!r}"
    # The bound is a hard invariant regardless of interleaving.
    assert len(cache._cache) <= cache.max_entries
