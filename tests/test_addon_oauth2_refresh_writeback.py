"""Refresh-token write-back tests (ADR-0017 slice 7).

If an upstream rotates the refresh token and we don't persist the new
value, the next exchange reads the STALE refresh token from BWS and the
binding silently locks out. Write-back closes that loop. Tests pin the
per-outcome audit shape and verify the access token is still served on
best-effort write-back failure (killing the request when we already hold
a valid access token would be hostile UX). The vault-cache invalidation
invariant (a successful write-back also calls
``client.flush(refresh_token_secret)``) is verified — otherwise the next
read inside the TTL window would return the cached stale value."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest

from kow.addon import AgentVaultProxyAddon
from kow.audit import AuditWriter
from kow.backends import BackendWriteConflictError
from kow.caching import CachingSecretsClient
from kow.config import Oauth2RefreshInjector
from kow.injectors.oauth2_refresh import OauthResolver
from tests import _oauth_helpers as oh
from tests._oauth_helpers import (
    PLACEHOLDER,
    FakeBackend,
    FakeResp,
    ReadOnlyBackend,
    UpdateFailsBackend,
)


@pytest.fixture(autouse=True)
def stub_ssrf_dns(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    oh.apply_public_ssrf_stub(monkeypatch)
    yield


def _build_addon(
    tmp_path: Path,
    backend: object,
    write_back: bool = True,
) -> tuple[AgentVaultProxyAddon, Path, CachingSecretsClient]:
    return oh.build_oauth_addon(tmp_path, backend=backend, write_back=write_back)


def _rotation_response_body(new_rt: str = "rtok-NEW") -> bytes:
    return oh.rotation_body(refresh_token=new_rt)


def _no_rotation_response_body(echoed_rt: str = "rtok-real") -> bytes:
    return oh.rotation_body(refresh_token=echoed_rt)


def _no_refresh_field_response_body() -> bytes:
    return json.dumps({"access_token": "at-FRESH", "expires_in": 3600}).encode()


_VAULT = {
    "GOOGLE_OAUTH_CLIENT_ID": "cid-real",
    "GOOGLE_OAUTH_CLIENT_SECRET": "csec-real",
    "GOOGLE_OAUTH_REFRESH_TOKEN": "rtok-real",
}


# ---------------------------------------------------------------------------
# Rotation + write-back SUCCESS
# ---------------------------------------------------------------------------


def test_rotation_writes_new_refresh_token_back_and_audits(tmp_path: Path) -> None:
    backend = FakeBackend(_VAULT)
    addon, audit_path, client = _build_addon(tmp_path, backend)

    flow = oh.make_request("www.googleapis.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    with patch(
        "kow.injectors.oauth2_refresh._transport_open",
        return_value=FakeResp(_rotation_response_body()),
    ):
        addon.requestheaders(flow)

    # Access token still served.
    assert flow.request.headers["Authorization"] == "Bearer at-FRESH"
    # The new refresh token was written back through the backend.
    assert backend.updates == [("GOOGLE_OAUTH_REFRESH_TOKEN", "rtok-NEW")]
    # Audit carries the rotation event with success outcome.
    events = oh.read_audit(audit_path)
    rot = [e for e in events if e["type"] == "refresh_token_rotated"]
    # Hardening series: ``pending`` is fsynced BEFORE the PUT, then the
    # final outcome — a crash mid-write leaves the pending record alone.
    assert [e["outcome"] for e in rot] == ["pending", "success"]
    assert rot[-1]["binding_name"] == "GOOGLE_OAUTH"
    assert rot[-1]["refresh_token_secret"] == "GOOGLE_OAUTH_REFRESH_TOKEN"
    # No secret material in audit (either record).
    serialised = json.dumps(rot)
    assert "rtok-NEW" not in serialised
    assert "rtok-real" not in serialised


def test_rotation_event_ordering_after_token_exchange_before_inject(tmp_path: Path) -> None:
    """refresh_token_rotated must come AFTER token_exchange (the
    exchange supplied the new token) and BEFORE inject_decision (it
    fires under the same G6 audit-before-action invariant as the
    other oauth events)."""
    addon, audit_path, _client = _build_addon(tmp_path, FakeBackend(_VAULT))
    flow = oh.make_request("www.googleapis.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    with patch(
        "kow.injectors.oauth2_refresh._transport_open",
        return_value=FakeResp(_rotation_response_body()),
    ):
        addon.requestheaders(flow)
    events = oh.read_audit(audit_path)
    relevant = ("token_exchange", "refresh_token_rotated", "inject_decision")
    types = [e["type"] for e in events if e["type"] in relevant]
    # Two rotated records (pending + final) sit between exchange and inject.
    assert types == [
        "token_exchange",
        "refresh_token_rotated",
        "refresh_token_rotated",
        "inject_decision",
    ]


def test_rotation_flushes_vault_cache_for_refresh_token(tmp_path: Path) -> None:
    """After write-back succeeds, the cached vault read of
    refresh_token_secret MUST be invalidated. Otherwise the next
    access-token expiry within ``ttl_seconds`` would re-use the stale
    cached value and re-derive a token from a refresh-token the
    upstream just invalidated."""
    backend = FakeBackend(_VAULT)
    addon, _audit_path, client = _build_addon(tmp_path, backend)

    flow = oh.make_request("www.googleapis.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    with patch(
        "kow.injectors.oauth2_refresh._transport_open",
        return_value=FakeResp(_rotation_response_body()),
    ):
        addon.requestheaders(flow)

    # The first request fetched the refresh-token; reading it again
    # right after write-back MUST round-trip to the backend (cache
    # entry invalidated), not return a cached value.
    fetches_before_re_read = len(backend.fetches)
    value = client.get("GOOGLE_OAUTH_REFRESH_TOKEN").reveal()
    assert value == "rtok-NEW"  # backend now holds the rotated value
    assert len(backend.fetches) == fetches_before_re_read + 1


# ---------------------------------------------------------------------------
# Rotation + write-back FAILURE — best-effort: still serve the access token
# ---------------------------------------------------------------------------


def test_writeback_failure_still_serves_access_token(tmp_path: Path) -> None:
    """Killing the request when we already hold a valid access token
    would be hostile UX. The new refresh token will be lost (audit is
    the signal); the current request still succeeds."""
    backend = UpdateFailsBackend(_VAULT)
    addon, audit_path, _client = _build_addon(tmp_path, backend)

    flow = oh.make_request("www.googleapis.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    with patch(
        "kow.injectors.oauth2_refresh._transport_open",
        return_value=FakeResp(_rotation_response_body()),
    ):
        addon.requestheaders(flow)

    # Header still rewritten with the exchanged access token.
    assert flow.request.headers["Authorization"] == "Bearer at-FRESH"
    # No response set (request continues upstream).
    assert flow.response is None

    events = oh.read_audit(audit_path)
    rot = [e for e in events if e["type"] == "refresh_token_rotated"]
    assert [e["outcome"] for e in rot] == ["pending", "write_back_failed"]
    assert rot[-1]["error_type"] == "BackendUnavailableError"


def test_writeback_unavailable_when_backend_readonly(tmp_path: Path) -> None:
    """Read-only backends (no ``update`` method) get the distinct
    ``write_back_unavailable`` outcome — an operator-actionable
    configuration error, not a transient vault outage."""
    backend = ReadOnlyBackend(_VAULT)
    addon, audit_path, _client = _build_addon(tmp_path, backend)

    flow = oh.make_request("www.googleapis.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    with patch(
        "kow.injectors.oauth2_refresh._transport_open",
        return_value=FakeResp(_rotation_response_body()),
    ):
        addon.requestheaders(flow)

    # Header still served — the upstream issued the new access token
    # and the operator should not be punished for a transient outage.
    assert flow.request.headers["Authorization"] == "Bearer at-FRESH"
    events = oh.read_audit(audit_path)
    rot = [e for e in events if e["type"] == "refresh_token_rotated"]
    # Dispatch discovers non-writability only at PUT time — inside the
    # write window — so the pending record precedes it.
    assert [e["outcome"] for e in rot] == ["pending", "write_back_unavailable"]
    assert rot[-1]["error_type"] == "BackendNotWritableError"


# ---------------------------------------------------------------------------
# Rotation with write-back DISABLED — operator opt-out, audit explicitly
# ---------------------------------------------------------------------------


def test_writeback_disabled_skips_update_and_audits_distinct_outcome(tmp_path: Path) -> None:
    backend = FakeBackend(_VAULT)
    addon, audit_path, _client = _build_addon(tmp_path, backend, write_back=False)

    flow = oh.make_request("www.googleapis.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    with patch(
        "kow.injectors.oauth2_refresh._transport_open",
        return_value=FakeResp(_rotation_response_body()),
    ):
        addon.requestheaders(flow)

    # No update call.
    assert backend.updates == []
    # Access token still served.
    assert flow.request.headers["Authorization"] == "Bearer at-FRESH"
    events = oh.read_audit(audit_path)
    rot = next(e for e in events if e["type"] == "refresh_token_rotated")
    assert rot["outcome"] == "write_back_disabled"


# ---------------------------------------------------------------------------
# NO rotation — no refresh_token_rotated audit at all
# ---------------------------------------------------------------------------


def test_no_rotation_when_upstream_echoes_same_refresh_token(tmp_path: Path) -> None:
    """RFC 6749 §6 allows the upstream to echo back the same refresh
    token. That is NOT a rotation; we must not write-back nor emit
    the rotation audit."""
    backend = FakeBackend(_VAULT)
    addon, audit_path, _client = _build_addon(tmp_path, backend)

    flow = oh.make_request("www.googleapis.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    with patch(
        "kow.injectors.oauth2_refresh._transport_open",
        return_value=FakeResp(_no_rotation_response_body(echoed_rt="rtok-real")),
    ):
        addon.requestheaders(flow)

    assert backend.updates == []
    events = oh.read_audit(audit_path)
    assert not any(e["type"] == "refresh_token_rotated" for e in events)


def test_no_rotation_when_upstream_omits_refresh_token_field(tmp_path: Path) -> None:
    """Many providers (e.g. Google for typical flows) omit
    ``refresh_token`` from the response unless they actually rotated.
    No field = no rotation event."""
    backend = FakeBackend(_VAULT)
    addon, audit_path, _client = _build_addon(tmp_path, backend)

    flow = oh.make_request("www.googleapis.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    with patch(
        "kow.injectors.oauth2_refresh._transport_open",
        return_value=FakeResp(_no_refresh_field_response_body()),
    ):
        addon.requestheaders(flow)

    assert backend.updates == []
    events = oh.read_audit(audit_path)
    assert not any(e["type"] == "refresh_token_rotated" for e in events)


# ---------------------------------------------------------------------------
# Malformed upstream refresh token — vault-poisoning defense (Oracle F1 / Silas #2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "junk_token",
    [
        "x",  # too short (single byte)
        "ab" * 4097,  # too long (>4096 bytes)
        "valid-prefix\x00with-null",  # control character
        "tab\there",  # tab
        "newline\ntoken",  # newline
        "non-ascii-ü-token-padding",  # non-ASCII
    ],
)
def test_malformed_rotated_token_rejected_no_writeback(tmp_path: Path, junk_token: str) -> None:
    """A compromised or MITM'd token endpoint could otherwise PUT
    arbitrary junk into BWS and permanently brick the binding (no
    live backup of the prior refresh_token exists). The shape guard
    rejects the rotation, audits ``write_back_rejected_malformed``,
    and STILL serves the access token for this request."""
    backend = FakeBackend(_VAULT)
    addon, audit_path, _client = _build_addon(tmp_path, backend)

    flow = oh.make_request("www.googleapis.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    body = json.dumps(
        {"access_token": "at-FRESH", "expires_in": 3600, "refresh_token": junk_token}
    ).encode()
    with patch("kow.injectors.oauth2_refresh._transport_open", return_value=FakeResp(body)):
        addon.requestheaders(flow)

    # Vault was NOT mutated — the prior refresh token survives.
    assert backend.updates == []
    assert backend._values["GOOGLE_OAUTH_REFRESH_TOKEN"] == "rtok-real"
    # Access token still served on this request.
    assert flow.request.headers["Authorization"] == "Bearer at-FRESH"
    events = oh.read_audit(audit_path)
    rot = next(e for e in events if e["type"] == "refresh_token_rotated")
    assert rot["outcome"] == "write_back_rejected_malformed"
    assert rot["error_type"] == "malformed_refresh_token"
    # No secret material — neither old nor junk token bytes leak.
    serialised = json.dumps(rot)
    assert "rtok-real" not in serialised
    if len(junk_token) >= 4:
        assert junk_token not in serialised


# ---------------------------------------------------------------------------
# Cache hit path — write-back already happened during the miss, hits skip
# ---------------------------------------------------------------------------


def test_cache_hit_does_not_re_writeback(tmp_path: Path) -> None:
    """After the first request rotates + writes back, the second
    request hits the derived-token cache. No second exchange => no
    second write-back, no second refresh_token_rotated audit."""
    backend = FakeBackend(_VAULT)
    addon, audit_path, _client = _build_addon(tmp_path, backend)

    with patch(
        "kow.injectors.oauth2_refresh._transport_open",
        return_value=FakeResp(_rotation_response_body()),
    ):
        for _ in range(2):
            flow = oh.make_request("www.googleapis.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
            addon.http_connect(flow)
            addon.requestheaders(flow)

    assert backend.updates == [("GOOGLE_OAUTH_REFRESH_TOKEN", "rtok-NEW")]
    events = oh.read_audit(audit_path)
    # One rotation → one pending/success pair; the cache-hit second
    # request contributes NO rotated events at all.
    rot = [e["outcome"] for e in events if e["type"] == "refresh_token_rotated"]
    assert rot == ["pending", "success"]


# ---------------------------------------------------------------------------
# Hardening series: pending-before-PUT ordering, per-binding rate limit,
# vault-conflict precondition — exercised via _handle_rotation directly.
# ---------------------------------------------------------------------------


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


class _DirectClient:
    """Duck-typed CachingSecretsClient for _handle_rotation: only
    update_secret is exercised. Mirrors the value-precondition."""

    def __init__(self, store: dict[str, str]) -> None:
        self.store = store
        self.writes: list[tuple[str, str]] = []
        self.audit_outcomes_at_write: list[list[str]] = []
        self._audit_path: str | None = None

    def observe_audit(self, path: str) -> None:
        self._audit_path = path

    def update_secret(
        self,
        name: str,
        value: str,
        ctx: object = None,
        *,
        expected_current_value: str | None = None,
    ) -> None:
        if self._audit_path is not None:
            events = oh.read_audit(Path(self._audit_path))
            self.audit_outcomes_at_write.append(
                [e["outcome"] for e in events if e["type"] == "refresh_token_rotated"]
            )
        if expected_current_value is not None and self.store.get(name) != expected_current_value:
            raise BackendWriteConflictError(f"secret {name!r} changed since read")
        self.writes.append((name, value))
        self.store[name] = value


def _rotate(
    resolver: OauthResolver,
    client: _DirectClient,
    audit: AuditWriter,
    *,
    new: str,
    old: str,
    injector: Oauth2RefreshInjector | None = None,
) -> None:
    resolver._handle_rotation(
        client=client,  # type: ignore[arg-type]
        audit=audit,
        request_id="req-direct",
        secret_name="BINDING",
        oauth_injector=injector or _make_injector(),
        new_refresh_token=new,
        old_refresh_token=old,
    )


def _rot_outcomes(audit_path: Path) -> list[str]:
    return [e["outcome"] for e in oh.read_audit(audit_path) if e["type"] == "refresh_token_rotated"]


def test_pending_is_on_disk_before_backend_put(tmp_path: Path) -> None:
    """At the moment the backend PUT runs, the fsynced audit stream must
    already contain the pending record — the crash-window guarantee, not
    just event ordering in the final file."""
    audit_path = tmp_path / "aud.jsonl"
    audit = AuditWriter(str(audit_path))
    client = _DirectClient({"RT": "rtok-OLD-12345678"})
    client.observe_audit(str(audit_path))
    _rotate(OauthResolver(), client, audit, new="rtok-NEW-12345678", old="rtok-OLD-12345678")
    assert client.audit_outcomes_at_write == [["pending"]]
    assert _rot_outcomes(audit_path) == ["pending", "success"]


def test_second_rotation_within_interval_is_rate_limited(tmp_path: Path) -> None:
    """Default 60 s floor: a forced-rotation storm gets ONE vault PUT;
    the second rotation audits a single write_back_rate_limited record
    (no pending — the write window is never entered)."""
    audit_path = tmp_path / "aud.jsonl"
    audit = AuditWriter(str(audit_path))
    client = _DirectClient({"RT": "rtok-A-12345678"})
    resolver = OauthResolver()
    _rotate(resolver, client, audit, new="rtok-B-12345678", old="rtok-A-12345678")
    _rotate(resolver, client, audit, new="rtok-C-12345678", old="rtok-B-12345678")
    assert [w[1] for w in client.writes] == ["rtok-B-12345678"]
    assert _rot_outcomes(audit_path) == ["pending", "success", "write_back_rate_limited"]


def test_zero_interval_disables_rate_limit(tmp_path: Path) -> None:
    audit_path = tmp_path / "aud.jsonl"
    audit = AuditWriter(str(audit_path))
    client = _DirectClient({"RT": "rtok-A-12345678"})
    resolver = OauthResolver()
    injector = _make_injector(write_back_min_interval_seconds=0)
    _rotate(
        resolver, client, audit, new="rtok-B-12345678", old="rtok-A-12345678", injector=injector
    )
    _rotate(
        resolver, client, audit, new="rtok-C-12345678", old="rtok-B-12345678", injector=injector
    )
    assert [w[1] for w in client.writes] == ["rtok-B-12345678", "rtok-C-12345678"]
    assert _rot_outcomes(audit_path) == ["pending", "success", "pending", "success"]


def test_operator_side_rotation_conflict_refuses_overwrite(tmp_path: Path) -> None:
    """Vault holds a value the exchange never saw (operator rotated
    manually mid-flight): the write is refused, the operator's value
    survives, and the audit says write_back_conflict."""
    audit_path = tmp_path / "aud.jsonl"
    audit = AuditWriter(str(audit_path))
    client = _DirectClient({"RT": "rtok-OPERATOR-NEW-99"})
    _rotate(OauthResolver(), client, audit, new="rtok-DERIVED-12345678", old="rtok-STALE-12345678")
    assert client.writes == []
    assert client.store["RT"] == "rtok-OPERATOR-NEW-99"
    events = oh.read_audit(audit_path)
    rot = [e for e in events if e["type"] == "refresh_token_rotated"]
    assert [e["outcome"] for e in rot] == ["pending", "write_back_conflict"]
    assert rot[-1]["error_type"] == "BackendWriteConflictError"
    serialised = json.dumps(rot)
    assert "rtok-OPERATOR-NEW-99" not in serialised
    assert "rtok-DERIVED-12345678" not in serialised
