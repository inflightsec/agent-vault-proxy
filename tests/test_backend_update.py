"""Tests for the ``SecretsBackend.update`` Protocol extension
(ADR-0017 slice 3).

The OAuth2 refresh-token write-back path needs to persist a rotated
refresh token back to the vault. The Protocol grows an *optional*
``update`` method (same opt-in shape as ``fetch_with_meta``) and a
module-level dispatch helper that falls back to raising
:class:`BackendNotWritableError` for read-only backends.

Slice 3 covers the Protocol surface and the BWS adapter. The runtime
write-back call site lands in slice 7.
"""

from __future__ import annotations

from typing import Any

import pytest

from kow.backends import (
    BackendNotWritableError,
    BackendUnavailableError,
    BackendWriteConflictError,
    FetchContext,
    SecretNotFoundError,
    update_secret,
)
from kow.backends.bws import BitwardenBackend
from kow.backends.static import StaticSecretsBackend
from kow.secret import Secret

# ---------------------------------------------------------------------------
# Dispatch helper — read-only fallback + writable forwarding
# ---------------------------------------------------------------------------


class _WritableFake:
    """Minimal writable backend recording the last update call."""

    def __init__(self, store: dict[str, str]) -> None:
        self._store = store
        self.last_update: tuple[str, str, FetchContext | None] | None = None

    def fetch(self, name: str, ctx: FetchContext | None = None) -> Secret:
        return Secret(self._store[name])

    def update(self, name: str, value: str, ctx: FetchContext | None = None) -> None:
        self.last_update = (name, value, ctx)
        self._store[name] = value


class _ReadOnlyFake:
    """A backend that does not implement ``update`` at all."""

    def __init__(self, store: dict[str, str]) -> None:
        self._store = store

    def fetch(self, name: str, ctx: FetchContext | None = None) -> Secret:
        return Secret(self._store[name])


def test_update_secret_dispatches_to_backend_when_present() -> None:
    """If the backend has an ``update`` method, the helper forwards
    every argument verbatim. No silent coercion of value or ctx."""
    backend = _WritableFake({"FOO": "v1"})
    ctx = FetchContext(request_id="req-A")
    update_secret(backend, "FOO", "v2", ctx)
    assert backend.last_update == ("FOO", "v2", ctx)
    assert backend.fetch("FOO").reveal() == "v2"


def test_update_secret_raises_for_read_only_backend() -> None:
    """A backend without ``update`` is read-only. The helper raises
    :class:`BackendNotWritableError`, which subclasses
    :class:`BackendUnavailableError` so the existing fail-closed
    catch-all in the addon still does the right thing."""
    backend = _ReadOnlyFake({"FOO": "v1"})
    with pytest.raises(BackendNotWritableError):
        update_secret(backend, "FOO", "v2")


def test_backend_not_writable_subclasses_backend_unavailable() -> None:
    """The exception hierarchy is the contract. Slice 7's write-back
    audit path catches ``BackendUnavailableError`` for the
    ``write_back_unavailable`` outcome; if the subclass relationship
    breaks, the audit branch silently flips. Pin it."""
    assert issubclass(BackendNotWritableError, BackendUnavailableError)


# ---------------------------------------------------------------------------
# BWS adapter — preserves notes + project_ids, surfaces SDK errors cleanly
# ---------------------------------------------------------------------------


class _FakeSecretsClient:
    """Minimal SDK double — implements ``get`` (used to read note/
    project_ids before update) and ``update``."""

    def __init__(self, secret: dict[str, Any]) -> None:
        # secret has: id, key, value, note, project_ids
        self._secret = secret
        self.last_update_args: tuple | None = None

    def get(self, secret_id: str) -> Any:
        if secret_id != self._secret["id"]:
            raise RuntimeError(f"unknown id {secret_id}")
        return _Response(self._secret)

    def update(
        self,
        org_id: str,
        secret_id: str,
        key: str,
        value: str,
        note: str | None,
        project_ids: list | None = None,
    ) -> Any:
        self.last_update_args = (org_id, secret_id, key, value, note, project_ids)
        self._secret["value"] = value
        # Preserve note + project_ids per the contract the adapter
        # enforces. If the adapter ever passes None for these, this
        # double catches it.
        return _Response(self._secret)


class _Response:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = _Data(data)


class _Data:
    def __init__(self, data: dict[str, Any]) -> None:
        self.value = data["value"]
        self.note = data.get("note")
        self.project_ids = data.get("project_ids")
        self.key = data.get("key")


class _FakeBitwardenClient:
    def __init__(self, secrets_client: _FakeSecretsClient) -> None:
        self._secrets = secrets_client

    def secrets(self) -> _FakeSecretsClient:
        return self._secrets


@pytest.fixture
def bws_with_one_secret() -> tuple[BitwardenBackend, _FakeSecretsClient]:
    """Pre-loaded BWS adapter with name→id map populated, one secret."""
    sec = {
        "id": "id-FOO",
        "key": "FOO",
        "value": "v1",
        "note": "binding-yaml-blob",
        "project_ids": ["proj-1"],
    }
    sdk_secrets = _FakeSecretsClient(sec)
    sdk_client = _FakeBitwardenClient(sdk_secrets)
    backend = BitwardenBackend(sdk_client=sdk_client, organization_id="org-X")
    # Prime the name→id map directly so the test doesn't need to
    # exercise list-all from the SDK double.
    backend._name_to_id = {"FOO": "id-FOO"}  # type: ignore[attr-defined]
    return backend, sdk_secrets


def test_bws_update_preserves_note_and_project_ids(
    bws_with_one_secret: tuple[BitwardenBackend, _FakeSecretsClient],
) -> None:
    """Blanking the note on every refresh-token rotation would lose
    binding metadata. The adapter MUST GET the current secret, capture
    note + project_ids, and pass them through verbatim on PUT."""
    backend, sdk = bws_with_one_secret
    update_secret(backend, "FOO", "v2-rotated")
    org_id, sid, key, value, note, project_ids = sdk.last_update_args  # type: ignore[misc]
    assert org_id == "org-X"
    assert sid == "id-FOO"
    assert key == "FOO"
    assert value == "v2-rotated"
    assert note == "binding-yaml-blob"  # preserved
    assert project_ids == ["proj-1"]  # preserved


def test_bws_update_raises_secret_not_found_for_unknown_name(
    bws_with_one_secret: tuple[BitwardenBackend, _FakeSecretsClient],
) -> None:
    backend, _sdk = bws_with_one_secret
    with pytest.raises(SecretNotFoundError):
        update_secret(backend, "DOES_NOT_EXIST", "v2")


def test_bws_update_wraps_sdk_exception_as_backend_unavailable(
    bws_with_one_secret: tuple[BitwardenBackend, _FakeSecretsClient],
) -> None:
    """SDK exceptions (network, auth, anything) bubble up as
    :class:`BackendUnavailableError` so the addon's existing fail-
    closed catch-all handles them the same way fetch failures already
    do. Distinct from :class:`SecretNotFoundError`."""
    backend, sdk = bws_with_one_secret

    def boom(*_args: object, **_kw: object) -> None:
        raise RuntimeError("network down")

    sdk.update = boom  # type: ignore[assignment]
    with pytest.raises(BackendUnavailableError):
        update_secret(backend, "FOO", "v2")


# ---------------------------------------------------------------------------
# Static backend — confirmed read-only via the dispatch helper
# ---------------------------------------------------------------------------


def test_static_backend_is_not_writable() -> None:
    """The test-fixture static backend is intentionally read-only.
    Confirm the helper hits the not-writable fallback for it — a
    regression that silently added an ``update`` method to
    ``StaticSecretsBackend`` would make test bindings appear writable
    in unit tests while real BWS paths still fail."""
    backend = StaticSecretsBackend(secrets={"FOO": "v1"})
    with pytest.raises(BackendNotWritableError):
        update_secret(backend, "FOO", "v2")


# ---------------------------------------------------------------------------
# Value-precondition (ADR-0017 hardening series — revision item, value variant)
# ---------------------------------------------------------------------------


def test_bws_update_conflict_when_vault_value_changed(
    bws_with_one_secret: tuple[BitwardenBackend, _FakeSecretsClient],
) -> None:
    """The caller states what it READ; the vault holds something else
    (operator rotated manually mid-flight). The PUT must be refused so
    the operator's newer secret survives — and the error message must
    carry no secret material."""
    backend, sdk = bws_with_one_secret
    with pytest.raises(BackendWriteConflictError) as excinfo:
        update_secret(
            backend,
            "FOO",
            "v2-derived-from-stale",
            expected_current_value="stale-value-the-caller-read",
        )
    assert sdk.last_update_args is None  # PUT never issued
    msg = str(excinfo.value)
    assert "v1" not in msg
    assert "stale-value-the-caller-read" not in msg
    assert "v2-derived-from-stale" not in msg


def test_bws_update_succeeds_when_precondition_matches(
    bws_with_one_secret: tuple[BitwardenBackend, _FakeSecretsClient],
) -> None:
    backend, sdk = bws_with_one_secret
    update_secret(backend, "FOO", "v2-rotated", expected_current_value="v1")
    assert sdk.last_update_args is not None
    assert sdk.last_update_args[3] == "v2-rotated"


def test_bws_update_without_precondition_never_conflicts(
    bws_with_one_secret: tuple[BitwardenBackend, _FakeSecretsClient],
) -> None:
    """Omitting the precondition preserves the pre-hardening contract:
    the adapter writes unconditionally (metadata-preserving GET+PUT)."""
    backend, sdk = bws_with_one_secret
    update_secret(backend, "FOO", "v3-unconditional")
    assert sdk.last_update_args is not None
