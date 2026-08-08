"""fetch_with_meta(name, ctx) -> (value, note) contract tests (ADR-0011 item 1).

The BWS-notes binding path needs the secret's note alongside its value.
Extending the protocol with a new REQUIRED method would break every other
backend (static, plus any third-party adapter). Instead the protocol gains
an OPTIONAL method with a default that returns ``(fetch(...), None)`` — so
backends with no notes concept keep working unchanged, and only bws.py
implements the real thing.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

from kow.backends import fetch_with_meta
from kow.backends.bws import BitwardenBackend
from kow.backends.static import StaticSecretsBackend, StaticSecretsConfig


def _mock_sdk_client(secrets: dict[str, tuple[str, str | None]]) -> MagicMock:
    """`secrets` maps name -> (value, note). note=None means the BWS field is
    absent; the SDK surfaces that as None."""
    sdk = MagicMock()
    list_data = SimpleNamespace(
        data=SimpleNamespace(data=[SimpleNamespace(id=f"id-{name}", key=name) for name in secrets])
    )
    sdk.secrets.return_value.list.return_value = list_data

    def fake_get(secret_id: str) -> SimpleNamespace:
        for name, (value, note) in secrets.items():
            if secret_id == f"id-{name}":
                return SimpleNamespace(data=SimpleNamespace(value=value, note=note))
        raise RuntimeError(f"unknown secret id: {secret_id}")

    sdk.secrets.return_value.get.side_effect = fake_get
    return sdk


def test_static_backend_returns_none_note_via_helper(tmp_path: Path) -> None:
    """A backend with no notes concept (static) returns (value, None) through
    the module-level default helper — the parity floor for item 1."""
    p = tmp_path / "secrets.yml"
    p.write_text("secrets:\n  K: v\n")
    p.chmod(0o600)
    backend = StaticSecretsBackend(config=StaticSecretsConfig(type="static", path=str(p)))
    assert fetch_with_meta(backend, "K") == ("v", None)


def test_bws_backend_returns_value_and_note() -> None:
    sdk = _mock_sdk_client({"FOO": ("real-value", "host: api.example.com")})
    backend = BitwardenBackend(sdk_client=sdk, organization_id="org-1")
    value, note = backend.fetch_with_meta("FOO")
    assert value == "real-value"
    assert note == "host: api.example.com"


def test_bws_backend_empty_note_becomes_none() -> None:
    """An empty-string note is normalised to None — 'no binding', not a
    malformed one. (ADR amendment: empty notes != malformed.)"""
    sdk = _mock_sdk_client({"FOO": ("real-value", "")})
    backend = BitwardenBackend(sdk_client=sdk, organization_id="org-1")
    value, note = backend.fetch_with_meta("FOO")
    assert value == "real-value"
    assert note is None


def test_bws_backend_whitespace_only_note_becomes_none() -> None:
    sdk = _mock_sdk_client({"FOO": ("real-value", "   \n\t ")})
    backend = BitwardenBackend(sdk_client=sdk, organization_id="org-1")
    _value, note = backend.fetch_with_meta("FOO")
    assert note is None


def test_bws_backend_missing_note_field_becomes_none() -> None:
    """If the SDK object has no .note attribute at all, treat as no note."""
    sdk = MagicMock()
    list_data = SimpleNamespace(
        data=SimpleNamespace(data=[SimpleNamespace(id="id-FOO", key="FOO")])
    )
    sdk.secrets.return_value.list.return_value = list_data
    sdk.secrets.return_value.get.return_value = SimpleNamespace(
        data=SimpleNamespace(value="real-value")  # no .note
    )
    backend = BitwardenBackend(sdk_client=sdk, organization_id="org-1")
    _value, note = backend.fetch_with_meta("FOO")
    assert note is None


def test_bws_fetch_still_returns_only_value() -> None:
    """The legacy fetch() path is unchanged — value only, no behavior drift."""
    sdk = _mock_sdk_client({"FOO": ("real-value", "host: api.example.com")})
    backend = BitwardenBackend(sdk_client=sdk, organization_id="org-1")
    assert backend.fetch("FOO") == "real-value"


def test_fetch_with_meta_helper_prefers_backend_method() -> None:
    """The module-level helper uses a backend's own fetch_with_meta when it
    has one (bws), and falls back to (fetch(), None) when it doesn't."""
    sdk = _mock_sdk_client({"FOO": ("real-value", "host: api.example.com")})
    backend = BitwardenBackend(sdk_client=sdk, organization_id="org-1")
    assert fetch_with_meta(backend, "FOO") == ("real-value", "host: api.example.com")
