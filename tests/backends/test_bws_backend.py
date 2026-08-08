"""BitwardenBackend tests — BWS-specific behavior.

The caching/TTL/jitter/LRU tests live in tests/test_caching.py with a
FakeBackend. This file tests the BWS-side concerns: name→id resolution,
auth lifecycle, exception translation, repr safety.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from kow.backends import (
    BackendUnavailableError,
    SecretNotFoundError,
)
from kow.backends.bws import BitwardenBackend, BwsConfig
from tests.backends.test_protocol_contract import ProtocolContract


def _mock_sdk_client(secrets: dict[str, str]) -> MagicMock:
    sdk = MagicMock()
    list_data = SimpleNamespace(
        data=SimpleNamespace(data=[SimpleNamespace(id=f"id-{name}", key=name) for name in secrets])
    )
    sdk.secrets.return_value.list.return_value = list_data

    def fake_get(secret_id: str) -> SimpleNamespace:
        for name, value in secrets.items():
            if secret_id == f"id-{name}":
                return SimpleNamespace(data=SimpleNamespace(value=value))
        raise RuntimeError(f"unknown secret id: {secret_id}")

    sdk.secrets.return_value.get.side_effect = fake_get
    return sdk


class TestBitwardenBackendContract(ProtocolContract):
    """BWS satisfies the cross-backend contract suite."""

    @pytest.fixture
    def backend(self) -> BitwardenBackend:
        sdk = _mock_sdk_client({"FOO": "bar"})
        return BitwardenBackend(sdk_client=sdk, organization_id="org-1")


def test_fetch_returns_value_from_sdk() -> None:
    sdk = _mock_sdk_client({"ANTHROPIC_API_KEY": "real-anthropic-secret"})
    backend = BitwardenBackend(sdk_client=sdk, organization_id="org-1")
    assert backend.fetch("ANTHROPIC_API_KEY") == "real-anthropic-secret"


def test_fetch_raises_secret_not_found_for_missing_name() -> None:
    sdk = _mock_sdk_client({"OTHER_KEY": "value"})
    backend = BitwardenBackend(sdk_client=sdk, organization_id="org-1")
    with pytest.raises(SecretNotFoundError):
        backend.fetch("ANTHROPIC_API_KEY")


def test_fetch_raises_unavailable_when_list_fails() -> None:
    sdk = MagicMock()
    sdk.secrets.return_value.list.side_effect = RuntimeError("network down")
    backend = BitwardenBackend(sdk_client=sdk, organization_id="org-1")
    with pytest.raises(BackendUnavailableError, match="list failed"):
        backend.fetch("ANY")


def test_fetch_raises_unavailable_when_get_fails() -> None:
    sdk = _mock_sdk_client({"ANTHROPIC_API_KEY": "value"})
    sdk.secrets.return_value.get.side_effect = RuntimeError("upstream 500")
    backend = BitwardenBackend(sdk_client=sdk, organization_id="org-1")
    with pytest.raises(BackendUnavailableError, match="get failed"):
        backend.fetch("ANTHROPIC_API_KEY")


def test_flush_name_map_forces_relist() -> None:
    sdk = _mock_sdk_client({"FOO": "v1"})
    backend = BitwardenBackend(sdk_client=sdk, organization_id="org-1")
    backend.fetch("FOO")
    backend.flush_name_map()
    backend.fetch("FOO")
    # Without flush, list() runs once; with flush in between, twice.
    assert sdk.secrets.return_value.list.call_count == 2


def test_repr_does_not_include_organization_id() -> None:
    """Belt-and-suspenders: even the org_id (not a secret per se) should
    not appear in repr — keeps log output free of identifiers that could
    aid an attacker in correlating leaked tracebacks."""
    sdk = _mock_sdk_client({})
    backend = BitwardenBackend(sdk_client=sdk, organization_id="org-abc-123-secret-id")
    assert "org-abc-123-secret-id" not in repr(backend)


def test_unconfigured_backend_raises_not_implemented() -> None:
    """Constructing with no sdk_client AND no config is a programmer
    error — surfaces immediately rather than silently no-op."""
    backend = BitwardenBackend()
    with pytest.raises(NotImplementedError):
        backend.fetch("ANY")


def test_bws_config_rejects_unknown_fields() -> None:
    """extra=forbid catches typos at startup."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        BwsConfig.model_validate({"organization_id": "org-1", "typo_field": "oops"})


def test_bws_config_defaults_to_us_cloud() -> None:
    """Default URLs target the US Bitwarden cloud."""
    cfg = BwsConfig.model_validate({"organization_id": "org-1"})
    assert cfg.api_url == "https://api.bitwarden.com"
    assert cfg.identity_url == "https://identity.bitwarden.com"


def test_bws_config_type_discriminator_is_bws() -> None:
    cfg = BwsConfig.model_validate({"organization_id": "org-1"})
    assert cfg.type == "bws"


def test_auth_failure_does_not_leak_sdk_exception_text(monkeypatch, tmp_path) -> None:
    """the BitwardenClient SDK's auth exceptions may include
    Authorization headers, request bodies, or token bytes in their str().
    Our wrapper must NOT interpolate `{e}` and must NOT chain via `from e`
    — both would surface the sensitive content into tracebacks/logs."""
    import sys
    from types import ModuleType

    sentinel = "SECRET-BEARER-abc.eyJ.def"

    fake_module = ModuleType("bitwarden_sdk")

    class FakeAuth:
        def login_access_token(self, token: str, state_path) -> None:
            # The SDK realistically might echo the auth header in a debug repr.
            raise RuntimeError(f"upstream auth backend returned: Authorization {sentinel}")

    class FakeBitwardenClient:
        def __init__(self, settings) -> None:
            pass

        def auth(self) -> FakeAuth:
            return FakeAuth()

    def fake_settings_from_dict(d):
        return d

    fake_module.BitwardenClient = FakeBitwardenClient  # type: ignore[attr-defined]
    fake_module.client_settings_from_dict = fake_settings_from_dict  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "bitwarden_sdk", fake_module)
    monkeypatch.setenv("BWS_ACCESS_TOKEN", sentinel)

    cfg = BwsConfig(organization_id="org-1")
    backend = BitwardenBackend(config=cfg)

    with pytest.raises(BackendUnavailableError) as exc_info:
        backend.fetch("X")

    err = exc_info.value
    # The wrapper message must not interpolate the SDK exception text.
    assert sentinel not in str(err), f"sentinel leaked into BackendUnavailableError message: {err}"
    # The cause chain must be suppressed so the SDK exception (which still
    # contains the sentinel) doesn't surface via `__cause__` in tracebacks.
    assert err.__cause__ is None, (
        f"exception chain must be suppressed (use `raise ... from None` or no `from`); "
        f"got __cause__={err.__cause__!r}"
    )


def test_warns_when_both_env_and_path_token_sources_set(monkeypatch, tmp_path) -> None:
    """BWS_ACCESS_TOKEN env var silently overrides the
    configured access_token_path. An operator who set the path expecting
    it to be authoritative will deploy with the env's stale token and
    never notice. Emit a warning so the divergence surfaces in logs."""
    import warnings

    token_file = tmp_path / "token"
    token_file.write_text("token-from-file")
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "token-from-env")

    cfg = BwsConfig(organization_id="org-1", access_token_path=str(token_file))
    backend = BitwardenBackend(config=cfg)

    # Stub bitwarden_sdk so we don't make a real network call. The auth
    # will "succeed" (no exception), giving us a clean point to inspect
    # the warning.
    import sys
    from types import ModuleType

    fake_module = ModuleType("bitwarden_sdk")

    class FakeAuth:
        def login_access_token(self, token, state_path):
            return None

    class FakeBitwardenClient:
        def __init__(self, settings):
            self.captured_token: str | None = None

        def auth(self):
            return FakeAuth()

        def secrets(self):
            class _S:
                def list(self, org_id):
                    from types import SimpleNamespace

                    return SimpleNamespace(data=SimpleNamespace(data=[]))

            return _S()

    fake_module.BitwardenClient = FakeBitwardenClient  # type: ignore[attr-defined]
    fake_module.client_settings_from_dict = lambda d: d  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "bitwarden_sdk", fake_module)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with pytest.raises(SecretNotFoundError):
            backend.fetch("ANY")  # empty store ⇒ SecretNotFoundError

    relevant = [
        w
        for w in caught
        if "BWS_ACCESS_TOKEN" in str(w.message) and "access_token_path" in str(w.message)
    ]
    assert relevant, (
        f"expected env-vs-path divergence warning; got: {[str(w.message) for w in caught]}"
    )
