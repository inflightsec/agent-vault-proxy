"""Schema tests for the ``oauth2_refresh`` injector (ADR-0017 slice 1).

Covers parsing-only contracts: the discriminated-union dispatch, the
provider-preset XOR validator, HTTPS-only ``token_url``, and the
``extra="forbid"`` typo-rejection posture. Runtime resolution (cache,
token exchange, audit emission) lands in later slices and has its own
test files.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from pydantic import ValidationError

from agent_vault_proxy.config import Config
from tests._oauth_helpers import apply_public_ssrf_stub

_FOO_PH = "foo_PLACEHOLDER_01HXY1234567890"


@pytest.fixture(autouse=True)
def stub_ssrf_dns(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Hermetic DNS for ``oauth2.example.com`` (and friends) via the
    shared loopback-pass-through stub. These tests exercise the
    SCHEMA, not the SSRF guard (``tests/test_ssrf_guard.py`` covers
    the guard itself)."""
    apply_public_ssrf_stub(monkeypatch)
    yield


def _wrap(inject: dict, *, secret_name: str = "FOO") -> dict:
    """Minimal valid Config skeleton wrapping one secret's ``inject`` block.

    Tests parametrise the inject block; everything around it is the
    minimum Pydantic accepts so the failure is attributable to the
    injector under test, not the surrounding skeleton."""
    return {
        "version": 1,
        "secrets": {
            secret_name: {
                "placeholder": _FOO_PH,
                "inject": inject,
                "bindings": [{"host": "api.example.com"}],
            }
        },
        "audit": {"path": "/tmp/x.jsonl"},
    }


# ---------------------------------------------------------------------------
# Positive cases — explicit and preset-based forms both parse
# ---------------------------------------------------------------------------


def test_explicit_form_parses_with_https_token_url() -> None:
    """No ``provider:`` — operator supplies ``token_url`` and
    ``client_auth_method`` themselves. This is the lowest-common-
    denominator path that must always work."""
    inject = {
        "type": "oauth2_refresh",
        "token_url": "https://oauth2.example.com/token",
        "client_auth_method": "body_post",
        "client_id_secret": "FOO_CLIENT_ID",
        "client_secret_secret": "FOO_CLIENT_SECRET",
        "refresh_token_secret": "FOO_REFRESH_TOKEN",
    }
    config = Config.model_validate(_wrap(inject))
    spec = config.secrets["FOO"].inject
    assert spec.type == "oauth2_refresh"
    assert spec.provider is None
    assert str(spec.token_url) == "https://oauth2.example.com/token"
    assert spec.client_auth_method == "body_post"


def test_preset_form_parses_without_explicit_token_url() -> None:
    """``provider: google`` is sufficient — the preset catalogue
    supplies token_url and auth method. Operator only needs to point
    at three BWS secrets."""
    inject = {
        "type": "oauth2_refresh",
        "provider": "google",
        "client_id_secret": "FOO_CLIENT_ID",
        "client_secret_secret": "FOO_CLIENT_SECRET",
        "refresh_token_secret": "FOO_REFRESH_TOKEN",
    }
    config = Config.model_validate(_wrap(inject))
    spec = config.secrets["FOO"].inject
    assert spec.type == "oauth2_refresh"
    assert spec.provider == "google"


def test_defaults_pinned() -> None:
    """Defaults the operator inherits without saying so. Pinned because
    a silent change breaks deployed bindings — e.g. an operator on
    Azure relying on the default ``Bearer {access_token}`` header
    format must not have it switched out from under them."""
    inject = {
        "type": "oauth2_refresh",
        "provider": "google",
        "client_id_secret": "C_ID",
        "client_secret_secret": "C_SEC",
        "refresh_token_secret": "R_TOK",
    }
    spec = Config.model_validate(_wrap(inject)).secrets["FOO"].inject
    assert spec.header == "Authorization"
    assert spec.format == "Bearer {access_token}"
    assert spec.cache_ttl_safety_seconds == 60
    assert spec.cache_ttl_max_seconds == 3600
    assert spec.refresh_token_write_back is True


# ---------------------------------------------------------------------------
# Negative cases — XOR, scheme, scope, typo-rejection
# ---------------------------------------------------------------------------


def test_no_provider_no_token_url_rejected() -> None:
    """Either path is required. Refuse early at config-load — the runtime
    has no sensible default to invent."""
    inject = {
        "type": "oauth2_refresh",
        "client_id_secret": "C_ID",
        "client_secret_secret": "C_SEC",
        "refresh_token_secret": "R_TOK",
    }
    with pytest.raises(ValidationError) as ei:
        Config.model_validate(_wrap(inject))
    assert "token_url" in str(ei.value) or "provider" in str(ei.value)


def test_provider_and_explicit_token_url_rejected() -> None:
    """XOR — the preset exists so operators don't have to copy URLs;
    accepting both invites the wrong one winning silently. Reject at
    load."""
    inject = {
        "type": "oauth2_refresh",
        "provider": "google",
        "token_url": "https://oauth2.example.com/token",
        "client_id_secret": "C_ID",
        "client_secret_secret": "C_SEC",
        "refresh_token_secret": "R_TOK",
    }
    with pytest.raises(ValidationError) as ei:
        Config.model_validate(_wrap(inject))
    assert "provider" in str(ei.value).lower()


def test_http_scheme_token_url_rejected() -> None:
    """HTTPS-only. A plaintext token endpoint would put the refresh
    token on the wire in cleartext on the very first exchange."""
    inject = {
        "type": "oauth2_refresh",
        "token_url": "http://oauth2.example.com/token",
        "client_auth_method": "body_post",
        "client_id_secret": "C_ID",
        "client_secret_secret": "C_SEC",
        "refresh_token_secret": "R_TOK",
    }
    with pytest.raises(ValidationError) as ei:
        Config.model_validate(_wrap(inject))
    assert "https" in str(ei.value).lower() or "scheme" in str(ei.value).lower()


def test_unknown_provider_rejected() -> None:
    """``provider:`` is a closed enumeration. Adding a provider needs a
    preset entry — silent fall-through to ``token_url`` required would
    surprise operators who'd mistyped a known name."""
    inject = {
        "type": "oauth2_refresh",
        "provider": "googel",  # typo
        "client_id_secret": "C_ID",
        "client_secret_secret": "C_SEC",
        "refresh_token_secret": "R_TOK",
    }
    with pytest.raises(ValidationError):
        Config.model_validate(_wrap(inject))


def test_unknown_field_rejected() -> None:
    """``extra='forbid'`` matches the rest of AVP. A ``token_uri:`` typo
    must not produce an unconfigured binding that silently runs."""
    inject = {
        "type": "oauth2_refresh",
        "token_url": "https://oauth2.example.com/token",
        "client_auth_method": "body_post",
        "client_id_secret": "C_ID",
        "client_secret_secret": "C_SEC",
        "refresh_token_secret": "R_TOK",
        "token_uri": "https://oauth2.example.com/token",  # typo
    }
    with pytest.raises(ValidationError) as ei:
        Config.model_validate(_wrap(inject))
    assert "token_uri" in str(ei.value) or "extra" in str(ei.value).lower()


def test_missing_required_secret_refs_rejected() -> None:
    """The three BWS secret references are always required regardless
    of preset usage — the catalogue can supply URLs but not credentials."""
    inject = {
        "type": "oauth2_refresh",
        "provider": "google",
        # missing client_id_secret
        "client_secret_secret": "C_SEC",
        "refresh_token_secret": "R_TOK",
    }
    with pytest.raises(ValidationError) as ei:
        Config.model_validate(_wrap(inject))
    assert "client_id_secret" in str(ei.value)


# ---------------------------------------------------------------------------
# Dispatch — discriminated union picks the right class
# ---------------------------------------------------------------------------


def test_discriminator_dispatches_to_oauth_class() -> None:
    """``type: oauth2_refresh`` must hit the new class, not get caught
    by the prior 'planned' fail-closed path."""
    from agent_vault_proxy.config import Oauth2RefreshInjector

    inject = {
        "type": "oauth2_refresh",
        "provider": "google",
        "client_id_secret": "C_ID",
        "client_secret_secret": "C_SEC",
        "refresh_token_secret": "R_TOK",
    }
    spec = Config.model_validate(_wrap(inject)).secrets["FOO"].inject
    assert isinstance(spec, Oauth2RefreshInjector)


def test_multi_does_not_accept_oauth2_refresh_child() -> None:
    """Anti-criterion: composing ``oauth2_refresh`` inside ``multi`` is
    deferred per ADR-0017 §1 — the resolution-step semantics inside a
    multi need their own design pass. Reject at load."""
    inject = {
        "type": "multi",
        "injectors": [
            {
                "type": "oauth2_refresh",
                "provider": "google",
                "client_id_secret": "C_ID",
                "client_secret_secret": "C_SEC",
                "refresh_token_secret": "R_TOK",
            },
            {"type": "header", "header": "X-Other", "format": "{FOO}"},
        ],
    }
    with pytest.raises(ValidationError):
        Config.model_validate(_wrap(inject))


# ---------------------------------------------------------------------------
# Stub-removal — the prior "planned: P1" error must NOT fire
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Provider/explicit shape tightening (Oracle C1/C2/C3 fixes)
# ---------------------------------------------------------------------------


def test_tenant_specific_provider_requires_explicit_token_url() -> None:
    """``provider: auth0`` (tenant-specific, preset.token_url is None)
    requires the operator to supply ``token_url`` — without it, AVP
    has no way to know which tenant to call. Reject at load."""
    inject = {
        "type": "oauth2_refresh",
        "provider": "auth0",
        "client_id_secret": "C_ID",
        "client_secret_secret": "C_SEC",
        "refresh_token_secret": "R_TOK",
    }
    with pytest.raises(ValidationError, match=r"tenant-specific|supply token_url"):
        Config.model_validate(_wrap(inject))


def test_tenant_specific_provider_with_explicit_token_url_loads() -> None:
    """``provider: auth0`` (or okta) WITH explicit ``token_url`` is the
    valid shape for tenant deployments. The preset contributes the
    auth method only."""
    from agent_vault_proxy.oauth_providers import PROVIDER_PRESETS

    inject = {
        "type": "oauth2_refresh",
        "provider": "auth0",
        "token_url": "https://tenant.auth0.com/oauth/token",
        "client_id_secret": "C_ID",
        "client_secret_secret": "C_SEC",
        "refresh_token_secret": "R_TOK",
    }
    spec = Config.model_validate(_wrap(inject)).secrets["FOO"].inject
    assert spec.provider == "auth0"
    assert str(spec.token_url) == "https://tenant.auth0.com/oauth/token"
    # auth_method comes from the preset, not the YAML.
    assert spec.client_auth_method == PROVIDER_PRESETS["auth0"].client_auth_method


def test_non_tenant_provider_with_explicit_token_url_rejected() -> None:
    """``provider: google`` already brings the vetted token_url. An
    explicit override would silently route to an operator-controlled
    URL — surprising, and bypasses the PR-review vetting of the preset.
    Reject."""
    inject = {
        "type": "oauth2_refresh",
        "provider": "google",
        "token_url": "https://attacker.example.com/token",
        "client_id_secret": "C_ID",
        "client_secret_secret": "C_SEC",
        "refresh_token_secret": "R_TOK",
    }
    with pytest.raises(ValidationError, match=r"provider.*supplies token_url"):
        Config.model_validate(_wrap(inject))


def test_provider_with_explicit_auth_method_rejected() -> None:
    """Silent override of the preset's auth method changes the wire
    protocol of every token exchange without any operator-visible
    intent. Reject for both tenant and non-tenant providers."""
    base = {
        "type": "oauth2_refresh",
        "client_id_secret": "C_ID",
        "client_secret_secret": "C_SEC",
        "refresh_token_secret": "R_TOK",
        "client_auth_method": "basic",
    }
    for provider in ("google", "auth0"):
        inject = {**base, "provider": provider}
        if provider == "auth0":
            inject["token_url"] = "https://tenant.auth0.com/oauth/token"
        with pytest.raises(ValidationError, match=r"client_auth_method"):
            Config.model_validate(_wrap(inject))


def test_tenant_provider_token_url_runs_ssrf_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """When a tenant-specific provider supplies its own token_url, the
    SSRF guard MUST still run on that URL. The earlier preset-only path
    skipped SSRF entirely, which would let a private-IP tenant URL
    through. This test pins the fix for that gap."""
    import socket

    def stub(host: str, *_a: object, **_kw: object) -> list[tuple]:
        # Tenant URL resolves to a loopback — must be blocked.
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 0))]

    monkeypatch.setattr("agent_vault_proxy._ssrf_guard.socket.getaddrinfo", stub)
    inject = {
        "type": "oauth2_refresh",
        "provider": "auth0",
        "token_url": "https://tenant.auth0.com/oauth/token",
        "client_id_secret": "C_ID",
        "client_secret_secret": "C_SEC",
        "refresh_token_secret": "R_TOK",
    }
    with pytest.raises(ValidationError, match=r"loopback"):
        Config.model_validate(_wrap(inject))


def test_planned_stub_no_longer_fires() -> None:
    """Before ADR-0017, ``inject.type: oauth2_refresh`` raised
    ``planned for phase P1`` at config-load. After this slice it must
    parse cleanly. This is the regression boundary."""
    inject = {
        "type": "oauth2_refresh",
        "provider": "google",
        "client_id_secret": "C_ID",
        "client_secret_secret": "C_SEC",
        "refresh_token_secret": "R_TOK",
    }
    # No exception expected — the prior fail-closed path is gone.
    Config.model_validate(_wrap(inject))
