"""Tests for the backend: discriminator block in config.py."""

from __future__ import annotations

import pytest

from agent_vault_proxy.backends.bws import BitwardenBackend, BwsConfig
from agent_vault_proxy.config import Config, ConfigError, build_backend


def _minimal_raw(extra: dict) -> dict:
    """Build a minimal valid raw config dict, with `extra` merged in
    (use to add `bws:` or `backend:` blocks to a base config)."""
    base = {
        "version": 1,
        "secrets": {
            "FOO": {
                "placeholder": "test_PLACEHOLDER_01HXY1234567890",
                "inject": {"header": "Authorization", "format": "Bearer {FOO}"},
                "bindings": [{"host": "api.example.com"}],
            }
        },
        "audit": {"path": "/tmp/x.jsonl"},
    }
    return {**base, **extra}


def test_v03_backend_block_parses() -> None:
    raw = _minimal_raw(
        {
            "backend": {
                "type": "bws",
                "config": {
                    "type": "bws",
                    "organization_id": "org-1",
                    "access_token_path": "/etc/agent-vault-proxy/bws-token",
                },
            }
        }
    )
    config = Config.model_validate(raw)
    assert config.backend is not None
    assert config.backend.type == "bws"


def test_build_backend_returns_instance_and_config() -> None:
    raw = _minimal_raw(
        {
            "backend": {
                "type": "bws",
                "config": {"type": "bws", "organization_id": "org-1"},
            }
        }
    )
    config = Config.model_validate(raw)
    backend, backend_config = build_backend(config)
    assert isinstance(backend, BitwardenBackend)
    assert isinstance(backend_config, BwsConfig)
    assert backend_config.organization_id == "org-1"


def test_build_backend_raises_when_no_backend_configured() -> None:
    raw = _minimal_raw({})  # neither `bws:` nor `backend:` block
    config = Config.model_validate(raw)
    with pytest.raises(ConfigError, match="no backend configured"):
        build_backend(config)


def test_unknown_backend_type_fails_at_config_load() -> None:
    """v0.4.1 moves backend-type validation forward to config-load so
    typos in `backend.type` surface in `bindings diff` / `--check`, not
    only at first secret fetch."""
    from pydantic import ValidationError

    raw = _minimal_raw(
        {
            "backend": {
                "type": "nonexistent",
                "config": {"foo": "bar"},
            }
        }
    )
    with pytest.raises(ValidationError, match="unknown backend type"):
        Config.model_validate(raw)


def test_v04_backend_block_strict_with_extra_forbid_at_load() -> None:
    """Typos under `backend.config` fail at config-load (v0.4.1 m1),
    not deferred to the first build_backend() / first secret fetch."""
    from pydantic import ValidationError

    raw = _minimal_raw(
        {
            "backend": {
                "type": "bws",
                "config": {
                    "type": "bws",
                    "organization_id": "org-1",
                    "made_up_field": "should-fail",
                },
            }
        }
    )
    with pytest.raises(ValidationError):
        Config.model_validate(raw)


def test_backend_config_validated_per_type_at_load() -> None:
    """type=bws with foreign field rejected at load time by BwsConfig's
    extra=forbid, not deferred to build_backend()."""
    from pydantic import ValidationError

    raw = _minimal_raw(
        {
            "backend": {
                "type": "bws",
                "config": {
                    "type": "bws",
                    "organization_id": "org-1",
                    "totally_made_up_field": "oops",
                },
            }
        }
    )
    with pytest.raises(ValidationError):
        Config.model_validate(raw)


def test_build_backend_reuses_eagerly_validated_config() -> None:
    """The after-validator on BackendBlock stashes the validated per-backend
    config; build_backend() reuses it instead of re-validating. Asserts the
    instance is the same Python object, not a fresh re-parse."""
    raw = _minimal_raw(
        {
            "backend": {
                "type": "bws",
                "config": {"type": "bws", "organization_id": "org-1"},
            }
        }
    )
    config = Config.model_validate(raw)
    assert config.backend is not None
    stashed = config.backend._validated_config
    assert stashed is not None
    _backend, backend_config = build_backend(config)
    assert backend_config is stashed
