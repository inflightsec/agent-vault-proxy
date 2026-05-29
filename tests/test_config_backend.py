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
                "placeholder": "x",
                "inject": {"header": "Authorization", "format": "Bearer {secret}"},
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


def test_build_backend_raises_on_unknown_type() -> None:
    raw = _minimal_raw(
        {
            "backend": {
                "type": "nonexistent",
                "config": {"foo": "bar"},
            }
        }
    )
    config = Config.model_validate(raw)
    with pytest.raises(ConfigError, match="unknown backend type"):
        build_backend(config)


def test_v04_backend_block_strict_with_extra_forbid() -> None:
    """v0.4 users writing `backend:` directly get strict validation — typos
    in config fail loudly rather than being silently dropped."""
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
    config = Config.model_validate(raw)
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        build_backend(config)


def test_build_backend_validates_per_type_config_schema() -> None:
    """type=bws with foreign field rejected by BwsConfig's extra=forbid."""
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
    config = Config.model_validate(raw)
    with pytest.raises(ValidationError):
        build_backend(config)
