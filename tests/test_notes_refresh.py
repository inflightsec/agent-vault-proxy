"""ADR-0032: the background notes-refresh brokers a NEW vault secret without a
restart — and fails SAFE (keeps live bindings) when the vault can't be listed.

These drive ``AgentVaultProxyAddon.refresh_notes()`` directly (the sync seam the
background loop calls via ``asyncio.to_thread``), so the refresh logic is pinned
without needing a running event loop.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_vault_proxy.addon import AgentVaultProxyAddon
from agent_vault_proxy.backends import BackendCannotListError

_SALT = b"\x11" * 32
_HOST_A = "api.aaa-example.com"
_HOST_B = "api.bbb-example.com"


class _MutableNotesBackend:
    """A listable notes backend whose secret set can change between lists, so a
    test can add a secret and re-list — exactly the vault-gained-a-secret case."""

    def __init__(self, secrets: dict[str, tuple[str, str | None]]) -> None:
        self._secrets = secrets
        self.flush_calls = 0
        self.fail = False

    def list_secret_names(self) -> list[str]:
        if self.fail:
            raise BackendCannotListError("vault unreachable")
        return list(self._secrets)

    def fetch(self, name: str, ctx: Any = None) -> str:
        return self._secrets[name][0]

    def fetch_with_meta(self, name: str, ctx: Any = None) -> tuple[str, str | None]:
        return self._secrets[name]

    def flush_name_map(self) -> None:
        self.flush_calls += 1

    def add(self, name: str, value: str, host: str) -> None:
        self._secrets[name] = (value, f"# avp-binding\nhost: {host}")


def _read_audit(path: Path) -> list[dict[str, Any]]:
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln] if path.exists() else []


def _config(tmp_path: Path, audit_path: Path, *, binding_source: str = "notes") -> Path:
    salt = tmp_path / "install-salt"
    salt.write_bytes(_SALT)
    salt.chmod(0o600)
    (tmp_path / "unused.yaml").write_text("secrets: {}\n")
    p = tmp_path / "bindings.yaml"
    p.write_text(
        f"""
version: 1
secrets: {{}}
binding_source: {binding_source}
install_salt_path: {salt}
unmatched_destination_policy: forward_unmodified
notes_refresh_seconds: 30
audit:
  path: {audit_path}
backend:
  type: static
  config:
    type: static
    path: {tmp_path / "unused.yaml"}
"""
    )
    return p


def _addon(
    tmp_path: Path, backend: _MutableNotesBackend, **kw: str
) -> tuple[AgentVaultProxyAddon, Path]:
    audit_path = tmp_path / "audit.jsonl"
    addon = AgentVaultProxyAddon()
    addon.configure_from_path(str(_config(tmp_path, audit_path, **kw)), backend_override=backend)
    return addon, audit_path


def test_refresh_brokers_new_secret_and_keeps_warm_caches(tmp_path: Path) -> None:
    backend = _MutableNotesBackend({"AAA": ("val-a", f"# avp-binding\nhost: {_HOST_A}")})
    addon, audit_path = _addon(tmp_path, backend)
    assert addon.config is not None and "AAA" in addon.config.secrets
    assert "BBB" not in addon.config.secrets
    client_before = addon.client
    token_cache_before = addon._token_cache

    backend.add("BBB", "val-b", _HOST_B)  # a new secret lands in the vault
    addon.refresh_notes()

    assert "BBB" in addon.config.secrets  # new binding live, no restart
    assert backend.flush_calls == 1  # fresh listing was forced
    # The whole point of a notes-only refresh: warm caches survive.
    assert addon.client is client_before
    assert addon._token_cache is token_cache_before
    refreshed = [e for e in _read_audit(audit_path) if e.get("type") == "notes_refreshed"]
    assert refreshed and refreshed[-1]["added"] == ["BBB"] and refreshed[-1]["removed"] == []


def test_refresh_is_silent_when_nothing_changed(tmp_path: Path) -> None:
    backend = _MutableNotesBackend({"AAA": ("val-a", f"# avp-binding\nhost: {_HOST_A}")})
    addon, audit_path = _addon(tmp_path, backend)
    addon.refresh_notes()
    assert not [e for e in _read_audit(audit_path) if e.get("type") == "notes_refreshed"]


def test_refresh_fails_safe_and_keeps_bindings_when_listing_fails(tmp_path: Path) -> None:
    backend = _MutableNotesBackend({"AAA": ("val-a", f"# avp-binding\nhost: {_HOST_A}")})
    addon, _audit = _addon(tmp_path, backend)
    old_config = addon.config
    assert old_config is not None and "AAA" in old_config.secrets

    backend.fail = True  # vault goes unreachable during the refresh
    addon.refresh_notes()  # must NOT drop live bindings

    # Old snapshot retained — a blip did not un-broker the secret.
    assert addon.config is old_config
    assert "AAA" in addon.config.secrets


def test_refresh_is_noop_in_file_mode(tmp_path: Path) -> None:
    backend = _MutableNotesBackend({})
    addon, _audit = _addon(tmp_path, backend, binding_source="file")
    before = addon.config
    addon.refresh_notes()
    assert addon.config is before
    assert backend.flush_calls == 0  # never even touched the backend
