"""gsm_notes activation hardening (ADR-0018, Cato audit F1).

A wildcard host arriving through the notes/annotation channel must NOT bypass
the `allow_wildcard_hosts` opt-in. The Config-level `enforce_wildcard_opt_in`
model_validator runs at load, before notes are merged in, so the activator
re-enforces it — fail closed (drop + attribute the placeholder as invalid).
"""

from __future__ import annotations

from pathlib import Path

from kow.addon import AgentVaultProxyAddon
from tests.fakes import FakeNotesListBackend as _FakeNotesListBackend

_SALT = b"\x11" * 32


def _gsm_notes_config(tmp_path: Path, *, allow_wildcard: bool) -> Path:
    salt_path = tmp_path / "install-salt"
    salt_path.write_bytes(_SALT)
    salt_path.chmod(0o600)
    yaml = f"""
version: 1
secrets: {{}}
binding_source: notes
install_salt_path: {salt_path}
allow_wildcard_hosts: {str(allow_wildcard).lower()}
unmatched_destination_policy: forward_unmodified
audit:
  path: {tmp_path / "audit.jsonl"}
backend:
  type: static
  config:
    type: static
    path: {tmp_path / "unused-secrets.yaml"}
"""
    p = tmp_path / "bindings.yaml"
    p.write_text(yaml)
    return p


def test_wildcard_annotation_rejected_when_opt_in_disabled(tmp_path: Path) -> None:
    cfg = _gsm_notes_config(tmp_path, allow_wildcard=False)
    backend = _FakeNotesListBackend(
        {
            "WIDE_KEY": ("v1", '# avp-binding\nhost: "*.internal.example.com"'),
            "GOOD_KEY": ("v2", "# avp-binding\napi.openai.com"),
        }
    )
    addon = AgentVaultProxyAddon()
    addon.configure_from_path(cfg, backend_override=backend)

    # The wildcard binding is dropped and fails closed; the exact-host one lives.
    assert "WIDE_KEY" not in addon.config.secrets
    assert "WIDE_KEY" in addon._invalid_names
    assert "GOOD_KEY" in addon.config.secrets


def test_wildcard_annotation_allowed_with_opt_in(tmp_path: Path) -> None:
    cfg = _gsm_notes_config(tmp_path, allow_wildcard=True)
    backend = _FakeNotesListBackend(
        {"WIDE_KEY": ("v1", '# avp-binding\nhost: "*.internal.example.com"')}
    )
    addon = AgentVaultProxyAddon()
    addon.configure_from_path(cfg, backend_override=backend)

    assert "WIDE_KEY" in addon.config.secrets
    assert "WIDE_KEY" not in addon._invalid_names


def test_honeytoken_flag_survives_notes_override(tmp_path: Path) -> None:
    """`both` mode: a file secret flagged honeytoken:true whose binding comes
    from a note must stay armed. The notes spec replaces the file spec, so
    without preserving the flag the tripwire silently disarms (Oracle MED)."""
    salt_path = tmp_path / "install-salt"
    salt_path.write_bytes(_SALT)
    salt_path.chmod(0o600)
    cfg = tmp_path / "bindings.yaml"
    cfg.write_text(
        f"""
version: 1
binding_source: both
install_salt_path: {salt_path}
unmatched_destination_policy: forward_unmodified
secrets:
  DECOY:
    placeholder: "sk-ant-PLACEHOLDER-01HXY1234567890ABCDEFGH"
    honeytoken: true
    inject:
      header: "Authorization"
      format: "Bearer {{DECOY}}"
    bindings:
      - host: "api.decoy-file.example.com"
audit:
  path: {tmp_path / "audit.jsonl"}
backend:
  type: static
  config:
    type: static
    path: {tmp_path / "unused.yaml"}
"""
    )
    backend = _FakeNotesListBackend({"DECOY": ("realval", "# avp-binding\napi.trap.example.com")})
    addon = AgentVaultProxyAddon()
    addon.configure_from_path(cfg, backend_override=backend)

    assert "DECOY" in addon.config.secrets
    assert addon.config.secrets["DECOY"].honeytoken is True
