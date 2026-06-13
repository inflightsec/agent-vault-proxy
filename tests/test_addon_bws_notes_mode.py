"""End-to-end: the daemon CONSUMES BWS notes (ADR-0011 item 3 activation).

These drive the addon through configure() in bws_notes/both mode and then
through a request, asserting:

  * a host-only note results in an injected real secret on the wire, audited
    binding_source: bws_notes;
  * a request carrying a no-binding secret's placeholder fails closed with
    reason no_binding_in_notes (and does NOT forward the real value);
  * a malformed note's placeholder fails closed with invalid_binding_metadata;
  * file-mode installs are completely unaffected (no BWS listing happens).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from mitmproxy.test import tflow

from agent_vault_proxy.addon import AgentVaultProxyAddon
from agent_vault_proxy.backends import BackendCannotListError
from agent_vault_proxy.placeholders import derive_placeholder

_SALT = b"\x09" * 32


class _FakeNotesListBackend:
    def __init__(self, secrets: dict[str, tuple[str, str | None]]) -> None:
        self._secrets = secrets

    def list_secret_names(self) -> list[str]:
        return list(self._secrets)

    def fetch(self, name, ctx=None) -> str:
        return self._secrets[name][0]

    def fetch_with_meta(self, name, ctx=None) -> tuple[str, str | None]:
        return self._secrets[name]


def _read_audit(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def _make_request(host: str, headers: dict[str, str], *, path: str = "/v1/messages") -> Any:
    flow = tflow.tflow()
    flow.request.host = host
    flow.request.port = 443
    flow.request.scheme = "https"
    flow.request.path = path
    flow.request.method = "POST"
    for k, v in headers.items():
        flow.request.headers[k] = v
    return flow


def _bws_notes_config(tmp_path: Path, audit_path: Path) -> Path:
    salt_path = tmp_path / "install-salt"
    salt_path.write_bytes(_SALT)
    salt_path.chmod(0o600)
    yaml = f"""
version: 1
secrets: {{}}
binding_source: bws_notes
install_salt_path: {salt_path}
unmatched_destination_policy: forward_unmodified
audit:
  path: {audit_path}
backend:
  type: static
  config:
    type: static
    path: {tmp_path / "unused-secrets.yaml"}
"""
    # static backend needs a file to exist for build_backend's eager config
    # validation? No — config validation only checks the path string. The
    # backend is replaced on the addon by our fake below, so the file is
    # never read.
    p = tmp_path / "bindings.yaml"
    p.write_text(yaml)
    return p


def _both_mode_config(
    tmp_path: Path,
    audit_path: Path,
    *,
    secret_name: str,
    placeholder: str,
    host: str,
) -> Path:
    salt_path = tmp_path / "install-salt"
    salt_path.write_bytes(_SALT)
    salt_path.chmod(0o600)
    yaml = f"""
version: 1
secrets:
  {secret_name}:
    placeholder: "{placeholder}"
    inject:
      header: "Authorization"
      format: "Bearer {{{secret_name}}}"
    bindings:
      - host: "{host}"
binding_source: both
install_salt_path: {salt_path}
unmatched_destination_policy: forward_unmodified
audit:
  path: {audit_path}
backend:
  type: static
  config:
    type: static
    path: {tmp_path / "unused-secrets.yaml"}
"""
    p = tmp_path / "bindings.yaml"
    p.write_text(yaml)
    return p


def _build_notes_addon(
    tmp_path: Path,
    secrets: dict[str, tuple[str, str | None]],
) -> tuple[AgentVaultProxyAddon, Path]:
    audit_path = tmp_path / "audit.jsonl"
    config_path = _bws_notes_config(tmp_path, audit_path)

    addon = AgentVaultProxyAddon()
    backend = _FakeNotesListBackend(secrets)
    # Drive configure() through the public injection seam so the BWS-notes
    # activation path runs exactly as in production, but against our fake
    # backend (no real BWS).
    addon.configure_from_path(str(config_path), backend_override=backend)
    return addon, audit_path


def test_daemon_injects_real_secret_from_host_only_note(tmp_path: Path) -> None:
    real = "sk-ant-REAL-value"
    addon, audit_path = _build_notes_addon(
        tmp_path, {"ANTHROPIC": (real, "host: api.anthropic.com")}
    )
    ph = derive_placeholder("ANTHROPIC", _SALT)
    flow = _make_request("api.anthropic.com", {"x-api-key": ph})
    addon.requestheaders(flow)

    # api.anthropic.com exception-table row uses x-api-key + raw value.
    assert flow.request.headers["x-api-key"] == real
    assert flow.request.headers["anthropic-version"] == "2023-06-01"
    events = _read_audit(audit_path)
    allowed = [e for e in events if e.get("decision") == "allowed"]
    assert len(allowed) == 1
    assert allowed[0]["binding_source"] == "bws_notes"
    assert allowed[0]["secret_name"] == "ANTHROPIC"
    assert "2023-06-01" not in audit_path.read_text()


def test_companion_header_does_not_overwrite_client_value(tmp_path: Path) -> None:
    """Companion headers are DEFAULTS, not overrides: a client-supplied
    anthropic-version must survive — AVP changes only the credential."""
    real = "sk-ant-REAL-value"
    addon, _audit_path = _build_notes_addon(
        tmp_path, {"ANTHROPIC": (real, "host: api.anthropic.com")}
    )
    ph = derive_placeholder("ANTHROPIC", _SALT)
    flow = _make_request(
        "api.anthropic.com",
        {"x-api-key": ph, "anthropic-version": "2099-01-01"},
    )
    addon.requestheaders(flow)

    assert flow.request.headers["x-api-key"] == real  # credential still injected
    assert flow.request.headers["anthropic-version"] == "2099-01-01"  # client value kept


def test_no_binding_placeholder_fails_closed(tmp_path: Path) -> None:
    real = "sk-REAL-should-not-leak"
    addon, audit_path = _build_notes_addon(tmp_path, {"FOO": (real, "")})  # no note
    ph = derive_placeholder("FOO", _SALT)
    flow = _make_request("api.example.com", {"Authorization": f"Bearer {ph}"})
    addon.requestheaders(flow)

    # Fail closed: placeholder forwarded verbatim, real value NEVER injected.
    assert flow.request.headers["Authorization"] == f"Bearer {ph}"
    assert real not in flow.request.headers["Authorization"]
    events = _read_audit(audit_path)
    denied = [e for e in events if e.get("decision") == "denied"]
    assert any(e["reason"] == "no_binding_in_notes" for e in denied), events
    assert any(e.get("secret_name") == "FOO" for e in denied)


def test_invalid_binding_placeholder_fails_closed(tmp_path: Path) -> None:
    real = "sk-REAL-should-not-leak"
    addon, audit_path = _build_notes_addon(tmp_path, {"BAR": (real, "host: [unclosed")})
    ph = derive_placeholder("BAR", _SALT)
    flow = _make_request("api.example.com", {"Authorization": f"Bearer {ph}"})
    addon.requestheaders(flow)

    assert flow.request.headers["Authorization"] == f"Bearer {ph}"
    assert real not in flow.request.headers["Authorization"]
    events = _read_audit(audit_path)
    denied = [e for e in events if e.get("decision") == "denied"]
    assert any(e["reason"] == "invalid_binding_metadata" for e in denied), events


def test_both_mode_invalid_note_terminal_denies_same_name_file_binding(tmp_path: Path) -> None:
    real = "sk-REAL-should-not-leak"
    audit_path = tmp_path / "audit.jsonl"
    file_placeholder = "file-PLACEHOLDER-01HXY1234567890ABCDE"
    config_path = _both_mode_config(
        tmp_path,
        audit_path,
        secret_name="SHARED_SECRET",
        placeholder=file_placeholder,
        host="api.example.com",
    )

    addon = AgentVaultProxyAddon()
    addon.configure_from_path(
        str(config_path),
        backend_override=_FakeNotesListBackend({"SHARED_SECRET": (real, "host: [unclosed")}),
    )

    flow = _make_request("api.example.com", {"Authorization": f"Bearer {file_placeholder}"})
    addon.requestheaders(flow)

    assert flow.request.headers["Authorization"] == f"Bearer {file_placeholder}"
    assert real not in flow.request.headers["Authorization"]
    events = _read_audit(audit_path)
    denied = [e for e in events if e.get("decision") == "denied"]
    assert any(e["reason"] == "invalid_binding_metadata" for e in denied), events
    assert any(e.get("secret_name") == "SHARED_SECRET" for e in denied), events
    assert not any(e.get("decision") == "allowed" for e in events), events


def test_daemon_injects_notion_companion_header_without_auditing_value(tmp_path: Path) -> None:
    real = "secret-notion-real"
    addon, audit_path = _build_notes_addon(tmp_path, {"NOTION": (real, "host: api.notion.com")})
    ph = derive_placeholder("NOTION", _SALT)
    flow = _make_request("api.notion.com", {"Authorization": f"Bearer {ph}"}, path="/v1/pages")
    addon.requestheaders(flow)

    assert flow.request.headers["Authorization"] == f"Bearer {real}"
    assert flow.request.headers["Notion-Version"] == "2022-06-28"
    assert "2022-06-28" not in audit_path.read_text()


def test_file_mode_does_not_list_bws(tmp_path: Path) -> None:
    """file mode (the default) must NOT enumerate BWS — existing installs are
    unaffected. We prove it by passing a backend whose list call raises."""

    class _ExplodingListBackend:
        def list_secret_names(self):
            raise AssertionError("file mode must not list BWS secrets")

        def fetch(self, name, ctx=None):
            return "v"

    audit_path = tmp_path / "audit.jsonl"
    ph = "sk-ant-PLACEHOLDER-01HXY1234567890ABCDEFGH"
    yaml = f"""
version: 1
secrets:
  ANTHROPIC_API_KEY:
    placeholder: "{ph}"
    inject:
      header: "Authorization"
      format: "Bearer {{ANTHROPIC_API_KEY}}"
    bindings:
      - host: "api.anthropic.com"
binding_source: file
audit:
  path: {audit_path}
"""
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(yaml)

    addon = AgentVaultProxyAddon()
    # Should not raise — file mode never calls list_secret_names.
    addon.configure_from_path(str(config_path), backend_override=_ExplodingListBackend())
    flow = _make_request("api.anthropic.com", {"Authorization": f"Bearer {ph}"})
    addon.requestheaders(flow)
    assert flow.request.headers["Authorization"] == "Bearer v"


def test_both_mode_merged_placeholder_substring_overlap_fails_closed(
    tmp_path: Path,
) -> None:
    """In `both` mode the file placeholder set is merged with the derived
    set. A file placeholder that is a SUBSTRING of a derived one (or vice
    versa) would make the addon's `in` matching ambiguous — configure() must
    fail closed rather than serve an ambiguous map."""
    import pytest

    audit_path = tmp_path / "audit.jsonl"
    salt_path = tmp_path / "install-salt"
    salt_path.write_bytes(_SALT)
    salt_path.chmod(0o600)

    derived = derive_placeholder("ANTHROPIC", _SALT)
    # A file secret whose placeholder is a substring of the derived one.
    overlapping = derived[:30]
    yaml = f"""
version: 1
secrets:
  FILE_SECRET:
    placeholder: "{overlapping}"
    inject:
      header: "Authorization"
      format: "Bearer {{FILE_SECRET}}"
    bindings:
      - host: "file.example.com"
binding_source: both
install_salt_path: {salt_path}
audit:
  path: {audit_path}
"""
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(yaml)

    backend = _FakeNotesListBackend({"ANTHROPIC": ("v", "host: api.anthropic.com")})
    addon = AgentVaultProxyAddon()
    with pytest.raises(ValueError, match="substring"):
        addon.configure_from_path(str(config_path), backend_override=backend)


def test_both_mode_degrades_to_file_bindings_when_salt_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    import agent_vault_proxy.placeholders as placeholders

    audit_path = tmp_path / "audit.jsonl"
    placeholder = "file-PLACEHOLDER-01HXY1234567890SALT1"
    config_path = _both_mode_config(
        tmp_path,
        audit_path,
        secret_name="FILE_SECRET",
        placeholder=placeholder,
        host="file.example.com",
    )
    monkeypatch.setattr(
        placeholders,
        "load_or_create_install_salt",
        lambda salt_path: (_ for _ in ()).throw(OSError("salt unavailable")),
    )
    caplog.set_level("WARNING", logger="agent_vault_proxy.addon")

    addon = AgentVaultProxyAddon()
    addon.configure_from_path(
        str(config_path),
        backend_override=_FakeNotesListBackend(
            {"FILE_SECRET": ("real-file-secret", "host: notes.example.com")}
        ),
    )

    flow = _make_request("file.example.com", {"Authorization": f"Bearer {placeholder}"})
    addon.requestheaders(flow)

    assert flow.request.headers["Authorization"] == "Bearer real-file-secret"
    assert any(
        "degraded" in r.message and "file bindings only" in r.message for r in caplog.records
    )


def test_both_mode_degrades_to_file_bindings_when_backend_cannot_list(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    class _CannotListBackend:
        def list_secret_names(self) -> list[str]:
            raise BackendCannotListError("listing disabled")

        def fetch(self, name, ctx=None) -> str:
            assert name == "FILE_SECRET"
            return "real-file-secret"

    audit_path = tmp_path / "audit.jsonl"
    placeholder = "file-PLACEHOLDER-01HXY1234567890LIST1"
    config_path = _both_mode_config(
        tmp_path,
        audit_path,
        secret_name="FILE_SECRET",
        placeholder=placeholder,
        host="file.example.com",
    )
    caplog.set_level("WARNING", logger="agent_vault_proxy.addon")

    addon = AgentVaultProxyAddon()
    addon.configure_from_path(str(config_path), backend_override=_CannotListBackend())

    flow = _make_request("file.example.com", {"Authorization": f"Bearer {placeholder}"})
    addon.requestheaders(flow)

    assert flow.request.headers["Authorization"] == "Bearer real-file-secret"
    assert any(
        "degraded" in r.message and "file bindings only" in r.message for r in caplog.records
    )


@pytest.mark.parametrize("failure_kind", ["salt", "list"])
def test_bws_notes_mode_degrades_to_no_bindings_without_crashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    failure_kind: str,
) -> None:
    import agent_vault_proxy.placeholders as placeholders

    class _CannotListBackend:
        def list_secret_names(self) -> list[str]:
            raise BackendCannotListError("listing disabled")

        def fetch(self, name, ctx=None) -> str:
            return "unused"

    backend: object = _FakeNotesListBackend({"FOO": ("real", "host: api.example.com")})
    if failure_kind == "salt":
        monkeypatch.setattr(
            placeholders,
            "load_or_create_install_salt",
            lambda salt_path: (_ for _ in ()).throw(OSError("salt unavailable")),
        )
    else:
        backend = _CannotListBackend()

    caplog.set_level("WARNING", logger="agent_vault_proxy.addon")
    addon = AgentVaultProxyAddon()
    config_path = _bws_notes_config(tmp_path, tmp_path / "audit.jsonl")
    addon.configure_from_path(str(config_path), backend_override=backend)

    assert addon.config is not None
    assert addon.config.secrets == {}
    flow = _make_request("api.example.com", {"Authorization": "Bearer avp-PLACEHOLDER-test"})
    addon.requestheaders(flow)
    assert flow.request.headers["Authorization"] == "Bearer avp-PLACEHOLDER-test"
    assert any("degraded" in r.message and "no bindings" in r.message for r in caplog.records)
