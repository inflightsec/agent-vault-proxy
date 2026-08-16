"""``avp env`` — project-secret -> placeholder env-file projection.

``avp env`` lists the BWS project's secrets via the configured backend,
validates each secret NAME against ``^[A-Za-z_][A-Za-z0-9_]*$`` (REJECT,
never sanitize — a bad name is skipped with a warning so one typo can't
break the whole file), derives the salted placeholder for each valid name,
and writes a validated, eval-safe env file (default ``~/.config/avp/env``,
mode 0600) with one ``export NAME='<placeholder>'`` line per valid secret.

The env file is the projection that lets the operator edit ONLY Bitwarden:
add a secret in BWS, re-run ``avp env --refresh``, and the agent's
environment gains the new placeholder. The agent never sees a real value.
"""

from __future__ import annotations

import os
import stat

import pytest

from kow.cli.env import (
    VALID_SECRET_NAME_RE,
    build_export_lines,
    list_secret_names,
    run_env,
    write_env_file,
)
from kow.secret import Secret

_SALT = b"\x07" * 32


class _FakeListBackend:
    """Backend exposing the name->id list call ``avp env`` relies on, plus a
    minimal fetch so it satisfies the wider backend surface in tests."""

    def __init__(self, names: list[str]) -> None:
        self._names = names

    def list_secret_names(self) -> list[str]:
        return list(self._names)

    def fetch(self, name: str, ctx=None) -> Secret:  # pragma: no cover - unused here
        return Secret("x")


# --------------------------------------------------------------------------
# name validation
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["FOO", "_x", "API_KEY_1", "github_pat"])
def test_valid_names_accepted(name: str) -> None:
    assert VALID_SECRET_NAME_RE.match(name)


@pytest.mark.parametrize(
    "name",
    ["1FOO", "FOO BAR", "FOO-BAR", "FOO;rm -rf", "", "FOO$(x)", "FOO\nBAR", "FOO'"],
)
def test_invalid_names_rejected(name: str) -> None:
    assert not VALID_SECRET_NAME_RE.match(name)


# --------------------------------------------------------------------------
# build_export_lines
# --------------------------------------------------------------------------


def test_build_export_lines_single_quotes_placeholder() -> None:
    lines, skipped = build_export_lines(["FOO"], _SALT)
    assert len(lines) == 1
    assert skipped == []
    # Single-quoted, export form, placeholder by construction has no metachars.
    assert lines[0].startswith("export FOO='avp-PLACEHOLDER-")
    assert lines[0].endswith("'")


def test_build_export_lines_skips_invalid_names_without_failing() -> None:
    """A single bad name must NOT break the whole file — it's skipped and
    reported, the valid names still produce lines."""
    lines, skipped = build_export_lines(["GOOD", "1BAD", "also-bad"], _SALT)
    assert any(line.startswith("export GOOD=") for line in lines)
    assert "1BAD" in skipped
    assert "also-bad" in skipped
    assert not any("1BAD" in line for line in lines)
    assert not any("also-bad" in line for line in lines)


def test_build_export_lines_never_emits_eval_unsafe_content() -> None:
    """Defense in depth: even though placeholders are metachar-free by
    construction, assert no shell-dangerous byte reaches a line."""
    lines, _skipped = build_export_lines(["A", "B", "C"], _SALT)
    for line in lines:
        for bad in ("$", "`", "\\", "\n", "\r", ";", "&", "|", '"'):
            assert bad not in line, (bad, line)


def test_build_export_lines_is_deterministic() -> None:
    first, _ = build_export_lines(["FOO", "BAR"], _SALT)
    second, _ = build_export_lines(["FOO", "BAR"], _SALT)
    assert first == second


# --------------------------------------------------------------------------
# write_env_file — 0600, atomic-ish
# --------------------------------------------------------------------------


def test_write_env_file_mode_0600(tmp_path) -> None:
    env_path = tmp_path / "env"
    write_env_file(env_path, ["export FOO='avp-PLACEHOLDER-aaaaaaaaaaaaaaaaaaaaa'"])
    mode = stat.S_IMODE(os.stat(env_path).st_mode)
    assert mode == 0o600, oct(mode)


def test_write_env_file_creates_parent(tmp_path) -> None:
    env_path = tmp_path / "config" / "avp" / "env"
    write_env_file(env_path, ["export FOO='x'"])
    assert env_path.exists()


def test_write_env_file_overwrites_on_refresh(tmp_path) -> None:
    env_path = tmp_path / "env"
    write_env_file(env_path, ["export OLDVAR='1'"])
    write_env_file(env_path, ["export NEWVAR='2'"])
    body = env_path.read_text()
    assert "OLDVAR" not in body
    assert "NEWVAR" in body


# --------------------------------------------------------------------------
# list_secret_names dispatch
# --------------------------------------------------------------------------


def test_list_secret_names_uses_backend_helper() -> None:
    backend = _FakeListBackend(["A", "B"])
    assert list_secret_names(backend) == ["A", "B"]


# --------------------------------------------------------------------------
# run_env — end to end against a fake backend (no real BWS)
# --------------------------------------------------------------------------


def _write_config(tmp_path, audit_path, install_salt_path=None) -> str:
    secrets_file = tmp_path / "secrets.yaml"
    secrets_file.write_text("secrets:\n  A: secret-a\n  B: secret-b\n")
    secrets_file.chmod(0o600)
    salt_line = f"install_salt_path: {install_salt_path}\n" if install_salt_path else ""
    yaml = f"""
version: 1
{salt_line}secrets:
  PLACEHOLDER_ONLY:
    placeholder: "avp-PLACEHOLDER-zzzzzzzzzzzzzzzzzzzzzzzz"
    inject:
      header: "Authorization"
      format: "Bearer {{PLACEHOLDER_ONLY}}"
    bindings:
      - host: api.example.com
audit:
  path: {audit_path}
backend:
  type: static
  config:
    type: static
    path: {secrets_file}
"""
    p = tmp_path / "bindings.yaml"
    p.write_text(yaml)
    return str(p)


def test_run_env_writes_file_from_backend(tmp_path, monkeypatch) -> None:
    cfg_path = _write_config(tmp_path, tmp_path / "audit.jsonl")
    env_path = tmp_path / "out-env"
    salt_path = tmp_path / "install-salt"

    rc = run_env(
        config_path=cfg_path,
        env_path=str(env_path),
        salt_path=str(salt_path),
        print_only=False,
        refresh=True,
    )
    assert rc == 0
    body = env_path.read_text()
    assert "export A='avp-PLACEHOLDER-" in body
    assert "export B='avp-PLACEHOLDER-" in body
    # The hint snippet for the profile is printed, not written into the file.
    assert "set -a" not in body


def test_run_env_print_only_does_not_write(tmp_path, capsys) -> None:
    cfg_path = _write_config(tmp_path, tmp_path / "audit.jsonl")
    env_path = tmp_path / "out-env"
    salt_path = tmp_path / "install-salt"

    rc = run_env(
        config_path=cfg_path,
        env_path=str(env_path),
        salt_path=str(salt_path),
        print_only=True,
        refresh=False,
    )
    assert rc == 0
    assert not env_path.exists()
    out = capsys.readouterr().out
    assert "export A='avp-PLACEHOLDER-" in out


def test_run_env_honors_config_install_salt_path(tmp_path) -> None:
    # With no --salt, avp env must derive against the config's install_salt_path
    # (the same value the daemon uses) — NOT $HOME — so the projected env file
    # and the running proxy agree on the placeholder.
    cfg_salt = tmp_path / "cfg-salt"
    cfg_path = _write_config(tmp_path, tmp_path / "audit.jsonl", install_salt_path=str(cfg_salt))
    env_path = tmp_path / "out-env"
    rc = run_env(
        config_path=cfg_path,
        env_path=str(env_path),
        salt_path=None,  # no --salt → fall back to config.install_salt_path
        print_only=False,
        refresh=True,
    )
    assert rc == 0
    assert cfg_salt.exists(), "salt should be created at the config-pinned path"
    assert "export A='avp-PLACEHOLDER-" in env_path.read_text()


def test_run_env_explicit_salt_overrides_config(tmp_path) -> None:
    cfg_salt = tmp_path / "cfg-salt"
    explicit_salt = tmp_path / "explicit-salt"
    cfg_path = _write_config(tmp_path, tmp_path / "audit.jsonl", install_salt_path=str(cfg_salt))
    rc = run_env(
        config_path=cfg_path,
        env_path=str(tmp_path / "out-env"),
        salt_path=str(explicit_salt),  # --salt wins over config
        print_only=False,
        refresh=True,
    )
    assert rc == 0
    assert explicit_salt.exists()
    assert not cfg_salt.exists(), "config path must be ignored when --salt is given"


def test_env_projects_the_file_declared_placeholder(tmp_path, capsys) -> None:
    """`kow env` must emit exactly what the daemon enforces.

    In `binding_source: file` the daemon matches `spec.placeholder`. Projecting
    a derived placeholder instead hands the agent a token the proxy does not
    recognise, and the documented `kow env && kow run` flow silently never
    injects — caught by the README VM leg.
    """
    from kow.cli.env import run_env

    declared = "sk-PLACEHOLDER-declared0000111122223"
    secrets = tmp_path / "secrets.yaml"
    secrets.write_text('secrets:\n  DECLARED_KEY: "real-value-xyz"\n')
    secrets.chmod(0o600)
    cfg = tmp_path / "bindings.yaml"
    cfg.write_text(f"""
version: 1
binding_source: file
secrets:
  DECLARED_KEY:
    placeholder: "{declared}"
    inject: {{header: "Authorization", format: "Bearer {{DECLARED_KEY}}"}}
    bindings: [{{host: "api.example.com"}}]
backend:
  type: static
  config:
    type: static
    path: {secrets}
audit: {{path: {tmp_path / "audit.jsonl"}}}
""")
    rc = run_env(config_path=str(cfg), salt_path=str(tmp_path / "salt"), print_only=True)
    assert rc == 0
    out = capsys.readouterr().out
    assert f"export DECLARED_KEY='{declared}'" in out, out
    assert "real-value-xyz" not in out
