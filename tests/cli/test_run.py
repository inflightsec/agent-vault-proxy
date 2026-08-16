"""Tests for ``avp run`` / ``avp sandvault`` launcher."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from kow.cli import run as run_mod


@pytest.fixture
def ca_path(tmp_path: Path) -> Path:
    p = tmp_path / "ca.pem"
    p.write_text("CA")
    return p


def _ns(**kwargs: Any) -> argparse.Namespace:
    defaults: dict[str, Any] = {
        "ca_cert": None,
        "proxy": "http://127.0.0.1:14322",
        "sandvault": False,
        # Default no_env_file=True so existing tests don't pick up the test
        # runner's real ~/.config/avp/env. Tests of env-file loading override
        # both keys explicitly.
        "env_file": "~/.config/avp/env",
        "no_env_file": True,
        "argv": [],
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def test_run_execs_command_with_avp_env(monkeypatch: pytest.MonkeyPatch, ca_path: Path) -> None:
    captured: dict[str, Any] = {}

    def fake_exec(file: str, argv: list[str], env: dict[str, str]) -> None:
        captured["file"] = file
        captured["argv"] = argv
        captured["env"] = env
        raise SystemExit(0)

    monkeypatch.setattr(run_mod.os, "execvpe", fake_exec)
    with pytest.raises(SystemExit) as exc:
        run_mod.run_run(_ns(ca_cert=str(ca_path), argv=["claude", "--print"]))
    assert exc.value.code == 0
    assert captured["file"] == "claude"
    assert captured["argv"] == ["claude", "--print"]
    assert captured["env"]["HTTPS_PROXY"] == "http://127.0.0.1:14322"
    assert captured["env"]["NODE_EXTRA_CA_CERTS"] == str(ca_path)
    assert captured["env"]["SSL_CERT_FILE"] == str(ca_path)
    assert captured["env"]["NODE_USE_ENV_PROXY"] == "1"


def test_run_strips_leading_double_dash(monkeypatch: pytest.MonkeyPatch, ca_path: Path) -> None:
    captured: dict[str, Any] = {}

    def fake_exec(file: str, argv: list[str], env: dict[str, str]) -> None:
        captured["argv"] = argv
        raise SystemExit(0)

    monkeypatch.setattr(run_mod.os, "execvpe", fake_exec)
    with pytest.raises(SystemExit):
        run_mod.run_run(_ns(ca_cert=str(ca_path), argv=["--", "claude"]))
    assert captured["argv"] == ["claude"]


def test_run_errors_without_command(ca_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        run_mod.run_run(_ns(ca_cert=str(ca_path), argv=[]))
    assert "usage" in str(exc.value)


def test_run_errors_when_ca_missing(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        run_mod.run_run(_ns(ca_cert=str(tmp_path / "no.pem"), argv=["claude"]))
    assert "CA not found" in str(exc.value)


def _exec_recorder(captured: dict[str, Any]):
    """Fake execvpe that records args and exits cleanly."""

    def fake(file: str, argv: list[str], env: dict[str, str]) -> None:
        captured["file"] = file
        captured["argv"] = argv
        captured["env"] = env
        raise SystemExit(0)

    return fake


def test_run_does_not_mutate_host_environ(monkeypatch: pytest.MonkeyPatch, ca_path: Path) -> None:
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    captured: dict[str, Any] = {}
    monkeypatch.setattr(run_mod.os, "execvpe", _exec_recorder(captured))
    with pytest.raises(SystemExit):
        run_mod.run_run(_ns(ca_cert=str(ca_path), argv=["claude"]))
    # The host's HTTPS_PROXY MUST remain unset — env routing only lives in the
    # spawned process's env dict, never in os.environ.
    assert os.environ.get("HTTPS_PROXY") is None


def test_sandvault_wraps_when_binary_present(
    monkeypatch: pytest.MonkeyPatch, ca_path: Path
) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(run_mod.shutil, "which", lambda _name: "/usr/local/bin/sandvault")
    monkeypatch.setattr(run_mod.os, "execvpe", _exec_recorder(captured))
    with pytest.raises(SystemExit):
        run_mod.run_run(_ns(ca_cert=str(ca_path), argv=["claude"], sandvault=True))
    assert captured["file"] == "/usr/local/bin/sandvault"
    assert captured["argv"] == ["/usr/local/bin/sandvault", "--", "claude"]


def test_sandvault_errors_when_binary_missing(
    monkeypatch: pytest.MonkeyPatch, ca_path: Path
) -> None:
    monkeypatch.setattr(run_mod.shutil, "which", lambda _name: None)
    with pytest.raises(SystemExit) as exc:
        run_mod.run_run(_ns(ca_cert=str(ca_path), argv=["claude"], sandvault=True))
    assert "sandvault not found" in str(exc.value)
    assert "brew install" in str(exc.value)


def test_run_propagates_existing_environ(monkeypatch: pytest.MonkeyPatch, ca_path: Path) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setenv("MY_TOKEN", "abc")
    monkeypatch.setattr(run_mod.os, "execvpe", _exec_recorder(captured))
    with pytest.raises(SystemExit):
        run_mod.run_run(_ns(ca_cert=str(ca_path), argv=["claude"]))
    assert captured["env"]["MY_TOKEN"] == "abc"
    assert captured["env"]["HTTPS_PROXY"] == "http://127.0.0.1:14322"


def test_default_ca_path_per_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    assert run_mod._default_ca_path() == run_mod._MACOS_CA
    monkeypatch.setattr(sys, "platform", "linux")
    assert run_mod._default_ca_path() == run_mod._LINUX_CA


def test_register_subparser_adds_run_and_sandvault() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")
    run_mod.register_run_subparser(sub)

    args = parser.parse_args(["run", "claude"])
    assert args.command == "run"
    assert args.argv == ["claude"]
    assert args.sandvault is False
    assert args.env_file == "~/.config/kow/env"
    assert args.no_env_file is False

    args = parser.parse_args(["run", "--sandvault", "claude", "--print"])
    assert args.command == "run"
    assert args.sandvault is True
    assert args.argv == ["claude", "--print"]

    args = parser.parse_args(["run", "--no-env-file", "claude"])
    assert args.no_env_file is True

    args = parser.parse_args(["run", "--env-file", "/tmp/other-env", "claude"])
    assert args.env_file == "/tmp/other-env"

    sv = parser.parse_args(["sandvault", "claude"])
    assert sv.command == "sandvault"
    assert sv.sandvault is True
    assert sv.argv == ["claude"]


def test_load_env_file_parses_valid_exports(tmp_path: Path) -> None:
    p = tmp_path / "env"
    p.write_text(
        "# placeholder env file\n"
        "export STRIPE_API_KEY='avp-PLACEHOLDER-abc123'\n"
        "export GITHUB_PAT='avp-PLACEHOLDER-def456'\n"
        "\n"
    )
    out = run_mod._load_env_file(p)
    assert out == {
        "STRIPE_API_KEY": "avp-PLACEHOLDER-abc123",
        "GITHUB_PAT": "avp-PLACEHOLDER-def456",
    }


def test_load_env_file_missing_returns_empty(tmp_path: Path) -> None:
    # First-run / no-secrets case — must not error.
    assert run_mod._load_env_file(tmp_path / "no-such-file") == {}


def test_load_env_file_skips_malformed_lines(tmp_path: Path) -> None:
    # We never run the file through a shell — malformed lines are ignored,
    # not evaluated, so an attacker who somehow controls a line in the env
    # file cannot inject shell commands or unquoted values.
    p = tmp_path / "env"
    p.write_text(
        "export OK='avp-PLACEHOLDER-good'\n"
        'export BAD_DOUBLE_QUOTE="x"\n'
        "export NO_QUOTES=raw-value\n"
        "FOO='no-export'\n"
        "export bad-name='x'\n"
        "$(rm -rf /)\n"
        "export EVIL='value-with-newline\n"
        "continued'\n"
    )
    out = run_mod._load_env_file(p)
    assert out == {"OK": "avp-PLACEHOLDER-good"}


def test_run_auto_loads_env_file(
    monkeypatch: pytest.MonkeyPatch, ca_path: Path, tmp_path: Path
) -> None:
    env_file = tmp_path / "avp-env"
    env_file.write_text("export STRIPE_API_KEY='avp-PLACEHOLDER-xyz'\n")
    captured: dict[str, Any] = {}
    monkeypatch.setattr(run_mod.os, "execvpe", _exec_recorder(captured))
    with pytest.raises(SystemExit):
        run_mod.run_run(
            _ns(
                ca_cert=str(ca_path),
                argv=["claude"],
                env_file=str(env_file),
                no_env_file=False,
            )
        )
    assert captured["env"]["STRIPE_API_KEY"] == "avp-PLACEHOLDER-xyz"
    assert captured["env"]["HTTPS_PROXY"] == "http://127.0.0.1:14322"


def test_run_skips_env_file_when_flag_set(
    monkeypatch: pytest.MonkeyPatch, ca_path: Path, tmp_path: Path
) -> None:
    env_file = tmp_path / "avp-env"
    env_file.write_text("export STRIPE_API_KEY='avp-PLACEHOLDER-xyz'\n")
    monkeypatch.delenv("STRIPE_API_KEY", raising=False)
    captured: dict[str, Any] = {}
    monkeypatch.setattr(run_mod.os, "execvpe", _exec_recorder(captured))
    with pytest.raises(SystemExit):
        run_mod.run_run(
            _ns(
                ca_cert=str(ca_path),
                argv=["claude"],
                env_file=str(env_file),
                no_env_file=True,
            )
        )
    assert "STRIPE_API_KEY" not in captured["env"]


def test_run_routing_vars_win_over_env_file(
    monkeypatch: pytest.MonkeyPatch, ca_path: Path, tmp_path: Path
) -> None:
    # Defense in depth: if a placeholder file somehow contained HTTPS_PROXY,
    # the routing var set by avp run must still win.
    env_file = tmp_path / "avp-env"
    env_file.write_text("export HTTPS_PROXY='http://attacker.example:8080'\n")
    captured: dict[str, Any] = {}
    monkeypatch.setattr(run_mod.os, "execvpe", _exec_recorder(captured))
    with pytest.raises(SystemExit):
        run_mod.run_run(
            _ns(
                ca_cert=str(ca_path),
                argv=["claude"],
                env_file=str(env_file),
                no_env_file=False,
            )
        )
    assert captured["env"]["HTTPS_PROXY"] == "http://127.0.0.1:14322"


def test_load_env_file_warns_on_malformed_lines(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Silent skips were a debugging trap: if `avp env` ever drifts from this
    # parser's grammar, the operator must see it instead of getting an empty
    # placeholder environment with no explanation.
    p = tmp_path / "env"
    p.write_text("export OK='value'\ngarbage line\n")
    p.chmod(0o600)
    run_mod._load_env_file(p)
    err = capsys.readouterr().err
    assert "skipping" in err and "env:2" in err


def test_load_env_file_warns_on_loose_mode(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    p = tmp_path / "env"
    p.write_text("export OK='value'\n")
    p.chmod(0o644)
    run_mod._load_env_file(p)
    err = capsys.readouterr().err
    assert "0o644" in err


def test_build_avp_env_overrides_lowercase_proxy_variants(ca_path: Path) -> None:
    # Some clients prefer lowercase `https_proxy` over `HTTPS_PROXY` and obey
    # `NO_PROXY` / `no_proxy`. If the host shell sets either, AVP must still
    # win in the spawned process — otherwise traffic bypasses the proxy.
    env = run_mod._build_avp_env(ca_path, "http://127.0.0.1:14322", {})
    for key in ("HTTPS_PROXY", "https_proxy", "http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"):
        assert env[key] == "http://127.0.0.1:14322", key
    for key in ("NO_PROXY", "no_proxy"):
        assert key not in env, key


def test_build_avp_env_strips_inherited_no_proxy(
    monkeypatch: pytest.MonkeyPatch, ca_path: Path
) -> None:
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("no_proxy", "api.example.com")
    env = run_mod._build_avp_env(ca_path, "http://127.0.0.1:14322", {})
    assert "NO_PROXY" not in env
    assert "no_proxy" not in env
