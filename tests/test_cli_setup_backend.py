"""Tests for `avp setup` backend selection: the interactive picker, the GSM
backend (keyless, hands off to `avp gcp-setup`), and graceful handling when no
BWS token is provided."""

from __future__ import annotations

import builtins

import pytest

from agent_vault_proxy.cli.main import main
from agent_vault_proxy.cli.setup import (
    PromptStep,
    _execute_prompt_step,
    _prompt_backend,
    _render_bindings,
    default_paths,
    plan_setup,
    run_setup,
)


# ── interactive picker ──────────────────────────────────────────────────────
def test_prompt_backend_maps_choices(monkeypatch):
    for answer, expected in [("1", "bws"), ("2", "gsm"), ("3", "static")]:
        monkeypatch.setattr(builtins, "input", lambda _prompt, a=answer: a)
        assert _prompt_backend() == expected


def test_prompt_backend_reprompts_until_valid(monkeypatch):
    answers = iter(["9", "x", "2"])  # invalid, invalid, then GSM
    monkeypatch.setattr(builtins, "input", lambda _prompt: next(answers))
    assert _prompt_backend() == "gsm"


# ── GSM backend rendering + planning ────────────────────────────────────────
def test_gsm_bindings_are_keyless_and_secure_by_default():
    paths = default_paths("linux", None)
    content = _render_bindings(paths, backend="gsm")
    assert "type: gsm" in content
    assert "self_check: deny" in content
    assert "reject_ambient_key: true" in content
    assert "project_id:" in content
    # Keyless by design: no key-file field may appear.
    assert "credential_config_path" not in content
    assert "key_file" not in content


def test_gsm_plan_has_no_token_prompt_and_no_static_file():
    paths = default_paths("linux", None)
    steps = plan_setup(os_name="linux", user="avp", group="avp", paths=paths, gsm=True)
    assert not any(isinstance(s, PromptStep) for s in steps)  # nothing to paste
    bindings = [
        getattr(s, "content", "") for s in steps if getattr(s, "path", "").endswith("bindings.yaml")
    ]
    assert bindings and "type: gsm" in bindings[0]
    assert not any(getattr(s, "path", "").endswith("static-secrets.yaml") for s in steps)


def test_bws_plan_still_prompts_for_token():
    paths = default_paths("linux", None)
    steps = plan_setup(os_name="linux", user="avp", group="avp", paths=paths)
    assert any(isinstance(s, PromptStep) for s in steps)


# ── graceful empty-token handling ───────────────────────────────────────────
def _token_step(tmp_path):
    return PromptStep(
        description="Capture the BWS token.",
        dest_path=str(tmp_path / "bws-token"),
        owner="root",
        group="root",
        mode=0o440,
        skip_if_exists=True,
    )


def test_empty_token_writes_nothing_and_explains(tmp_path, monkeypatch, capsys):
    # both getpass prompts return empty
    monkeypatch.setattr("agent_vault_proxy.cli.setup.getpass", lambda _prompt: "")
    step = _token_step(tmp_path)
    _execute_prompt_step(step, dry_run=False)
    assert not (tmp_path / "bws-token").exists()  # no 0-byte junk file
    err = capsys.readouterr().err
    assert "no BWS token" in err
    assert "--static" in err and "--gsm" in err  # offers the alternatives


def test_nonempty_token_is_written_stripped(tmp_path, monkeypatch):
    monkeypatch.setattr("agent_vault_proxy.cli.setup.getpass", lambda _prompt: "  0.abc.tok  ")
    step = _token_step(tmp_path)
    _execute_prompt_step(step, dry_run=False)
    assert (tmp_path / "bws-token").read_text() == "0.abc.tok"


# ── run_setup wiring: picker on no-flag, GSM hand-off ────────────────────────
def _stub_run_setup_env(monkeypatch):
    monkeypatch.setattr("agent_vault_proxy.cli.setup.platform.system", lambda: "Linux")
    monkeypatch.setattr("agent_vault_proxy.cli.setup.os.geteuid", lambda: 0)
    monkeypatch.setattr("agent_vault_proxy.cli.setup.execute_plan", lambda steps, dry_run: None)
    monkeypatch.setattr("agent_vault_proxy.cli.setup.run_doctor", lambda **kwargs: 0)


def test_no_flag_on_tty_invokes_picker(monkeypatch):
    _stub_run_setup_env(monkeypatch)
    monkeypatch.setattr("agent_vault_proxy.cli.setup.sys.stdin.isatty", lambda: True)
    called = {"picker": False}

    def _picker():
        called["picker"] = True
        return "static"

    monkeypatch.setattr("agent_vault_proxy.cli.setup._prompt_backend", _picker)
    run_setup(user=None, dry_run=False, prefix=None)
    assert called["picker"] is True


def test_no_flag_off_tty_defaults_bws_no_picker(monkeypatch):
    _stub_run_setup_env(monkeypatch)
    monkeypatch.setattr("agent_vault_proxy.cli.setup.sys.stdin.isatty", lambda: False)

    def _boom():
        raise AssertionError("picker must not run off a TTY")

    monkeypatch.setattr("agent_vault_proxy.cli.setup._prompt_backend", _boom)
    assert run_setup(user=None, dry_run=False, prefix=None) == 0


def test_gsm_prints_gcp_setup_handoff(monkeypatch, capsys):
    _stub_run_setup_env(monkeypatch)
    run_setup(user=None, dry_run=False, prefix=None, gsm=True)
    out = capsys.readouterr().out
    assert "GSM backend selected" in out
    assert "avp gcp-setup" in out


# ── CLI mutual exclusion ────────────────────────────────────────────────────
def test_backend_flags_are_mutually_exclusive():
    with pytest.raises(SystemExit):
        main(["setup", "--gsm", "--static"])
