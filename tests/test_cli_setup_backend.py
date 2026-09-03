"""Tests for `avp setup` backend selection: the interactive picker, the GSM
backend (keyless, hands off to `avp gcp-setup`), and graceful handling when no
BWS token is provided."""

from __future__ import annotations

import builtins

import pytest
import yaml

from kow.cli.main import main
from kow.cli.setup import (
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


def test_prompt_backend_maps_new_backends(monkeypatch):
    # aws + keychain were appended as 4 and 5; 1/2/3 stay bws/gsm/static.
    for answer, expected in [("4", "aws"), ("5", "keychain")]:
        monkeypatch.setattr(builtins, "input", lambda _prompt, a=answer: a)
        assert _prompt_backend() == expected


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


# ── AWS Secrets Manager backend rendering + planning ─────────────────────────
def test_aws_bindings_are_keyless_notes_and_secure_by_default():
    paths = default_paths("linux", None)
    content = _render_bindings(paths, backend="aws")
    assert "type: aws-secrets-manager" in content
    assert "binding_source: notes" in content
    assert "secret_prefix:" in content
    assert "self_check: deny" in content
    assert "require_temporary_credentials: true" in content
    # Keyless by design: no static IAM-user key material may appear.
    assert "aws_access_key_id" not in content
    assert "aws_secret_access_key" not in content
    # Notes-aware like GSM: no config-file secrets block (checked structurally,
    # since the header comment legitimately mentions the word "secrets").
    assert "secrets" not in yaml.safe_load(content)


def test_aws_plan_has_no_token_prompt_and_no_static_file():
    paths = default_paths("linux", None)
    steps = plan_setup(os_name="linux", user="avp", group="avp", paths=paths, aws=True)
    assert not any(isinstance(s, PromptStep) for s in steps)  # nothing to paste
    bindings = [
        getattr(s, "content", "") for s in steps if getattr(s, "path", "").endswith("bindings.yaml")
    ]
    assert bindings and "type: aws-secrets-manager" in bindings[0]
    assert not any(getattr(s, "path", "").endswith("static-secrets.yaml") for s in steps)


# ── macOS Keychain backend rendering + planning ──────────────────────────────
def test_keychain_bindings_are_keyless_file_source_and_valid():
    from kow.config import Config

    paths = default_paths("macos", None)
    content = _render_bindings(paths, backend="keychain")
    assert "type: keychain" in content
    assert "service: kow" in content
    # Value-only backend (no notes metadata): bindings live in this file.
    assert "binding_source: file" in content
    # The rendered starter must be a valid config.
    cfg = Config.model_validate(yaml.safe_load(content))
    assert cfg.backend is not None
    assert cfg.backend.type == "keychain"
    assert cfg.binding_source == "file"


def test_keychain_plan_has_no_token_prompt_and_no_static_file():
    paths = default_paths("macos", None)
    steps = plan_setup(
        os_name="macos", user="_avp", group="_avp", uid=250, gid=250, paths=paths, keychain=True
    )
    assert not any(isinstance(s, PromptStep) for s in steps)  # keyless — nothing to paste
    bindings = [
        getattr(s, "content", "") for s in steps if getattr(s, "path", "").endswith("bindings.yaml")
    ]
    assert bindings and "type: keychain" in bindings[0]
    assert not any(getattr(s, "path", "").endswith("static-secrets.yaml") for s in steps)


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
    monkeypatch.setattr("kow.cli.setup.getpass", lambda _prompt: "")
    step = _token_step(tmp_path)
    _execute_prompt_step(step, dry_run=False)
    assert not (tmp_path / "bws-token").exists()  # no 0-byte junk file
    err = capsys.readouterr().err
    assert "no BWS token" in err
    assert "--static" in err and "--gsm" in err  # offers the alternatives


def test_nonempty_token_is_written_stripped(tmp_path, monkeypatch):
    monkeypatch.setattr("kow.cli.setup.getpass", lambda _prompt: "  0.abc.tok  ")
    step = _token_step(tmp_path)
    _execute_prompt_step(step, dry_run=False)
    assert (tmp_path / "bws-token").read_text() == "0.abc.tok"


# ── run_setup wiring: picker on no-flag, GSM hand-off ────────────────────────
def _stub_run_setup_env(monkeypatch):
    monkeypatch.setattr("kow.cli.setup.platform.system", lambda: "Linux")
    monkeypatch.setattr("kow.cli.setup.os.geteuid", lambda: 0)
    monkeypatch.setattr("kow.cli.setup.execute_plan", lambda steps, dry_run: None)
    monkeypatch.setattr("kow.cli.setup.run_doctor", lambda **kwargs: 0)


def test_no_flag_on_tty_invokes_picker(monkeypatch):
    _stub_run_setup_env(monkeypatch)
    monkeypatch.setattr("kow.cli.setup.sys.stdin.isatty", lambda: True)
    called = {"picker": False}

    def _picker():
        called["picker"] = True
        return "static"

    monkeypatch.setattr("kow.cli.setup._prompt_backend", _picker)
    run_setup(user=None, dry_run=False, prefix=None)
    assert called["picker"] is True


def test_no_flag_off_tty_defaults_bws_no_picker(monkeypatch):
    _stub_run_setup_env(monkeypatch)
    monkeypatch.setattr("kow.cli.setup.sys.stdin.isatty", lambda: False)

    def _boom():
        raise AssertionError("picker must not run off a TTY")

    monkeypatch.setattr("kow.cli.setup._prompt_backend", _boom)
    assert run_setup(user=None, dry_run=False, prefix=None) == 0


def test_gsm_prints_gcp_setup_handoff(monkeypatch, capsys):
    _stub_run_setup_env(monkeypatch)
    run_setup(user=None, dry_run=False, prefix=None, gsm=True)
    out = capsys.readouterr().out
    assert "GSM backend selected" in out
    assert "kow gcp-setup" in out


def test_aws_prints_iam_handoff(monkeypatch, capsys):
    _stub_run_setup_env(monkeypatch)
    run_setup(user=None, dry_run=False, prefix=None, aws=True)
    out = capsys.readouterr().out
    assert "AWS Secrets Manager backend selected" in out
    assert "secretsmanager:GetSecretValue" in out
    assert "self_check: deny" in out


# ── keychain is macOS-only: the guard refuses it off a Mac ───────────────────
def test_keychain_refused_off_macos(monkeypatch, capsys):
    monkeypatch.setattr("kow.cli.setup.platform.system", lambda: "Linux")
    monkeypatch.setattr("kow.cli.setup.os.geteuid", lambda: 0)

    def _must_not_run(*_a, **_k):
        raise AssertionError("must refuse before touching the host")

    monkeypatch.setattr("kow.cli.setup.execute_plan", _must_not_run)
    monkeypatch.setattr("kow.cli.setup.run_doctor", _must_not_run)
    rc = run_setup(user=None, dry_run=False, prefix=None, keychain=True)
    assert rc != 0
    err = capsys.readouterr().err
    assert "macOS" in err
    assert "keychain" in err.lower()


def test_keychain_allowed_on_macos(monkeypatch):
    monkeypatch.setattr("kow.cli.setup.platform.system", lambda: "Darwin")
    monkeypatch.setattr("kow.cli.setup.os.geteuid", lambda: 0)
    monkeypatch.setattr("kow.cli.setup.execute_plan", lambda steps, dry_run: None)
    monkeypatch.setattr("kow.cli.setup.run_doctor", lambda **kwargs: 0)
    monkeypatch.setattr("kow.cli.setup._user_exists", lambda _user: True)
    # Guard must NOT fire on a Mac; run completes and returns the doctor rc.
    assert run_setup(user=None, dry_run=False, prefix=None, keychain=True) == 0


# ── CLI mutual exclusion ────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "flags",
    [
        ["--gsm", "--static"],
        ["--keychain", "--aws"],
        ["--keychain", "--bws"],
        ["--aws", "--static"],
        ["--aws", "--gsm"],
    ],
)
def test_backend_flags_are_mutually_exclusive(flags):
    with pytest.raises(SystemExit):
        main(["setup", *flags])
