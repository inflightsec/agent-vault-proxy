"""Step executors and macOS id helpers in ``cli.setup``.

These cover the side-effecting executor branches (skip conditions, non-fatal
command failures, the hidden-prompt step) and the pure macOS uid/gid
allocation helpers (driven with a faked ``dscl``). All run unprivileged: the
owner/group chown paths early-return when euid != 0, which is the case here.
"""

from __future__ import annotations

import pytest

from kow.cli import setup as setup_mod
from kow.cli.setup import CommandStep, PromptStep

# --------------------------------------------------------------------------
# _execute_command_step
# --------------------------------------------------------------------------


def test_command_step_dry_run_prints_and_skips(capsys) -> None:
    step = CommandStep(description="make widget", argv=("true",))
    setup_mod._execute_command_step(step, dry_run=True)
    assert "[dry-run] make widget" in capsys.readouterr().out


def test_command_step_skips_when_user_exists(capsys) -> None:
    # root always exists; the step must be skipped without running argv.
    step = CommandStep(description="add user", argv=("false",), skip_if_user_exists="root")
    setup_mod._execute_command_step(step, dry_run=False)
    assert "Skipping" in capsys.readouterr().out


def test_command_step_skips_when_path_exists(tmp_path, capsys) -> None:
    marker = tmp_path / "already-there"
    marker.write_text("x")
    step = CommandStep(description="seed path", argv=("false",), skip_if_path_exists=str(marker))
    setup_mod._execute_command_step(step, dry_run=False)
    assert "Skipping" in capsys.readouterr().out


def test_command_step_runs_successfully(capsys) -> None:
    setup_mod._execute_command_step(CommandStep(description="ok", argv=("true",)), dry_run=False)


def test_command_step_nonfatal_failure_warns(capsys) -> None:
    step = CommandStep(description="optional attr", argv=("false",), allow_attr_unsupported=True)
    setup_mod._execute_command_step(step, dry_run=False)
    assert "non-fatal" in capsys.readouterr().err


def test_command_step_fatal_failure_raises() -> None:
    step = CommandStep(description="required", argv=("false",))
    with pytest.raises(RuntimeError, match="command failed"):
        setup_mod._execute_command_step(step, dry_run=False)


# --------------------------------------------------------------------------
# _execute_prompt_step
# --------------------------------------------------------------------------


def _prompt(dest, *, skip_if_exists=True) -> PromptStep:
    return PromptStep(
        description="paste token",
        dest_path=str(dest),
        owner="root",
        group="root",
        mode=0o600,
        skip_if_exists=skip_if_exists,
    )


def test_prompt_step_dry_run_prints(tmp_path, capsys) -> None:
    setup_mod._execute_prompt_step(_prompt(tmp_path / "tok"), dry_run=True)
    assert "[dry-run]" in capsys.readouterr().out


def test_prompt_step_skips_when_dest_exists(tmp_path, capsys) -> None:
    dest = tmp_path / "tok"
    dest.write_text("old")
    setup_mod._execute_prompt_step(_prompt(dest), dry_run=False)
    assert "already exists" in capsys.readouterr().out
    assert dest.read_text() == "old"  # untouched


def test_prompt_step_writes_hidden_token(tmp_path, monkeypatch) -> None:
    dest = tmp_path / "sub" / "tok"
    monkeypatch.setattr(setup_mod, "getpass", lambda _prompt: "s3cret-token")
    setup_mod._execute_prompt_step(_prompt(dest, skip_if_exists=False), dry_run=False)
    assert dest.read_text() == "s3cret-token"


# --------------------------------------------------------------------------
# macOS uid/gid helpers (pure logic, faked dscl)
# --------------------------------------------------------------------------


def _fake_proc(stdout: str, returncode: int = 0):
    class P:
        pass

    p = P()
    p.stdout = stdout
    p.stderr = ""
    p.returncode = returncode
    return p


def test_list_macos_ids_parses_and_skips_malformed(monkeypatch) -> None:
    out = "_avp 250\nbroken-line\n_other notanint\n_svc 251\n"
    monkeypatch.setattr(setup_mod.subprocess, "run", lambda *a, **k: _fake_proc(out))
    ids = setup_mod._list_macos_ids("/Users", "UniqueID")
    assert ids == {"_avp": 250, "_svc": 251}


def test_list_macos_ids_raises_on_dscl_failure(monkeypatch) -> None:
    monkeypatch.setattr(setup_mod.subprocess, "run", lambda *a, **k: _fake_proc("", returncode=1))
    with pytest.raises(RuntimeError, match="failed to list macOS ids"):
        setup_mod._list_macos_ids("/Users", "UniqueID")


def test_next_macos_uid_gid_returns_first_free(monkeypatch) -> None:
    # 250 and 251 are taken across users+groups; first free is 252.
    def fake_ids(path, attr):
        return {"a": 250} if "Users" in path else {"b": 251}

    monkeypatch.setattr(setup_mod, "_list_macos_ids", fake_ids)
    assert setup_mod._next_macos_uid_gid() == (252, 252)


def test_is_macos_id_collision_error() -> None:
    assert setup_mod._is_macos_id_collision_error(RuntimeError("eDSRecordAlreadyExists"))
    assert setup_mod._is_macos_id_collision_error(RuntimeError("already exists"))
    assert not setup_mod._is_macos_id_collision_error(RuntimeError("some other failure"))


def test_macos_ids_owned_by(monkeypatch) -> None:
    monkeypatch.setattr(
        setup_mod,
        "_list_macos_ids",
        lambda path, attr: {"_avp": 250} if "Users" in path else {"_avp": 250},
    )
    assert setup_mod._macos_ids_owned_by(user="_avp", group="_avp", candidate=250)
    assert not setup_mod._macos_ids_owned_by(user="_avp", group="_avp", candidate=999)
