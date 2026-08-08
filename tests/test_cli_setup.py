from __future__ import annotations

import os
import pwd
import stat
import xml.dom.minidom

import pytest
import yaml

from kow.cli import setup as setup_mod
from kow.cli.main import main
from kow.cli.setup import (
    CommandStep,
    FileStep,
    PromptStep,
    default_paths,
    execute_plan,
    plan_setup,
    run_setup,
)
from kow.config import Config


def _plan(
    os_name: str,
    *,
    user: str,
    uid: int | None = None,
    gid: int | None = None,
    no_service: bool = False,
    static: bool = False,
):
    paths = default_paths(os_name, None)
    steps = plan_setup(
        os_name=os_name,
        user=user,
        group=user,
        paths=paths,
        uid=uid,
        gid=gid,
        no_service=no_service,
        static=static,
    )
    return paths, steps


def _command_steps(steps):
    commands: list[CommandStep] = []
    for step in steps:
        if isinstance(step, CommandStep):
            commands.append(step)
            continue
        if isinstance(step, FileStep):
            commands.extend(step.pre_actions)
            commands.extend(step.post_actions)
    return commands


def _file_step(steps, path: str) -> FileStep:
    return next(step for step in steps if isinstance(step, FileStep) and step.path == path)


def _prompt_step(steps, dest_path: str) -> PromptStep:
    return next(
        step for step in steps if isinstance(step, PromptStep) and step.dest_path == dest_path
    )


def test_plan_linux_dirs_owners_modes() -> None:
    paths, steps = _plan("linux", user="avp")
    mkdirs = {
        step.argv[-1]: step for step in _command_steps(steps) if step.argv[:2] == ("install", "-d")
    }
    assert mkdirs[paths.confdir].argv == (
        "install",
        "-d",
        "-m",
        "0750",
        "-o",
        "root",
        "-g",
        "avp",
        paths.confdir,
    )
    assert mkdirs[paths.statedir].argv == (
        "install",
        "-d",
        "-m",
        "0750",
        "-o",
        "avp",
        "-g",
        "avp",
        paths.statedir,
    )
    assert mkdirs[paths.logdir].argv == (
        "install",
        "-d",
        "-m",
        "0750",
        "-o",
        "avp",
        "-g",
        "avp",
        paths.logdir,
    )


def test_plan_linux_useradd() -> None:
    _paths, steps = _plan("linux", user="avp")
    useradd = next(
        step for step in _command_steps(steps) if step.argv and step.argv[0] == "useradd"
    )
    assert useradd.argv == (
        "useradd",
        "--system",
        "--no-create-home",
        "--shell",
        "/usr/sbin/nologin",
        "avp",
    )
    assert useradd.skip_if_user_exists == "avp"


def test_plan_linux_audit_appendonly() -> None:
    paths, steps = _plan("linux", user="avp")
    audit = _file_step(steps, paths.audit_path)
    assert audit.mode == 0o640
    # SET append-only is fatal by default; the CLEAR runs first (pre_actions) and is non-fatal.
    assert any(
        action.argv == ("chattr", "+a", paths.audit_path) and not action.allow_attr_unsupported
        for action in audit.post_actions
    )
    assert any(
        action.argv == ("chattr", "-a", paths.audit_path) and action.allow_attr_unsupported
        for action in audit.pre_actions
    )


def test_plan_macos_dirs_owners_modes() -> None:
    paths, steps = _plan("macos", user="_avp", uid=250, gid=250)
    mkdirs = {
        step.argv[-1]: step for step in _command_steps(steps) if step.argv[:2] == ("install", "-d")
    }
    assert mkdirs[paths.confdir].argv == (
        "install",
        "-d",
        "-m",
        "0750",
        "-o",
        "root",
        "-g",
        "_avp",
        paths.confdir,
    )
    assert mkdirs[paths.statedir].argv == (
        "install",
        "-d",
        "-m",
        "0750",
        "-o",
        "_avp",
        "-g",
        "_avp",
        paths.statedir,
    )
    assert mkdirs[paths.logdir].argv == (
        "install",
        "-d",
        "-m",
        "0750",
        "-o",
        "_avp",
        "-g",
        "_avp",
        paths.logdir,
    )


def test_plan_macos_dscl_sequence() -> None:
    _paths, steps = _plan("macos", user="_avp", uid=250, gid=250)
    dscl_argv = [
        step.argv for step in _command_steps(steps) if step.argv and step.argv[0] == "dscl"
    ]
    assert ("dscl", ".", "-create", "/Groups/_avp", "PrimaryGroupID", "250") in dscl_argv
    assert ("dscl", ".", "-create", "/Users/_avp", "UniqueID", "250") in dscl_argv
    assert ("dscl", ".", "-create", "/Users/_avp", "PrimaryGroupID", "250") in dscl_argv
    assert ("dscl", ".", "-create", "/Users/_avp", "UserShell", "/usr/bin/false") in dscl_argv
    assert ("dscl", ".", "-create", "/Users/_avp", "NFSHomeDirectory", "/var/empty") in dscl_argv
    assert ("dscl", ".", "-create", "/Users/_avp", "IsHidden", "1") in dscl_argv


def test_plan_macos_audit_chflags() -> None:
    paths, steps = _plan("macos", user="_avp", uid=250, gid=250)
    audit = _file_step(steps, paths.audit_path)
    # SET append-only is fatal by default; macOS now has a CLEAR step that runs first.
    assert any(
        action.argv == ("chflags", "sappnd", paths.audit_path) and not action.allow_attr_unsupported
        for action in audit.post_actions
    )
    assert any(
        action.argv == ("chflags", "nosappnd", paths.audit_path) and action.allow_attr_unsupported
        for action in audit.pre_actions
    )


def test_plan_token_prompt() -> None:
    paths, steps = _plan("linux", user="avp")
    prompt = _prompt_step(steps, paths.token_path)
    assert prompt.mode == 0o440
    assert prompt.owner == "root"
    assert prompt.group == "avp"
    assert prompt.skip_if_exists is True


def test_plan_starter_bindings_validates_both() -> None:
    for os_name, user, audit_path in (
        ("linux", "avp", "/var/log/agent-vault-proxy/audit.jsonl"),
        ("macos", "_avp", "/usr/local/var/log/agent-vault-proxy/audit.jsonl"),
    ):
        paths, steps = _plan(os_name, user=user, uid=250, gid=250)
        bindings = _file_step(steps, paths.bindings_path)
        raw = yaml.safe_load(bindings.content)
        cfg = Config.model_validate(raw)
        assert cfg.binding_source == "both"
        assert cfg.backend is not None
        assert cfg.backend.type == "bws"
        assert audit_path in bindings.content


@pytest.mark.parametrize(("os_name", "user"), [("linux", "avp"), ("macos", "_avp")])
def test_plan_static_skips_token_prompt_and_validates_bindings(os_name, user) -> None:
    paths, steps = _plan(os_name, user=user, uid=250, gid=250, static=True)
    assert all(not isinstance(step, PromptStep) for step in steps)
    bindings = _file_step(steps, paths.bindings_path)
    raw = yaml.safe_load(bindings.content)
    cfg = Config.model_validate(raw)
    assert cfg.binding_source == "file"
    assert cfg.backend is not None
    assert cfg.backend.type == "static"


@pytest.mark.parametrize(
    ("os_name", "user", "expected_path"),
    [
        ("linux", "avp", "/etc/agent-vault-proxy/static-secrets.yaml"),
        ("macos", "_avp", "/usr/local/etc/agent-vault-proxy/static-secrets.yaml"),
    ],
)
def test_plan_static_secrets_file_matches_bindings_secret_key(
    os_name,
    user,
    expected_path,
) -> None:
    paths, steps = _plan(os_name, user=user, uid=250, gid=250, static=True)
    assert paths.static_secrets_path == expected_path
    bindings = _file_step(steps, paths.bindings_path)
    bindings_raw = yaml.safe_load(bindings.content)
    static_secrets = _file_step(steps, paths.static_secrets_path)
    assert static_secrets.mode == 0o640
    static_raw = yaml.safe_load(static_secrets.content)
    [binding_secret_name] = bindings_raw["secrets"].keys()
    assert binding_secret_name == "EXAMPLE_API_KEY"
    assert static_raw["secrets"] == {binding_secret_name: "change-me-not-a-real-secret"}


def test_plan_ca_and_salt_run_as_user_no_regen() -> None:
    paths, steps = _plan("linux", user="avp")
    commands = _command_steps(steps)
    salt = next(step for step in commands if "load_or_create_install_salt" in " ".join(step.argv))
    ca = next(step for step in commands if "CertStore.from_store" in " ".join(step.argv))
    assert salt.run_as == "avp"
    assert salt.skip_if_path_exists == paths.salt_path
    assert ca.run_as == "avp"
    assert ca.skip_if_path_exists == paths.ca_pem


def test_plan_salt_in_statedir_pinned_in_bindings() -> None:
    # Service user cannot write the root-owned confdir; statedir = daemon
    # HOME, and the bindings pin keeps placeholder derivation in sync.
    for os_name, user in (("linux", "avp"), ("macos", "_avp")):
        paths, steps = _plan(os_name, user=user, uid=250, gid=250)
        assert paths.salt_path == f"{paths.statedir}/install-salt"
        bindings = _file_step(steps, paths.bindings_path)
        raw = yaml.safe_load(bindings.content)
        assert raw["install_salt_path"] == paths.salt_path


def test_plan_public_ca_install_group_per_os() -> None:
    # macOS has no "root" group; gid 0 is "wheel" — `install -g root` would fail.
    for os_name, expected_group in (("linux", "root"), ("macos", "wheel")):
        paths, steps = _plan(os_name, user="avp", uid=250, gid=250)
        ca_install = next(step for step in _command_steps(steps) if step.argv[-1] == paths.ca_pem)
        assert ca_install.argv[ca_install.argv.index("-g") + 1] == expected_group


def test_plan_systemd_unit_linux() -> None:
    paths, steps = _plan("linux", user="avp")
    service = _file_step(steps, paths.service_file)
    assert "ProtectSystem=strict" in service.content
    assert "NoNewPrivileges=yes" in service.content
    assert "-m kow" in service.content


def test_plan_systemd_unit_linux_no_service() -> None:
    paths, steps = _plan("linux", user="avp", no_service=True)
    default_paths_, default_steps = _plan("linux", user="avp")
    service = _file_step(steps, paths.service_file)
    default_service = _file_step(default_steps, default_paths_.service_file)
    assert all("daemon-reload" not in step.argv for step in _command_steps(steps))
    assert all("enable" not in step.argv for step in _command_steps(steps))
    assert service.path == paths.service_file
    assert service.owner == default_service.owner
    assert service.group == default_service.group
    assert service.mode == 0o644
    assert service.content == default_service.content
    assert service.post_actions == ()


def test_plan_systemd_unit_linux_default_activates_service() -> None:
    paths, steps = _plan("linux", user="avp")
    service = _file_step(steps, paths.service_file)
    assert ("systemctl", "daemon-reload") in [action.argv for action in service.post_actions]
    assert ("systemctl", "enable", "--now", "agent-vault-proxy") in [
        action.argv for action in service.post_actions
    ]


def test_plan_launchd_plist_macos() -> None:
    paths, steps = _plan("macos", user="_avp", uid=250, gid=250)
    plist = _file_step(steps, paths.plist_file)
    assert "<key>UserName</key>" in plist.content
    assert "<string>_avp</string>" in plist.content
    assert "io.inflightsec.agent-vault-proxy" in plist.content
    xml.dom.minidom.parseString(plist.content)


def test_plan_launchd_plist_macos_no_service() -> None:
    paths, steps = _plan("macos", user="_avp", uid=250, gid=250, no_service=True)
    default_paths_, default_steps = _plan("macos", user="_avp", uid=250, gid=250)
    plist = _file_step(steps, paths.plist_file)
    default_plist = _file_step(default_steps, default_paths_.plist_file)
    assert all("launchctl" not in step.argv for step in _command_steps(steps))
    assert plist.path == paths.plist_file
    assert plist.owner == default_plist.owner
    assert plist.group == default_plist.group
    assert plist.mode == default_plist.mode
    assert plist.content == default_plist.content
    assert plist.post_actions == ()


def test_execute_dry_run_no_side_effects(tmp_path, capsys) -> None:
    target = tmp_path / "dry-run.txt"
    step = FileStep(
        description="Write dry-run file.",
        path=str(target),
        content="secretless\n",
        owner="root",
        group="root",
        mode=0o640,
    )
    rc = execute_plan([step], dry_run=True)
    assert rc == 0
    assert not target.exists()
    assert capsys.readouterr().out


def test_execute_file_step_writes(tmp_path) -> None:
    me = pwd.getpwuid(os.geteuid()).pw_name
    target = tmp_path / "written.txt"
    step = FileStep(
        description="Write file.",
        path=str(target),
        content="hello\n",
        owner=me,
        group=me,
        mode=0o640,
    )
    rc = execute_plan([step], dry_run=False)
    assert rc == 0
    assert target.read_text() == "hello\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o640


def test_run_setup_requires_root_unless_dry_run(monkeypatch, capsys) -> None:
    monkeypatch.setattr("kow.cli.setup.platform.system", lambda: "Linux")
    monkeypatch.setattr("kow.cli.setup.os.geteuid", lambda: 1000)
    monkeypatch.setattr("kow.cli.setup.run_doctor", lambda **kwargs: 0)
    rc = run_setup(user=None, dry_run=False, prefix=None)
    assert rc != 0
    assert "sudo" in capsys.readouterr().err

    monkeypatch.setattr("kow.cli.setup.execute_plan", lambda steps, dry_run: 0)
    rc = run_setup(user=None, dry_run=True, prefix=None)
    assert rc == 0


def test_main_setup_dispatch(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_run_setup(*, user, dry_run, prefix, allow_mutable_audit, no_service, static, **_):
        seen["args"] = (user, dry_run, prefix, allow_mutable_audit, no_service, static)
        return 23

    monkeypatch.setattr("kow.cli.main.run_setup", _fake_run_setup)
    rc = main(["setup", "--dry-run", "--no-service"])
    assert rc == 23
    assert seen["args"] == (None, True, None, False, True, False)


def test_main_setup_static_dispatch(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_run_setup(*, user, dry_run, prefix, allow_mutable_audit, no_service, static, **_):
        seen["args"] = (user, dry_run, prefix, allow_mutable_audit, no_service, static)
        return 29

    monkeypatch.setattr("kow.cli.main.run_setup", _fake_run_setup)
    rc = main(["setup", "--dry-run", "--static"])
    assert rc == 29
    assert seen["args"] == (None, True, None, False, False, True)


def test_main_setup_allow_mutable_audit_flag(monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_run_setup(*, user, dry_run, prefix, allow_mutable_audit, no_service, static, **_):
        seen["args"] = (allow_mutable_audit, no_service, static)
        return 0

    monkeypatch.setattr("kow.cli.main.run_setup", _fake_run_setup)
    rc = main(["setup", "--dry-run", "--allow-mutable-audit"])
    assert rc == 0
    assert seen["args"] == (True, False, False)


def test_render_env_block_sources_file() -> None:
    block = setup_mod._render_env_block("/tmp/ca.pem")
    assert "eval" not in block
    assert "avp env\nset -a; . ~/.config/avp/env; set +a" in block


# --- Finding 1: atomic, correct-owner token/file writes ---------------------


def test_write_file_is_atomic_no_partial_on_failure(tmp_path, monkeypatch) -> None:
    me = pwd.getpwuid(os.geteuid()).pw_name
    target = tmp_path / "token"
    step = FileStep(
        description="Write token.",
        path=str(target),
        content="super-secret-token\n",
        owner=me,
        group=me,
        mode=0o440,
    )

    # Fail mid-write, AFTER the temp file is created but BEFORE the rename.
    def _boom(_fd, _data) -> None:
        raise OSError("simulated write failure")

    monkeypatch.setattr(setup_mod, "_write_all", _boom)
    with pytest.raises(OSError, match="simulated write failure"):
        execute_plan([step], dry_run=False)

    # No partial file at the final path, and no stray temp left behind.
    assert not target.exists()
    leftovers = [p for p in tmp_path.iterdir() if p.name.startswith(".token.")]
    assert leftovers == []


def test_write_file_success_uses_rename_with_mode(tmp_path) -> None:
    me = pwd.getpwuid(os.geteuid()).pw_name
    target = tmp_path / "token"
    step = FileStep(
        description="Write token.",
        path=str(target),
        content="tok\n",
        owner=me,
        group=me,
        mode=0o440,
    )
    rc = execute_plan([step], dry_run=False)
    assert rc == 0
    assert target.read_text() == "tok\n"
    # Mode set on the temp fd before rename, so the visible file already has it.
    assert stat.S_IMODE(target.stat().st_mode) == 0o440
    assert [p for p in tmp_path.iterdir() if p.name.startswith(".token.")] == []


# --- Finding 2: reruns tighten toward policy, never widen --------------------


def test_existing_file_stricter_perms_preserved(tmp_path) -> None:
    me = pwd.getpwuid(os.geteuid()).pw_name
    target = tmp_path / "bindings.yaml"
    target.write_text("existing\n")
    os.chmod(target, 0o600)  # operator tightened below policy 0o640
    step = FileStep(
        description="Write bindings.",
        path=str(target),
        content="planned\n",
        owner=me,
        group=me,
        mode=0o640,
        skip_if_exists=True,
    )
    execute_plan([step], dry_run=False)
    # Content preserved (skip_if_exists) AND perms not widened back to 0o640.
    assert target.read_text() == "existing\n"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_existing_file_broader_perms_tightened(tmp_path) -> None:
    me = pwd.getpwuid(os.geteuid()).pw_name
    target = tmp_path / "bindings.yaml"
    target.write_text("existing\n")
    os.chmod(target, 0o666)  # insecure drift, broader than policy
    step = FileStep(
        description="Write bindings.",
        path=str(target),
        content="planned\n",
        owner=me,
        group=me,
        mode=0o640,
        skip_if_exists=True,
    )
    execute_plan([step], dry_run=False)
    assert stat.S_IMODE(target.stat().st_mode) == 0o640


# --- Finding 3: append-only ordering + fatal-by-default ----------------------


def _audit_step(os_name: str, *, user: str, allow_mutable_audit: bool) -> FileStep:
    paths = default_paths(os_name, None)
    steps = plan_setup(
        os_name=os_name,
        user=user,
        group=user,
        uid=250,
        gid=250,
        paths=paths,
        allow_mutable_audit=allow_mutable_audit,
    )
    return _file_step(steps, paths.audit_path)


@pytest.mark.parametrize(
    ("os_name", "user", "clear_argv0", "set_verb"),
    [
        ("linux", "avp", "chattr", "+a"),
        ("macos", "_avp", "chflags", "sappnd"),
    ],
)
def test_audit_clears_before_setting_on_both_oses(os_name, user, clear_argv0, set_verb) -> None:
    audit = _audit_step(os_name, user=user, allow_mutable_audit=False)
    # CLEAR lives in pre_actions (runs before metadata) on BOTH OSes.
    assert audit.pre_actions, f"{os_name} audit step must have a clear (pre) action"
    assert audit.pre_actions[0].argv[0] == clear_argv0
    assert audit.pre_actions[0].allow_attr_unsupported is True
    # SET lives in post_actions (runs after metadata) and is fatal by default.
    set_action = next(a for a in audit.post_actions if set_verb in a.argv)
    assert set_action.allow_attr_unsupported is False


@pytest.mark.parametrize(("os_name", "user"), [("linux", "avp"), ("macos", "_avp")])
def test_audit_set_non_fatal_under_allow_mutable_audit(os_name, user) -> None:
    audit = _audit_step(os_name, user=user, allow_mutable_audit=True)
    set_action = audit.post_actions[-1]
    assert set_action.allow_attr_unsupported is True


def test_audit_set_failure_is_fatal_by_default(tmp_path, monkeypatch) -> None:
    target = tmp_path / "audit.jsonl"
    failing_set = CommandStep(
        description="Set append-only audit flag.",
        argv=("chattr", "+a", str(target)),
        allow_attr_unsupported=False,
    )
    step = FileStep(
        description="Create audit log.",
        path=str(target),
        content="",
        owner=pwd.getpwuid(os.geteuid()).pw_name,
        group=pwd.getpwuid(os.geteuid()).pw_name,
        mode=0o640,
        skip_if_exists=True,
        post_actions=(failing_set,),
    )

    # Stub the command runner so the SET "fails" without needing real chattr.
    def _fake_run(*_a, **_k):
        class _P:
            returncode = 1
            stdout = ""
            stderr = "Operation not supported"

        return _P()

    monkeypatch.setattr(setup_mod.subprocess, "run", _fake_run)
    with pytest.raises(RuntimeError, match="command failed"):
        execute_plan([step], dry_run=False)


# --- Finding 4: macOS UID/GID allocation avoids group-only collisions --------


def test_next_macos_uid_gid_avoids_gid_only_collision(monkeypatch) -> None:
    # 250 is free among Users but TAKEN by a group; allocator must skip it.
    def _fake_list(record_path: str, _attribute: str) -> dict[str, int]:
        if record_path == "/Users":
            return {"root": 0, "_existing": 251}
        return {"wheel": 0, "_taken_group": 250}

    monkeypatch.setattr(setup_mod, "_list_macos_ids", _fake_list)
    uid, gid = setup_mod._next_macos_uid_gid()
    assert uid == gid
    assert uid not in {250, 251}  # 250 = group collision, 251 = user collision
    assert uid == 252
