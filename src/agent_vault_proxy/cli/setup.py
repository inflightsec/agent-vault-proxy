"""``avp setup`` installer planner/executor.

This module is intentionally split into a pure planner and a thin executor.
``plan_setup`` only renders an ordered list of immutable steps from explicit
inputs; it never probes the host or touches the filesystem. ``execute_plan``
applies those steps, using ``sudo -u <user>`` for ``run_as`` commands because
setup itself runs as root. For testability, file ownership changes are skipped
when the executor is not running as uid 0.
"""

from __future__ import annotations

import os
import platform
import plistlib
import pwd
import shlex
import stat
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from getpass import getpass
from pathlib import Path

import yaml

from agent_vault_proxy.cli.doctor import run_doctor
from agent_vault_proxy.config import Config

_LINUX_SERVICE_NAME = "agent-vault-proxy.service"
_MACOS_PLIST_NAME = "io.inflightsec.agent-vault-proxy.plist"


@dataclass(frozen=True)
class CommandStep:
    description: str
    argv: tuple[str, ...]
    run_as: str | None = None
    skip_if_path_exists: str | None = None
    allow_attr_unsupported: bool = False
    skip_if_user_exists: str | None = None


@dataclass(frozen=True)
class FileStep:
    description: str
    path: str
    content: str
    owner: str
    group: str
    mode: int
    skip_if_exists: bool = False
    pre_actions: tuple[CommandStep, ...] = ()
    post_actions: tuple[CommandStep, ...] = ()


@dataclass(frozen=True)
class PromptStep:
    description: str
    dest_path: str
    owner: str
    group: str
    mode: int
    skip_if_exists: bool = True


type Step = CommandStep | FileStep | PromptStep


@dataclass(frozen=True)
class SetupPaths:
    confdir: str
    statedir: str
    logdir: str
    mitmproxy_dir: str
    ca_pem: str
    token_path: str
    bindings_path: str
    static_secrets_path: str
    salt_path: str
    audit_path: str
    service_file: str
    plist_file: str
    python_exe: str


def default_paths(os_name: str, prefix: str | None) -> SetupPaths:
    """Return the install layout for ``os_name`` and optional staging prefix."""
    root = Path(prefix) if prefix is not None else Path("/")
    if os_name == "linux":
        confdir = root / "etc" / "agent-vault-proxy"
        statedir = root / "var" / "lib" / "agent-vault-proxy"
        logdir = root / "var" / "log" / "agent-vault-proxy"
        service_file = root / "etc" / "systemd" / "system" / _LINUX_SERVICE_NAME
        plist_file = root / "Library" / "LaunchDaemons" / _MACOS_PLIST_NAME
    elif os_name == "macos":
        confdir = root / "usr" / "local" / "etc" / "agent-vault-proxy"
        statedir = root / "usr" / "local" / "var" / "lib" / "agent-vault-proxy"
        logdir = root / "usr" / "local" / "var" / "log" / "agent-vault-proxy"
        service_file = root / "etc" / "systemd" / "system" / _LINUX_SERVICE_NAME
        plist_file = root / "Library" / "LaunchDaemons" / _MACOS_PLIST_NAME
    else:
        raise ValueError(f"unsupported os_name {os_name!r}")

    mitmproxy_dir = statedir / ".mitmproxy"
    return SetupPaths(
        confdir=str(confdir),
        statedir=str(statedir),
        logdir=str(logdir),
        mitmproxy_dir=str(mitmproxy_dir),
        ca_pem=str(confdir / "ca.pem"),
        token_path=str(confdir / "bws-token"),
        bindings_path=str(confdir / "bindings.yaml"),
        static_secrets_path=str(confdir / "static-secrets.yaml"),
        # Statedir (= daemon HOME, the resolver fallback): the run_as
        # service user cannot write the root-owned 0750 confdir.
        salt_path=str(statedir / "install-salt"),
        audit_path=str(logdir / "audit.jsonl"),
        service_file=str(service_file),
        plist_file=str(plist_file),
        python_exe=sys.executable,
    )


def plan_setup(
    *,
    os_name: str,
    user: str,
    group: str,
    paths: SetupPaths,
    uid: int | None = None,
    gid: int | None = None,
    allow_mutable_audit: bool = False,
    no_service: bool = False,
    static: bool = False,
) -> list[Step]:
    """Render the ``avp setup`` install plan without touching the host."""
    if os_name not in {"linux", "macos"}:
        raise ValueError(f"unsupported os_name {os_name!r}")

    # gid-0 group differs per platform; macOS has no "root" group.
    gid0_group = "root" if os_name == "linux" else "wheel"
    steps: list[Step] = []
    steps.extend(_plan_service_user(os_name=os_name, user=user, group=group, uid=uid, gid=gid))
    steps.extend(
        [
            _mkdir_step(
                description="Create AVP config directory.",
                path=paths.confdir,
                owner="root",
                group=group,
                mode=0o750,
            ),
            _mkdir_step(
                description="Create AVP state directory.",
                path=paths.statedir,
                owner=user,
                group=group,
                mode=0o750,
            ),
            _mkdir_step(
                description="Create AVP log directory.",
                path=paths.logdir,
                owner=user,
                group=group,
                mode=0o750,
            ),
            _mkdir_step(
                description="Create mitmproxy CA state directory.",
                path=paths.mitmproxy_dir,
                owner=user,
                group=group,
                mode=0o700,
            ),
            FileStep(
                description="Create audit log file and lock append-only policy.",
                path=paths.audit_path,
                content="",
                owner=user,
                group=group,
                mode=0o640,
                skip_if_exists=True,
                pre_actions=_audit_pre_actions(os_name, paths.audit_path),
                post_actions=_audit_post_actions(
                    os_name,
                    paths.audit_path,
                    allow_mutable_audit=allow_mutable_audit,
                ),
            ),
            FileStep(
                description="Write starter bindings.yaml.",
                path=paths.bindings_path,
                content=_render_bindings(paths, static=static),
                owner="root",
                group=group,
                mode=0o640,
                skip_if_exists=True,
            ),
            CommandStep(
                description="Generate or reuse the installation salt as the service user.",
                argv=(
                    paths.python_exe,
                    "-c",
                    "from agent_vault_proxy.placeholders import load_or_create_install_salt; "
                    f"load_or_create_install_salt({paths.salt_path!r})",
                ),
                run_as=user,
                skip_if_path_exists=paths.salt_path,
            ),
            CommandStep(
                description="Generate the mitmproxy CA as the service user.",
                argv=(
                    paths.python_exe,
                    "-c",
                    "from pathlib import Path; from mitmproxy.certs import CertStore; "
                    f"CertStore.from_store(Path({paths.mitmproxy_dir!r}), 'mitmproxy', 2048, None)",
                ),
                run_as=user,
                skip_if_path_exists=paths.ca_pem,
            ),
            CommandStep(
                description="Install the public CA certificate into the config directory.",
                argv=(
                    "install",
                    "-m",
                    "0644",
                    "-o",
                    "root",
                    "-g",
                    gid0_group,
                    str(Path(paths.mitmproxy_dir) / "mitmproxy-ca-cert.pem"),
                    paths.ca_pem,
                ),
                skip_if_path_exists=paths.ca_pem,
            ),
        ]
    )
    if not static:
        steps.insert(
            -4,
            PromptStep(
                description="Capture the Bitwarden Secrets Manager machine-account token.",
                dest_path=paths.token_path,
                owner="root",
                group=group,
                mode=0o440,
                skip_if_exists=True,
            ),
        )
    else:
        steps.insert(
            -4,
            FileStep(
                description="Write starter static secrets file.",
                path=paths.static_secrets_path,
                content='secrets:\n  EXAMPLE_API_KEY: "change-me-not-a-real-secret"\n',
                owner="root",
                group=group,
                mode=0o640,
                skip_if_exists=True,
            ),
        )

    if os_name == "linux":
        steps.append(
            FileStep(
                description="Install the systemd unit.",
                path=paths.service_file,
                content=_render_systemd_unit(user=user, group=group, paths=paths),
                owner="root",
                group="root",
                mode=0o644,
                post_actions=()
                if no_service
                else (
                    CommandStep(
                        description="Reload systemd units.",
                        argv=("systemctl", "daemon-reload"),
                    ),
                    CommandStep(
                        description="Enable and start agent-vault-proxy.",
                        argv=("systemctl", "enable", "--now", "agent-vault-proxy"),
                    ),
                ),
            )
        )
    else:
        steps.append(
            FileStep(
                description="Install the launchd plist.",
                path=paths.plist_file,
                content=_render_launchd_plist(user=user, group=group, paths=paths),
                owner="root",
                group="wheel",
                mode=0o644,
                post_actions=()
                if no_service
                else (
                    CommandStep(
                        description="Load and enable the launchd service.",
                        argv=("launchctl", "load", "-w", paths.plist_file),
                    ),
                ),
            )
        )

    return steps


def execute_plan(steps: list[Step], *, dry_run: bool) -> int:
    """Execute a rendered setup plan."""
    for step in steps:
        if isinstance(step, CommandStep):
            _execute_command_step(step, dry_run=dry_run)
            continue
        if isinstance(step, FileStep):
            _execute_file_step(step, dry_run=dry_run)
            continue
        _execute_prompt_step(step, dry_run=dry_run)
    return 0


def run_setup(
    *,
    user: str | None,
    dry_run: bool,
    prefix: str | None,
    allow_mutable_audit: bool = False,
    no_service: bool = False,
    static: bool = False,
) -> int:
    """CLI entry point for ``avp setup``."""
    system_name = platform.system()
    if system_name == "Linux":
        os_name = "linux"
        resolved_user = user or "avp"
    elif system_name == "Darwin":
        os_name = "macos"
        resolved_user = user or "_avp"
    else:
        print(f"avp setup: unsupported OS {system_name!r}", file=sys.stderr)
        return 1

    if not dry_run and os.geteuid() != 0:
        print("re-run with sudo", file=sys.stderr)
        return 1

    paths = default_paths(os_name, prefix)
    uid: int | None = None
    gid: int | None = None
    if os_name == "macos" and not dry_run and not _user_exists(resolved_user):
        uid, gid = _create_macos_service_account(resolved_user, resolved_user)

    plan = plan_setup(
        os_name=os_name,
        user=resolved_user,
        group=resolved_user,
        paths=paths,
        uid=uid,
        gid=gid,
        allow_mutable_audit=allow_mutable_audit,
        no_service=no_service,
        static=static,
    )
    execute_plan(plan, dry_run=dry_run)
    if no_service:
        if os_name == "linux":
            print(
                "Service was not activated; run `systemctl enable --now "
                "agent-vault-proxy` when ready."
            )
        else:
            print(
                f"Service was not activated; run `launchctl load -w {paths.plist_file}` when ready."
            )

    doctor_rc = run_doctor(
        ca_cert_path=paths.ca_pem,
        ca_key_path=str(Path(paths.mitmproxy_dir) / "mitmproxy-ca.pem"),
    )
    print(_render_env_block(paths.ca_pem))
    if os_name == "macos":
        print("Add these to ~/.zshenv (not ~/.zshrc) so non-login shells inherit them.")
        print(
            "NOTE (macOS): launchd is service supervision, not a sandbox. "
            "This gives you isolated-user privilege separation + launchd supervision, "
            "but NOT kernel confinement — there is no equivalent to systemd's "
            "ProtectSystem, RestrictAddressFamilies, or syscall filter. If this host "
            "is a credible target, run agent-vault-proxy inside Docker or a Linux VM."
        )
    return doctor_rc


def _plan_service_user(
    *,
    os_name: str,
    user: str,
    group: str,
    uid: int | None,
    gid: int | None,
) -> list[CommandStep]:
    if os_name == "linux":
        return [
            CommandStep(
                description="Create the dedicated system user if it does not exist.",
                argv=(
                    "useradd",
                    "--system",
                    "--no-create-home",
                    "--shell",
                    "/usr/sbin/nologin",
                    user,
                ),
                skip_if_user_exists=user,
            )
        ]

    return _macos_service_user_steps(user=user, group=group, uid=uid, gid=gid, skip_user=user)


def _macos_service_user_steps(
    *,
    user: str,
    group: str,
    uid: int | None,
    gid: int | None,
    skip_user: str | None,
) -> list[CommandStep]:
    uid_text = "AUTO_UID" if uid is None else str(uid)
    gid_text = "AUTO_GID" if gid is None else str(gid)
    return [
        CommandStep(
            description="Create the dedicated launchd group if it does not exist.",
            argv=("dscl", ".", "-create", f"/Groups/{group}", "PrimaryGroupID", gid_text),
            skip_if_user_exists=skip_user,
        ),
        CommandStep(
            description="Create the dedicated launchd user if it does not exist.",
            argv=("dscl", ".", "-create", f"/Users/{user}", "UniqueID", uid_text),
            skip_if_user_exists=skip_user,
        ),
        CommandStep(
            description="Set the service user's primary group.",
            argv=("dscl", ".", "-create", f"/Users/{user}", "PrimaryGroupID", gid_text),
            skip_if_user_exists=skip_user,
        ),
        CommandStep(
            description="Set the service user's shell.",
            argv=("dscl", ".", "-create", f"/Users/{user}", "UserShell", "/usr/bin/false"),
            skip_if_user_exists=skip_user,
        ),
        CommandStep(
            description="Set the service user's home directory.",
            argv=("dscl", ".", "-create", f"/Users/{user}", "NFSHomeDirectory", "/var/empty"),
            skip_if_user_exists=skip_user,
        ),
        CommandStep(
            description="Set the service user's real name.",
            argv=(
                "dscl",
                ".",
                "-create",
                f"/Users/{user}",
                "RealName",
                "agent-vault-proxy service user",
            ),
            skip_if_user_exists=skip_user,
        ),
        CommandStep(
            description="Hide the service user from the login UI.",
            argv=("dscl", ".", "-create", f"/Users/{user}", "IsHidden", "1"),
            skip_if_user_exists=skip_user,
        ),
    ]


def _mkdir_step(*, description: str, path: str, owner: str, group: str, mode: int) -> CommandStep:
    return CommandStep(
        description=description,
        argv=(
            "install",
            "-d",
            "-m",
            f"{mode:04o}",
            "-o",
            owner,
            "-g",
            group,
            path,
        ),
    )


def _audit_pre_actions(os_name: str, audit_path: str) -> tuple[CommandStep, ...]:
    if os_name == "linux":
        return (
            CommandStep(
                description="Clear append-only audit flag before any metadata refresh.",
                argv=("chattr", "-a", audit_path),
                allow_attr_unsupported=True,
            ),
        )
    return (
        CommandStep(
            description="Clear append-only audit flag before any metadata refresh.",
            argv=("chflags", "nosappnd", audit_path),
            allow_attr_unsupported=True,
        ),
    )


def _audit_post_actions(
    os_name: str,
    audit_path: str,
    *,
    allow_mutable_audit: bool,
) -> tuple[CommandStep, ...]:
    if os_name == "linux":
        return (
            CommandStep(
                description="Set append-only audit flag.",
                argv=("chattr", "+a", audit_path),
                allow_attr_unsupported=allow_mutable_audit,
            ),
        )
    return (
        CommandStep(
            description="Set append-only audit flag.",
            argv=("chflags", "sappnd", audit_path),
            allow_attr_unsupported=allow_mutable_audit,
        ),
    )


def _render_bindings(paths: SetupPaths, *, static: bool = False) -> str:
    if not static:
        file_bindings_comment = "# bindings come from BWS notes; add file bindings here if needed"
        return textwrap.dedent(
            f"""\
            # agent-vault-proxy starter config written by `avp setup`.
            # Edit your real bindings in Bitwarden secret notes (binding_source: both);
            # this file only configures the backend + audit sink.
            version: 1
            binding_source: both
            # Pinned so daemon + tooling derive identical placeholders.
            install_salt_path: {paths.salt_path}
            secrets: {{}}            {file_bindings_comment}
            backend:
              type: bws
              config:
                organization_id: "REPLACE-WITH-YOUR-BWS-ORG-UUID"   # <- you MUST set this
                access_token_path: {paths.token_path}
                state_path: {paths.statedir}/bws-state.json
                # EU defaults; change to api.bitwarden.com / identity.bitwarden.com for US.
                api_url: https://api.bitwarden.eu
                identity_url: https://identity.bitwarden.eu
            audit:
              path: {paths.audit_path}
            """
        )

    content = textwrap.dedent(
        f"""\
        # agent-vault-proxy starter config written by `avp setup`.
        # Static backend for development/testing only; replace this example before real use.
        version: 1
        binding_source: file
        secrets:
          EXAMPLE_API_KEY:
            placeholder: "avp-PLACEHOLDER-EXAMPLE-0001"
            inject:
              header: "Authorization"
              format: "Bearer {{EXAMPLE_API_KEY}}"
            bindings:
              - host: "example.com"
        backend:
          type: static
          config:
            type: static
            path: {paths.static_secrets_path}
        audit:
          path: {paths.audit_path}
        """
    )
    Config.model_validate(yaml.safe_load(content))
    return content


def _render_systemd_unit(*, user: str, group: str, paths: SetupPaths) -> str:
    return textwrap.dedent(
        f"""\
        [Unit]
        Description=agent-vault-proxy — BWS-backed egress credential injector
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=simple
        User={user}
        Group={group}
        ExecStart={paths.python_exe} -m agent_vault_proxy --set avp_config={paths.bindings_path}
        Environment=HOME={paths.statedir}
        ReadWritePaths={paths.logdir} {paths.statedir}
        ReadOnlyPaths={paths.confdir}
        ProtectSystem=strict
        ProtectHome=yes
        PrivateTmp=yes
        PrivateDevices=yes
        ProtectKernelTunables=yes
        ProtectKernelModules=yes
        ProtectControlGroups=yes
        ProtectKernelLogs=yes
        ProtectHostname=yes
        ProtectClock=yes
        RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
        RestrictNamespaces=yes
        RestrictRealtime=yes
        RestrictSUIDSGID=yes
        LockPersonality=yes
        NoNewPrivileges=yes
        SystemCallArchitectures=native
        SystemCallFilter=@system-service
        SystemCallFilter=~@privileged @resources @mount
        Restart=on-failure
        RestartSec=5

        [Install]
        WantedBy=multi-user.target
        """
    )


def _render_launchd_plist(*, user: str, group: str, paths: SetupPaths) -> str:
    payload = {
        "Label": "io.inflightsec.agent-vault-proxy",
        "UserName": user,
        "GroupName": group,
        "ProgramArguments": [
            paths.python_exe,
            "-m",
            "agent_vault_proxy",
            "--set",
            f"avp_config={paths.bindings_path}",
        ],
        "EnvironmentVariables": {"HOME": paths.statedir},
        "RunAtLoad": True,
        "KeepAlive": True,
    }
    return plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=False).decode("utf-8")


def _execute_command_step(step: CommandStep, *, dry_run: bool) -> None:
    if dry_run:
        print(f"[dry-run] {step.description}: {_format_command(step)}")
        return
    if step.skip_if_user_exists and _user_exists(step.skip_if_user_exists):
        print(f"Skipping {step.description}: user {step.skip_if_user_exists} already exists.")
        return
    if step.skip_if_path_exists and os.path.exists(step.skip_if_path_exists):
        print(f"Skipping {step.description}: {step.skip_if_path_exists} already exists.")
        return
    argv = _command_argv(step)
    # Planner output is an immutable argv tuple; we never invoke a shell here.
    proc = subprocess.run(  # noqa: S603
        argv,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
        return
    if step.allow_attr_unsupported:
        print(
            f"Warning: {step.description} failed but was marked non-fatal: "
            f"{_format_command(step)} :: {proc.stderr.strip()}",
            file=sys.stderr,
        )
        return
    stderr = proc.stderr.strip()
    raise RuntimeError(
        f"command failed with exit code {proc.returncode}: {shlex.join(argv)} :: {stderr}"
    )


def _execute_file_step(step: FileStep, *, dry_run: bool) -> None:
    exists = os.path.exists(step.path)
    if dry_run:
        verb = "preserve existing file" if step.skip_if_exists and exists else "write file"
        print(f"[dry-run] {step.description}: {verb} {step.path}")
        if exists:
            for pre_action in step.pre_actions:
                print(f"[dry-run] {pre_action.description}: {_format_command(pre_action)}")
        for post_action in step.post_actions:
            print(f"[dry-run] {post_action.description}: {_format_command(post_action)}")
        return

    if exists:
        for pre_action in step.pre_actions:
            _execute_command_step(pre_action, dry_run=False)

    if exists and step.skip_if_exists:
        print(f"Skipping overwrite for {step.path}: file already exists.")
        _apply_existing_file_metadata(step.path, owner=step.owner, group=step.group, mode=step.mode)
    else:
        _write_file(
            path=step.path,
            content=step.content,
            owner=step.owner,
            group=step.group,
            mode=step.mode,
        )

    for post_action in step.post_actions:
        _execute_command_step(post_action, dry_run=False)


def _execute_prompt_step(step: PromptStep, *, dry_run: bool) -> None:
    if dry_run:
        print(f"[dry-run] {step.description}: prompt for secret and write {step.dest_path}")
        return
    if step.skip_if_exists and os.path.exists(step.dest_path):
        print(f"Skipping {step.dest_path}: token file already exists.")
        return
    token = getpass("Paste the BWS machine-account access token (input hidden): ")
    _write_file(
        path=step.dest_path,
        content=token,
        owner=step.owner,
        group=step.group,
        mode=step.mode,
    )


def _write_file(*, path: str, content: str, owner: str, group: str, mode: int) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_fd, temp_path = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    renamed = False
    try:
        _write_all(temp_fd, content.encode("utf-8"))
        os.fsync(temp_fd)
        os.fchmod(temp_fd, mode)
        _apply_fd_owner(temp_fd, owner=owner, group=group)
        os.close(temp_fd)
        temp_fd = -1
        os.rename(temp_path, target)
        renamed = True
        _fsync_directory(target.parent)
    finally:
        if temp_fd != -1:
            os.close(temp_fd)
        if not renamed and os.path.exists(temp_path):
            os.unlink(temp_path)


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise OSError("short write while creating installer file")
        offset += written


def _apply_fd_owner(fd: int, owner: str, group: str) -> None:
    if os.geteuid() != 0:
        return
    uid, gid = _resolve_owner_group(owner, group)
    os.fchown(fd, uid, gid)


def _apply_existing_file_metadata(path: str, *, owner: str, group: str, mode: int) -> None:
    current_mode = stat.S_IMODE(os.stat(path).st_mode)
    # Reruns may repair insecure drift, but must not widen an operator-tightened file.
    if current_mode & ~mode:
        os.chmod(path, mode)
    if os.geteuid() != 0:
        return
    uid, gid = _resolve_owner_group(owner, group)
    st = os.stat(path)
    if st.st_uid != uid or st.st_gid != gid:
        os.chown(path, uid, gid)


def _resolve_owner_group(owner: str, group: str) -> tuple[int, int]:
    uid = pwd.getpwnam(owner).pw_uid
    gid = pwd.getpwnam(owner).pw_gid if group == owner else _lookup_gid(group)
    return uid, gid


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _lookup_gid(group: str) -> int:
    import grp

    return grp.getgrnam(group).gr_gid


def _format_command(step: CommandStep) -> str:
    return shlex.join(_command_argv(step))


def _command_argv(step: CommandStep) -> tuple[str, ...]:
    if step.run_as is None:
        return step.argv
    return ("sudo", "-u", step.run_as, *step.argv)


def _user_exists(user: str) -> bool:
    try:
        pwd.getpwnam(user)
    except KeyError:
        return False
    return True


def _next_macos_uid_gid() -> tuple[int, int]:
    used = set(_list_macos_ids("/Users", "UniqueID").values())
    used.update(_list_macos_ids("/Groups", "PrimaryGroupID").values())
    for candidate in range(250, 500):
        if candidate not in used:
            return candidate, candidate
    raise RuntimeError("could not find an unused macOS uid/gid below 500")


def _list_macos_ids(record_path: str, attribute: str) -> dict[str, int]:
    proc = subprocess.run(  # noqa: S603
        ("/usr/bin/dscl", ".", "-list", record_path, attribute),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"failed to list macOS ids from {record_path} {attribute}: "
            f"{proc.returncode} :: {proc.stderr.strip()}"
        )
    found: dict[str, int] = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        try:
            found[parts[0]] = int(parts[1])
        except ValueError:
            continue
    return found


def _create_macos_service_account(
    user: str,
    group: str,
    *,
    max_attempts: int = 5,
) -> tuple[int, int]:
    last_error: RuntimeError | None = None
    for _ in range(max_attempts):
        uid, gid = _next_macos_uid_gid()
        try:
            for step in _macos_service_user_steps(
                user=user,
                group=group,
                uid=uid,
                gid=gid,
                skip_user=None,
            ):
                _execute_command_step(step, dry_run=False)
        except RuntimeError as exc:
            if not _is_macos_id_collision_error(exc):
                raise
            last_error = exc
            continue
        if _macos_ids_owned_by(user=user, group=group, candidate=uid):
            return uid, gid
    if last_error is not None:
        raise RuntimeError(
            f"failed to allocate a stable macOS uid/gid for {user} after {max_attempts} attempts"
        ) from last_error
    raise RuntimeError(
        f"failed to allocate a stable macOS uid/gid for {user} after {max_attempts} attempts"
    )


def _is_macos_id_collision_error(exc: RuntimeError) -> bool:
    message = str(exc)
    return "eDSRecordAlreadyExists" in message or "already exists" in message


def _macos_ids_owned_by(*, user: str, group: str, candidate: int) -> bool:
    users = _list_macos_ids("/Users", "UniqueID")
    groups = _list_macos_ids("/Groups", "PrimaryGroupID")
    return users.get(user) == candidate and groups.get(group) == candidate


def _render_env_block(ca_pem: str) -> str:
    return textwrap.dedent(
        f"""\
        export HTTPS_PROXY="http://127.0.0.1:14322"
        export HTTP_PROXY="http://127.0.0.1:14322"
        export NODE_EXTRA_CA_CERTS="{ca_pem}"
        export SSL_CERT_FILE="{ca_pem}"
        export REQUESTS_CA_BUNDLE="{ca_pem}"
        export CURL_CA_BUNDLE="{ca_pem}"
        avp env
        set -a; . ~/.config/avp/env; set +a
        """
    ).rstrip()
