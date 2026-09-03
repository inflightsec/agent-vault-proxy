"""``kow setup`` installer planner/executor.

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

from kow import _paths
from kow.cli.doctor import run_doctor
from kow.config import Config

_LINUX_SERVICE_NAME = f"{_paths.LINUX_SERVICE_UNIT}.service"
_MACOS_PLIST_NAME = "io.inflightsec.kow.plist"


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


def _legacy_install_present(os_name: str) -> bool:
    """True iff a pre-rename confdir exists and the kow one does not."""
    new, old = (
        (_paths.LINUX_CONFDIR, _paths.legacy_of(_paths.LINUX_CONFDIR))
        if os_name == "linux"
        else (_paths.MACOS_CONFDIR, _paths.legacy_of(_paths.MACOS_CONFDIR))
    )
    return _paths.exists(old) and not _paths.exists(new)


def _adopt_legacy_layout(os_name: str, prefix: str | None) -> bool:
    """Host probe (kept out of the pure planner): adopt an existing pre-rename
    install rather than laying a second, empty tree beside it. A staging prefix
    is always a fresh layout."""
    if prefix is not None or not _legacy_install_present(os_name):
        return False
    print(
        "Existing agent-vault-proxy install detected — keeping its directories. "
        "New installs use /etc/kow.",
        file=sys.stderr,
    )
    return True


def default_service_user(os_name: str, *, legacy: bool = False) -> str:
    """Service account for ``os_name``. ``legacy=True`` keeps the pre-rename
    account so an adopted install does not orphan its file ownership."""
    if os_name == "linux":
        return _paths.LEGACY_LINUX_SERVICE_USER if legacy else _paths.LINUX_SERVICE_USER
    return _paths.LEGACY_MACOS_SERVICE_USER if legacy else _paths.MACOS_SERVICE_USER


def default_paths(os_name: str, prefix: str | None, *, legacy: bool = False) -> SetupPaths:
    """Return the install layout for ``os_name`` and optional staging prefix.

    New installs land under ``kow``. ``legacy=True`` returns the pre-rename
    ``agent-vault-proxy`` layout so re-running setup on an existing host adopts
    its directories instead of laying a second, empty tree beside them. The
    caller decides — this function stays pure and never probes the host
    (:func:`run_setup` does the probing).
    """
    root = Path(prefix) if prefix is not None else Path("/")
    leaf = _paths.LEGACY_NAME if legacy else "kow"

    if os_name == "linux":
        confdir = root / "etc" / leaf
        statedir = root / "var" / "lib" / leaf
        logdir = root / "var" / "log" / leaf
    elif os_name == "macos":
        confdir = root / "usr" / "local" / "etc" / leaf
        statedir = root / "usr" / "local" / "var" / "lib" / leaf
        logdir = root / "usr" / "local" / "var" / "log" / leaf
    else:
        raise ValueError(f"unsupported os_name {os_name!r}")
    service_file = root / "etc" / "systemd" / "system" / _LINUX_SERVICE_NAME
    plist_file = root / "Library" / "LaunchDaemons" / _MACOS_PLIST_NAME

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
    gsm: bool = False,
    keychain: bool = False,
    aws: bool = False,
) -> list[Step]:
    """Render the ``kow setup`` install plan without touching the host."""
    if os_name not in {"linux", "macos"}:
        raise ValueError(f"unsupported os_name {os_name!r}")
    # Single internal backend selector derived from the mutually-exclusive flags.
    backend = (
        "gsm"
        if gsm
        else "aws"
        if aws
        else "keychain"
        if keychain
        else "static"
        if static
        else "bws"
    )

    # gid-0 group differs per platform; macOS has no "root" group.
    gid0_group = "root" if os_name == "linux" else "wheel"
    steps: list[Step] = []
    steps.extend(_plan_service_user(os_name=os_name, user=user, group=group, uid=uid, gid=gid))
    steps.extend(
        [
            _mkdir_step(
                description="Create kow config directory.",
                path=paths.confdir,
                owner="root",
                group=group,
                mode=0o750,
            ),
            _mkdir_step(
                description="Create kow state directory.",
                path=paths.statedir,
                owner=user,
                group=group,
                mode=0o750,
            ),
            _mkdir_step(
                description="Create kow log directory.",
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
                content=_render_bindings(paths, backend=backend),
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
                    "from kow.placeholders import load_or_create_install_salt; "
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
    if backend == "bws":
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
    elif backend == "static":
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
    # backend in {"gsm", "aws", "keychain"}: keyless — no local secret material to
    # provision. GSM/AWS grant access out-of-band via IAM (hand-off printed after
    # setup); the keychain holds values the operator adds with `kow secret add`.

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
                        description="Enable and start kow.",
                        argv=("systemctl", "enable", "--now", _paths.LINUX_SERVICE_UNIT),
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
    gsm: bool = False,
    bws: bool = False,
    keychain: bool = False,
    aws: bool = False,
) -> int:
    """CLI entry point for ``kow setup``.

    Backend selection: exactly one of ``--bws`` / ``--gsm`` / ``--aws`` /
    ``--keychain`` / ``--static`` may be passed. When none is (all False), an
    interactive picker runs on a TTY; off a TTY it defaults to BWS so Ansible /
    container runs stay non-interactive. ``--keychain`` is macOS-only and refused
    on any other host.
    """
    system_name = platform.system()
    if system_name == "Linux":
        os_name = "linux"
    elif system_name == "Darwin":
        os_name = "macos"
    else:
        print(f"kow setup: unsupported OS {system_name!r}", file=sys.stderr)
        return 1

    if not dry_run and os.geteuid() != 0:
        print("re-run with sudo", file=sys.stderr)
        return 1

    # No backend flag → let the user choose on a TTY; default BWS off a TTY so
    # non-interactive (Ansible / container) runs are unchanged. The resolver also
    # enforces the macOS-only keychain guard.
    static, gsm, aws, keychain, backend_error = _resolve_backend(
        system_name=system_name,
        static=static,
        gsm=gsm,
        bws=bws,
        aws=aws,
        keychain=keychain,
    )
    if backend_error is not None:
        print(backend_error, file=sys.stderr)
        return 1

    legacy = _adopt_legacy_layout(os_name, prefix)
    resolved_user = user or default_service_user(os_name, legacy=legacy)
    paths = default_paths(os_name, prefix, legacy=legacy)
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
        gsm=gsm,
        keychain=keychain,
        aws=aws,
    )
    execute_plan(plan, dry_run=dry_run)
    if no_service:
        if os_name == "linux":
            print(
                "Service was not activated; run `systemctl enable --now "
                f"{_paths.LINUX_SERVICE_UNIT}` when ready."
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
            "is a credible target, run keys-on-the-wire inside Docker or a Linux VM."
        )
    _print_backend_handoff(paths, gsm=gsm, aws=aws)
    print(_render_next_steps())
    return doctor_rc


def _resolve_backend(
    *,
    system_name: str,
    static: bool,
    gsm: bool,
    bws: bool,
    aws: bool,
    keychain: bool,
) -> tuple[bool, bool, bool, bool, str | None]:
    """Resolve which backend to install.

    Runs the interactive picker when no flag was passed and stdin is a TTY, then
    enforces the macOS-only keychain guard (which also catches a keychain pick
    from the picker on a non-Mac host). Returns
    ``(static, gsm, aws, keychain, error)`` — ``error`` is a message to print and
    refuse on, or ``None`` to proceed. ``bws`` is the implicit default, so it is
    consumed here but not returned.
    """
    if not (static or gsm or bws or aws or keychain) and sys.stdin.isatty():
        choice = _prompt_backend()
        static = choice == "static"
        gsm = choice == "gsm"
        aws = choice == "aws"
        keychain = choice == "keychain"
    if keychain and system_name != "Darwin":
        return (
            static,
            gsm,
            aws,
            keychain,
            f"kow setup: the keychain backend requires macOS; this host is "
            f"{system_name!r}. Choose --bws / --gsm / --aws / --static instead.",
        )
    return static, gsm, aws, keychain, None


def _print_backend_handoff(paths: SetupPaths, *, gsm: bool, aws: bool) -> None:
    """Print the post-setup hand-off for the keyless networked backends. GSM and
    AWS are mutually exclusive, so at most one note prints; BWS/static/keychain
    have no networked IAM step to hand off."""
    if gsm:
        print(_render_gsm_handoff(paths))
    elif aws:
        print(_render_aws_handoff(paths))


def _prompt_backend() -> str:
    """Interactive backend picker (TTY only). Returns
    'bws' | 'gsm' | 'static' | 'aws' | 'keychain'. Loops until a valid 1-5 choice
    is entered — never guesses a default."""
    print("Which secret backend should keys-on-the-wire use?")
    print("  [1] Bitwarden Secrets Manager (BWS) — paste a machine-account token")
    print("  [2] Google Secret Manager (GSM)     — keyless (gcloud ADC), nothing to paste")
    print("  [3] Local static file               — no vault, 0600 file (dev/testing)")
    print("  [4] AWS Secrets Manager             — keyless (ambient IAM), nothing to paste")
    print("  [5] macOS Keychain                  — keyless (login keychain), macOS only")
    choices = {"1": "bws", "2": "gsm", "3": "static", "4": "aws", "5": "keychain"}
    while True:
        answer = input("Enter 1, 2, 3, 4, or 5: ").strip()
        if answer in choices:
            return choices[answer]
        print(f"'{answer}' is not 1, 2, 3, 4, or 5 — please try again.")


def _render_gsm_handoff(paths: SetupPaths) -> str:
    """DRY hand-off to `kow gcp-setup` — setup selects the backend; the separate,
    privileged IAM helper grants per-secret read access. GSM is keyless, so
    nothing was pasted here."""
    return (
        "\n"
        "GSM backend selected — keyless, so nothing was pasted. Two steps to finish:\n"
        "\n"
        f"  1. Set your project number in {paths.bindings_path}\n"
        "     (field `project_id`; optionally `impersonate_service_account`).\n"
        "\n"
        "  2. Grant kow read access PER SECRET (least privilege) with the IAM helper:\n"
        "       sudo kow gcp-setup --project <PROJECT> \\\n"
        "         --member serviceAccount:<AVP_SERVICE_ACCOUNT> --secret <SECRET_NAME>\n"
        "\n"
        "  kow authenticates via gcloud ADC and refuses a downloaded key file\n"
        "  (reject_ambient_key: true); self_check: deny stops it starting under a\n"
        "  broad identity. Verify anytime with: kow doctor --probe-gcp\n"
    )


def _render_aws_handoff(paths: SetupPaths) -> str:
    """Hand-off for the aws-secrets-manager backend — keyless via ambient IAM
    (Roles Anywhere / SSO / instance profile), so nothing was pasted. Mirrors
    :func:`_render_gsm_handoff`: setup selects the backend; the operator grants
    least-privilege read on their own prefix ARN out-of-band."""
    return (
        "\n"
        "AWS Secrets Manager backend selected — keyless (ambient IAM), so nothing "
        "was pasted. Two steps to finish:\n"
        "\n"
        f"  1. Set your region and secret_prefix in {paths.bindings_path}\n"
        "     (fields `region` and `secret_prefix`).\n"
        "\n"
        "  2. Grant kow's IAM identity read access, scoped to your prefix ARN\n"
        "     (least privilege — never account-wide):\n"
        "       secretsmanager:GetSecretValue\n"
        "     e.g. on arn:aws:secretsmanager:<region>:<account>:secret:kow/*\n"
        "\n"
        "  kow resolves credentials from the ambient chain and refuses permanent\n"
        "  IAM-user keys (require_temporary_credentials: true); self_check: deny\n"
        "  refuses to start if the identity can read or enumerate secrets outside\n"
        "  secret_prefix.\n"
    )


def _render_next_steps() -> str:
    """Post-setup guidance: how to add the first binding. Leads with the universal
    paste-into-any-agent one-liner (the agent fetches the guide and drives kow),
    then the deterministic `kow binding new` tool as the by-hand fallback. Never
    auto-installs anything."""
    return (
        "\n"
        "Next: put an API key behind the proxy. Your real key never enters the agent.\n"
        "\n"
        "  Fast path: paste this to any AI agent (Claude Code, Codex, Cursor, ...):\n"
        "\n"
        "    Read https://keysonthewire.com/install and set up kow for me.\n"
        "\n"
        "  The agent reads the guide and drives kow for you. Same tool in every agent.\n"
        "\n"
        "  Prefer to do it by hand? Run the generator and paste what it prints into\n"
        "  your vault (it validates the binding, so it can't be silently wrong):\n"
        "\n"
        "    kow binding new --host api.stripe.com --name STRIPE_API_KEY\n"
    )


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
                "keys-on-the-wire service user",
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


def _render_bindings(paths: SetupPaths, *, backend: str = "bws") -> str:
    if backend == "bws":
        file_bindings_comment = "# bindings come from BWS notes; add file bindings here if needed"
        return textwrap.dedent(
            f"""\
            # keys-on-the-wire starter config written by `kow setup`.
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

    if backend == "gsm":
        # Keyless by design (ADR-0018): NO key-file field. kow authenticates via
        # gcloud ADC / SA impersonation and refuses a downloaded key
        # (reject_ambient_key). self_check: deny refuses to start under a broad
        # identity. project_id is a placeholder — set it, then grant per-secret
        # read with `kow gcp-setup` (see the hand-off printed after setup).
        return textwrap.dedent(
            f"""\
            # keys-on-the-wire starter config written by `kow setup --gsm`.
            # Host bindings live in each GSM secret's `avp-binding` annotation
            # (binding_source: notes); no `secrets:` block is needed here.
            version: 1
            binding_source: notes
            # Pinned so daemon + tooling derive identical placeholders.
            install_salt_path: {paths.salt_path}
            backend:
              type: gsm
              config:
                type: gsm
                project_id: "REPLACE-WITH-YOUR-GCP-PROJECT-NUMBER"   # <- you MUST set this
                secret_prefix: "kow-"                 # scopes list + the self_check guard
                # impersonate_service_account: "kow-ro@PROJECT.iam.gserviceaccount.com"
                self_check: deny                      # refuse to start under a broad identity
                reject_ambient_key: true              # refuse a downloaded SA key via ADC
            audit:
              path: {paths.audit_path}
            """
        )

    if backend == "aws":
        # AWS Secrets Manager (ADR-0038): notes-aware like GSM — each secret
        # carries its host in an `avp-binding` tag or a `# avp-binding` marker in
        # its Description (binding_source: notes), so no `secrets:` block here.
        # Keyless via ambient IAM; nothing to paste. region + secret_prefix are
        # placeholders you MUST set, and self_check: deny bounds the namespace.
        return textwrap.dedent(
            f"""\
            # keys-on-the-wire starter config written by `kow setup --aws`.
            # Host bindings live in each secret's `avp-binding` tag (bare host) or a
            # `# avp-binding` marker block in its Description (binding_source: notes);
            # no `secrets:` block is needed here.
            version: 1
            binding_source: notes
            # Pinned so daemon + tooling derive identical placeholders.
            install_salt_path: {paths.salt_path}
            backend:
              type: aws-secrets-manager
              config:
                type: aws-secrets-manager
                region: "REPLACE-WITH-YOUR-AWS-REGION"   # <- you MUST set this (e.g. us-east-1)
                secret_prefix: "kow/"                 # scopes list + the self_check guard
                self_check: deny                      # refuse to start under a broad identity
                require_temporary_credentials: true   # refuse permanent IAM-user keys
            audit:
              path: {paths.audit_path}
            """
        )

    if backend == "keychain":
        # macOS Keychain (ADR-0046): a value-only backend with no notes metadata,
        # so — exactly like `static` — the bindings live in THIS file
        # (binding_source: file). The VALUE for each name comes from the login
        # keychain (service: kow), added out-of-band with `kow secret add`.
        # Keyless: nothing to paste. macOS only (guarded in run_setup).
        content = textwrap.dedent(
            f"""\
            # keys-on-the-wire starter config written by `kow setup --keychain`.
            # macOS only. Secret VALUES live in the login keychain (service: kow);
            # add them with `kow secret add`. This file carries the bindings.
            version: 1
            binding_source: file
            secrets:
              EXAMPLE_API_KEY:
                placeholder: "example_PLACEHOLDER_0001"
                inject:
                  header: "Authorization"
                  format: "Bearer {{EXAMPLE_API_KEY}}"
                bindings:
                  - host: "example.com"
            backend:
              type: keychain
              config:
                type: keychain
                service: kow
            audit:
              path: {paths.audit_path}
            """
        )
        Config.model_validate(yaml.safe_load(content))
        return content

    content = textwrap.dedent(
        f"""\
        # keys-on-the-wire starter config written by `kow setup`.
        # Static backend for development/testing only; replace this example before real use.
        version: 1
        binding_source: file
        secrets:
          EXAMPLE_API_KEY:
            placeholder: "example_PLACEHOLDER_0001"
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
        Description=keys-on-the-wire — BWS-backed egress credential injector
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=simple
        User={user}
        Group={group}
        ExecStart={paths.python_exe} -m kow --set kow_config={paths.bindings_path}
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
        "Label": _paths.MACOS_PLIST_LABEL,
        "UserName": user,
        "GroupName": group,
        "ProgramArguments": [
            paths.python_exe,
            "-m",
            "kow",
            "--set",
            f"kow_config={paths.bindings_path}",
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
    token = getpass("Paste the BWS machine-account access token (input hidden): ").strip()
    if not token:
        token = getpass("No token entered. Paste it now, or press Enter again to skip: ").strip()
    if not token:
        # Never write a 0-byte token file — that only produces confusing daemon
        # errors later. Skip cleanly and tell the user how to finish or switch.
        print(
            "kow setup: no BWS token provided — skipping (nothing written). The proxy "
            f"will not start until you write the token to {step.dest_path}, or re-run "
            "`sudo kow setup --static` (local file) or `sudo kow setup --gsm` "
            "(Google Secret Manager).",
            file=sys.stderr,
        )
        return
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
        kow env
        set -a; . ~/.config/kow/env; set +a
        """
    ).rstrip()
