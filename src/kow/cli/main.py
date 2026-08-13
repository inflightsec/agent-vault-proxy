"""``avp`` operator CLI entry point.

Separate from the daemon entry point (``keys-on-the-wire`` ->
``__main__:main``, which launches mitmdump). ``avp`` hosts the operator
verbs that manage the install: today ``kow env`` (project BWS secrets to a
placeholder env file) and ``kow doctor`` (CA regression checks). Wired into
``[project.scripts]`` as ``avp``.

Kept deliberately thin: argument parsing + dispatch only. Each subcommand's
logic lives in its own module (``cli/env.py``, ``cli/doctor.py``) so it can
be unit-tested without going through argparse.
"""

from __future__ import annotations

import argparse
import sys

from kow.cli.binding import register_binding_subparser, run_binding
from kow.cli.doctor import run_doctor
from kow.cli.env import default_env_path, run_env
from kow.cli.gcp_setup import run_gcp_setup
from kow.cli.mcp import register_mcp_subparser, run_mcp
from kow.cli.moo import run_moo
from kow.cli.oauth_login import register_oauth_subparser, run_oauth
from kow.cli.run import register_run_subparser, run_run
from kow.cli.secret import register_secret_subparser, run_secret
from kow.cli.setup import run_setup
from kow.placeholders import InstallSaltError

_DEFAULT_CONFIG = "/etc/agent-vault-proxy/bindings.yaml"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="avp",
        description="keys-on-the-wire operator CLI (env projection, health checks).",
    )
    sub = parser.add_subparsers(dest="command")

    env_p = sub.add_parser(
        "env",
        help="Project BWS project secrets to a placeholder env file.",
        description=(
            "List the BWS project's secrets, derive each one's salted placeholder, "
            "and write `export NAME='<placeholder>'` lines to a 0600 env file. The "
            "agent sources this file and never sees real credential bytes."
        ),
    )
    env_p.add_argument("--config", default=_DEFAULT_CONFIG, help="Path to bindings.yaml.")
    env_p.add_argument(
        "--out",
        default=None,
        help=f"Env file to write (default {default_env_path()}).",
    )
    env_p.add_argument(
        "--salt",
        default=None,
        help="Install-salt path (default: $KOW_CONFDIR/install-salt or next to bindings.yaml).",
    )
    env_p.add_argument(
        "--print",
        dest="print_only",
        action="store_true",
        help="Print export lines to stdout instead of writing the env file.",
    )
    env_p.add_argument(
        "--refresh",
        action="store_true",
        help="Re-project from BWS (every run re-projects; flag is for clarity).",
    )

    doctor_p = sub.add_parser(
        "doctor",
        help="Read-only health checks (CA not in OS trust store; CA key perms).",
        description=(
            "Verify the narrow-trust CA invariants (ADR-0012): the kow CA must not be "
            "in any OS/browser trust store, and the CA private key must be 0600 in a "
            "0700 confdir. Read-only."
        ),
    )
    doctor_p.add_argument(
        "--ca-cert",
        default=None,
        help="Path to the kow CA cert (default: confdir mitmproxy-ca-cert.pem).",
    )
    doctor_p.add_argument(
        "--ca-key",
        default=None,
        help="Path to the kow CA private key (default: confdir mitmproxy-ca.pem).",
    )
    doctor_p.add_argument(
        "--config",
        default=_DEFAULT_CONFIG,
        help="Path to bindings.yaml (only used by --probe-oauth).",
    )
    doctor_p.add_argument(
        "--probe-oauth",
        action="store_true",
        help=(
            "Probe each oauth2_refresh binding: SSRF, vault inputs, "
            "write-back capability. Read-only unless --exchange is also given."
        ),
    )
    doctor_p.add_argument(
        "--binding",
        default=None,
        help="Restrict --probe-oauth to one named binding (default: probe all).",
    )
    doctor_p.add_argument(
        "--exchange",
        action="store_true",
        help=(
            "When combined with --probe-oauth, actually call the upstream "
            "token endpoint. MAY ROTATE the refresh token (provider-dependent); "
            "a rotation during a probe is reported as a WARN since the probe "
            "does not write-back to the vault."
        ),
    )

    doctor_p.add_argument(
        "--probe-gcp",
        action="store_true",
        help=(
            "Read-only Google Secret Manager identity/scope report for a `gsm` "
            "backend: keyless auth, enumeration scope, project-wide access, and "
            "in-scope secret count. Never writes."
        ),
    )

    setup_p = sub.add_parser(
        "setup",
        help="Install the kow service user, config, CA, and service definition.",
        description=(
            "Perform the primary manual install for agent-vault-proxy: create the "
            "service user, lay out directories, prompt for the BWS token, write the "
            "starter bindings, generate the CA and install salt, and register the "
            "system service."
        ),
    )
    setup_p.add_argument(
        "--user",
        default=None,
        help="Service user to create/use (default: avp on Linux, _avp on macOS).",
    )
    setup_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the planned setup actions without changing the host.",
    )
    setup_p.add_argument(
        "--prefix",
        default=None,
        help="Optional prefix root for staging the install layout.",
    )
    setup_p.add_argument(
        "--allow-mutable-audit",
        action="store_true",
        help=(
            "Downgrade append-only audit lock failure from fatal to a loud warning, "
            "for filesystems that cannot support chattr +a / chflags sappnd."
        ),
    )
    setup_p.add_argument(
        "--no-service",
        action="store_true",
        help=(
            "Provision everything (user, dirs, token, bindings, CA, salt, service "
            "definition FILE) but skip service activation; the provision-only path "
            "for Ansible / managed supervision and container tests."
        ),
    )
    backend_group = setup_p.add_mutually_exclusive_group()
    backend_group.add_argument(
        "--bws",
        action="store_true",
        help="Backend: Bitwarden Secrets Manager (prompts for a machine-account token).",
    )
    backend_group.add_argument(
        "--gsm",
        action="store_true",
        help="Backend: Google Secret Manager — keyless; hands off to `kow gcp-setup`.",
    )
    backend_group.add_argument(
        "--static",
        action="store_true",
        help=(
            "Backend: local file-based static secrets — no BWS token needed "
            "(development/testing / headless). With no backend flag, setup prompts "
            "you to choose one."
        ),
    )
    gcp_setup_p = sub.add_parser(
        "gcp-setup",
        help="Grant a service account PER-SECRET Google Secret Manager access.",
        description=(
            "Grant roles/secretmanager.secretAccessor on each named secret "
            "individually (never project/folder/org level) so the gsm backend's "
            "identity can read only its own secrets. Shells out to gcloud."
        ),
    )
    gcp_setup_p.add_argument("--project", required=True, help="GCP project id or number.")
    gcp_setup_p.add_argument(
        "--member",
        required=True,
        help="IAM member, e.g. serviceAccount:avp-ro@PROJECT.iam.gserviceaccount.com.",
    )
    gcp_setup_p.add_argument(
        "--secret",
        dest="secrets",
        action="append",
        default=[],
        help="Secret id to grant access on (repeatable).",
    )
    gcp_setup_p.add_argument(
        "--scope",
        default="secret",
        help="Grant scope. Only 'secret' is allowed; broader scopes are refused.",
    )
    gcp_setup_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the gcloud commands without running them.",
    )

    register_secret_subparser(sub)
    register_run_subparser(sub)
    register_binding_subparser(sub)
    register_mcp_subparser(sub)
    register_oauth_subparser(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    # Undocumented easter egg: `kow moo`. Intercepted before argparse so it
    # never surfaces in --help (not even in the subcommand choices metavar).
    if (sys.argv[1:] if argv is None else argv) == ["moo"]:
        return run_moo()

    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return _dispatch(parser, args)
    except InstallSaltError as exc:
        # Graceful, no-traceback exit for the install-salt guards (perms /
        # ownership / corruption). They're operator-fixable, and a raw Python
        # traceback buries both the message and the likely "ran as root" cause.
        print(f"avp: {exc}", file=sys.stderr)
        if exc.hint:
            print(f"\n{exc.hint}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        # Missing config / salt / cert path — an operator path mistake, not a
        # bug. One actionable line instead of a traceback.
        target = exc.filename or exc.strerror or exc
        print(f"avp: file not found: {target}", file=sys.stderr)
        print("Check the --config path (and that setup has run) and try again.", file=sys.stderr)
        return 1


def _dispatch(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    if args.command == "env":
        return run_env(
            config_path=args.config,
            env_path=args.out,
            salt_path=args.salt,
            print_only=args.print_only,
            refresh=args.refresh,
        )
    if args.command == "doctor":
        return run_doctor(
            ca_cert_path=args.ca_cert,
            ca_key_path=args.ca_key,
            config_path=args.config,
            probe_oauth=args.probe_oauth,
            binding_filter=args.binding,
            do_exchange=args.exchange,
            probe_gcp=args.probe_gcp,
        )
    if args.command == "setup":
        return run_setup(
            user=args.user,
            dry_run=args.dry_run,
            prefix=args.prefix,
            allow_mutable_audit=args.allow_mutable_audit,
            no_service=args.no_service,
            static=args.static,
            gsm=args.gsm,
            bws=args.bws,
        )
    if args.command == "gcp-setup":
        return run_gcp_setup(
            project=args.project,
            member=args.member,
            secrets=args.secrets,
            scope=args.scope,
            dry_run=args.dry_run,
        )
    if args.command == "secret":
        return run_secret(args)
    if args.command in ("run", "sandvault"):
        return run_run(args)
    if args.command == "binding":
        return run_binding(args)
    if args.command == "mcp":
        return run_mcp(args)
    if args.command == "oauth":
        return run_oauth(args)

    # No subcommand — print help and signal misuse.
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
