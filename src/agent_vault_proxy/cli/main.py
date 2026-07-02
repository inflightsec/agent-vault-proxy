"""``avp`` operator CLI entry point.

Separate from the daemon entry point (``agent-vault-proxy`` ->
``__main__:main``, which launches mitmdump). ``avp`` hosts the operator
verbs that manage the install: today ``avp env`` (project BWS secrets to a
placeholder env file) and ``avp doctor`` (CA regression checks). Wired into
``[project.scripts]`` as ``avp``.

Kept deliberately thin: argument parsing + dispatch only. Each subcommand's
logic lives in its own module (``cli/env.py``, ``cli/doctor.py``) so it can
be unit-tested without going through argparse.
"""

from __future__ import annotations

import argparse
import sys

from agent_vault_proxy.cli.doctor import run_doctor
from agent_vault_proxy.cli.env import default_env_path, run_env
from agent_vault_proxy.cli.run import register_run_subparser, run_run
from agent_vault_proxy.cli.secret import register_secret_subparser, run_secret
from agent_vault_proxy.cli.setup import run_setup

_DEFAULT_CONFIG = "/etc/agent-vault-proxy/bindings.yaml"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="avp",
        description="agent-vault-proxy operator CLI (env projection, health checks).",
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
        help="Install-salt path (default: $AVP_CONFDIR/install-salt or next to bindings.yaml).",
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
            "Verify the narrow-trust CA invariants (ADR-0012): the AVP CA must not be "
            "in any OS/browser trust store, and the CA private key must be 0600 in a "
            "0700 confdir. Read-only."
        ),
    )
    doctor_p.add_argument(
        "--ca-cert",
        default=None,
        help="Path to the AVP CA cert (default: confdir mitmproxy-ca-cert.pem).",
    )
    doctor_p.add_argument(
        "--ca-key",
        default=None,
        help="Path to the AVP CA private key (default: confdir mitmproxy-ca.pem).",
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

    setup_p = sub.add_parser(
        "setup",
        help="Install the AVP service user, config, CA, and service definition.",
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
    setup_p.add_argument(
        "--static",
        action="store_true",
        help=(
            "Provision with the file-based static secrets backend instead of "
            "Bitwarden — no BWS token needed (development/testing only)."
        ),
    )
    register_secret_subparser(sub)
    register_run_subparser(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

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
        )
    if args.command == "setup":
        return run_setup(
            user=args.user,
            dry_run=args.dry_run,
            prefix=args.prefix,
            allow_mutable_audit=args.allow_mutable_audit,
            no_service=args.no_service,
            static=args.static,
        )
    if args.command == "secret":
        return run_secret(args)
    if args.command in ("run", "sandvault"):
        return run_run(args)

    # No subcommand — print help and signal misuse.
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
