"""``avp run`` / ``avp sandvault`` — launch a command with AVP env routing.

Sets the four AVP env vars (HTTPS_PROXY, NODE_EXTRA_CA_CERTS, SSL_CERT_FILE,
NODE_USE_ENV_PROXY) in the spawned process only — the host shell never
inherits them. Also auto-loads placeholder exports from ``~/.config/avp/env``
(written by ``avp env``) so the host shell can stay free of placeholder env
vars too. Optional ``--sandvault`` (or the ``avp sandvault`` alias)
additionally wraps the launch in the SandVault macOS sandbox tool.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from pathlib import Path

_LINUX_CA = Path("/etc/agent-vault-proxy/ca.pem")
_MACOS_CA = Path("/usr/local/etc/agent-vault-proxy/ca.pem")
_DEFAULT_PROXY = "http://127.0.0.1:14322"
_LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")
_DEFAULT_ENV_FILE = "~/.config/avp/env"

# Matches lines emitted by ``avp env``: ``export NAME='value'`` with a
# single-quoted, metachar-free value. We do not run the file through a shell.
_EXPORT_RE = re.compile(r"^export ([A-Za-z_][A-Za-z0-9_]*)='([^']*)'$")


def _default_ca_path() -> Path:
    return _MACOS_CA if sys.platform == "darwin" else _LINUX_CA


def _proxy_is_loopback(proxy_url: str) -> bool:
    """True if the proxy URL points at a loopback host. Used to warn the
    operator when they aim AVP env at a non-local proxy (typo or attack)."""
    from urllib.parse import urlparse

    try:
        host = urlparse(proxy_url).hostname
    except ValueError:
        return False
    return host in _LOOPBACK_HOSTS


def _load_env_file(path: Path) -> dict[str, str]:
    """Parse ``export NAME='value'`` lines from ``path``.

    Returns an empty dict if the file is missing — that's the first-run /
    no-secrets case and not an error. Lines that don't match the strict
    format are silently skipped; we never pass the file through a shell, so
    a malformed line is ignored rather than treated as injection."""
    try:
        text = path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return {}
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _EXPORT_RE.match(line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def _build_avp_env(
    ca_path: Path, proxy_url: str, placeholder_env: dict[str, str]
) -> dict[str, str]:
    env = os.environ.copy()
    # Placeholders first, then the four routing vars — routing always wins
    # if a placeholder file somehow contained HTTPS_PROXY etc. (it shouldn't).
    env.update(placeholder_env)
    env["HTTPS_PROXY"] = proxy_url
    env["NODE_EXTRA_CA_CERTS"] = str(ca_path)
    env["SSL_CERT_FILE"] = str(ca_path)
    env["NODE_USE_ENV_PROXY"] = "1"
    return env


def _resolve_sandvault() -> str:
    sandvault_bin = shutil.which("sandvault")
    if sandvault_bin is None:
        raise SystemExit(
            "sandvault not found on PATH. Install with:\n"
            "  brew install webcoyote/sandvault/sandvault"
        )
    return sandvault_bin


def run_run(args: argparse.Namespace) -> int:
    """Set AVP env and exec the requested command. Replaces this process."""
    command = list(args.argv or [])
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("usage: avp run [--sandvault] [--] CMD [ARGS...]")

    ca_path = Path(args.ca_cert) if args.ca_cert else _default_ca_path()
    if not ca_path.exists():
        raise SystemExit(f"AVP CA not found at {ca_path}: run `sudo avp setup` first")

    if args.no_env_file:
        placeholder_env: dict[str, str] = {}
    else:
        env_file = Path(args.env_file).expanduser()
        placeholder_env = _load_env_file(env_file)

    env = _build_avp_env(ca_path, args.proxy, placeholder_env)

    if not _proxy_is_loopback(args.proxy):
        print(
            f"[avp run] WARNING: --proxy {args.proxy!r} is not loopback; "
            "this routes credentials through a remote host. Use 127.0.0.1 "
            "unless you've intentionally chosen another endpoint.",
            file=sys.stderr,
        )

    if args.sandvault:
        command = [_resolve_sandvault(), "--", *command]

    try:
        # execvpe takes argv as a list (not a shell string), so there's no
        # shell injection surface — the user explicitly chose what to launch.
        os.execvpe(command[0], command, env)  # noqa: S606  # nosec B606
    except FileNotFoundError:
        raise SystemExit(f"command not found: {command[0]}") from None


def register_run_subparser(parent_subparsers: argparse._SubParsersAction) -> None:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--ca-cert",
        default=None,
        help="Path to AVP CA cert (default: platform confdir ca.pem).",
    )
    common.add_argument(
        "--proxy",
        default=_DEFAULT_PROXY,
        help=f"HTTPS_PROXY value to set (default {_DEFAULT_PROXY}).",
    )
    common.add_argument(
        "--env-file",
        default=_DEFAULT_ENV_FILE,
        help=(
            f"Placeholder env file to load (default {_DEFAULT_ENV_FILE}, "
            "written by `avp env`). Missing file is a no-op."
        ),
    )
    common.add_argument(
        "--no-env-file",
        action="store_true",
        help="Skip loading any placeholder env file.",
    )

    run_p = parent_subparsers.add_parser(
        "run",
        parents=[common],
        help="Launch CMD with AVP env routing scoped to its process tree.",
        description=(
            "Set HTTPS_PROXY, NODE_EXTRA_CA_CERTS, SSL_CERT_FILE, and "
            "NODE_USE_ENV_PROXY for CMD only — the host shell never inherits "
            "them. Also load placeholder exports from ~/.config/avp/env "
            "(written by `avp env`) so the host shell can stay free of "
            "placeholder vars too. Use `--` before CMD to disambiguate flags."
        ),
    )
    run_p.add_argument(
        "--sandvault",
        action="store_true",
        help="Also wrap CMD with SandVault (requires `sandvault` on PATH).",
    )
    run_p.add_argument(
        "argv",
        nargs=argparse.REMAINDER,
        metavar="CMD",
        help="Command and arguments to execute.",
    )

    sv_p = parent_subparsers.add_parser(
        "sandvault",
        parents=[common],
        help="Alias for `avp run --sandvault`.",
        description=(
            "Wrap CMD with SandVault and AVP env routing. Equivalent to "
            "`avp run --sandvault -- CMD`."
        ),
    )
    sv_p.add_argument(
        "argv",
        nargs=argparse.REMAINDER,
        metavar="CMD",
        help="Command and arguments to execute.",
    )
    sv_p.set_defaults(sandvault=True)
