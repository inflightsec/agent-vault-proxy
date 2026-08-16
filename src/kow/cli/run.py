"""``kow run`` / ``kow sandvault`` — launch a command with kow env routing.

Sets the four kow env vars (HTTPS_PROXY, NODE_EXTRA_CA_CERTS, SSL_CERT_FILE,
NODE_USE_ENV_PROXY) in the spawned process only — the host shell never
inherits them. Also auto-loads placeholder exports from ``~/.config/kow/env``
(written by ``kow env``) so the host shell can stay free of placeholder env
vars too. Optional ``--sandvault`` (or the ``kow sandvault`` alias)
additionally wraps the launch in the SandVault macOS sandbox tool.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from pathlib import Path

from kow import _paths

_LINUX_CA = _paths.resolve(_paths.LINUX_CONFDIR / "ca.pem")
_MACOS_CA = _paths.resolve(_paths.MACOS_CONFDIR / "ca.pem")
_DEFAULT_PROXY = "http://127.0.0.1:14322"
_LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")
# Resolved through cli.env.default_env_path() so the pre-rename
# ~/.config/kow/env keeps working (ADR-0045).
_DEFAULT_ENV_FILE = "~/.config/kow/env"

# Matches lines emitted by ``kow env``: ``export NAME='value'`` with a
# single-quoted, metachar-free value. We do not run the file through a shell.
_EXPORT_RE = re.compile(r"^export ([A-Za-z_][A-Za-z0-9_]*)='([^']*)'$")


def _default_ca_path() -> Path:
    return _MACOS_CA if sys.platform == "darwin" else _LINUX_CA


def _proxy_is_loopback(proxy_url: str) -> bool:
    """True if the proxy URL points at a loopback host. Used to warn the
    operator when they aim kow env at a non-local proxy (typo or attack)."""
    from urllib.parse import urlparse

    try:
        host = urlparse(proxy_url).hostname
    except ValueError:
        return False
    return host in _LOOPBACK_HOSTS


def _warn_env_file_perms(path: Path) -> None:
    """Defense-in-depth: warn (don't refuse) if the user-owned env file is
    not 0600 and self-owned. Threat is local — anyone who can write
    ``~/.config/kow/env`` already has code-execution as the user — but a
    loud warning catches honest misconfiguration."""
    try:
        st = path.lstat()
    except OSError:
        return
    if (st.st_mode & 0o777) != 0o600:
        print(
            f"[kow run] WARNING: {path} mode {oct(st.st_mode & 0o777)} "
            "(expected 0o600). Re-run `kow env` to rewrite.",
            file=sys.stderr,
        )
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        print(
            f"[kow run] WARNING: {path} not owned by current user.",
            file=sys.stderr,
        )


def _load_env_file(path: Path) -> dict[str, str]:
    """Parse ``export NAME='value'`` lines from ``path``.

    Returns an empty dict if the file is missing — that's the first-run /
    no-secrets case and not an error. Permission-denied is reported and also
    returns empty so launches don't break, but the operator sees the warning.

    Lines that don't match the strict format are skipped with a one-line
    warning each so a regex/grammar drift between ``kow env`` and this parser
    surfaces immediately instead of producing a silently-empty environment.
    We never pass the file through a shell."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    except OSError as exc:
        print(
            f"[kow run] WARNING: could not read {path}: {type(exc).__name__}.",
            file=sys.stderr,
        )
        return {}
    _warn_env_file_perms(path)
    out: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _EXPORT_RE.match(line)
        if m:
            out[m.group(1)] = m.group(2)
        else:
            print(
                f"[kow run] WARNING: skipping {path}:{lineno} — does not "
                "match `export NAME='value'` grammar.",
                file=sys.stderr,
            )
    return out


# Lowercase proxy variants and bypass lists that some clients prefer over the
# uppercase forms (curl, requests, some Go binaries). Without overriding these
# the host shell can divert traffic away from kow — e.g. `NO_PROXY=*` or a
# stale `https_proxy=http://other:3128` shadowing our routing.
_PROXY_OVERRIDE_KEYS = (
    "https_proxy",
    "http_proxy",
    "HTTP_PROXY",
    "all_proxy",
    "ALL_PROXY",
)
_PROXY_BYPASS_KEYS = ("NO_PROXY", "no_proxy")


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
    # Defense in depth: override every proxy variant + clear bypass lists so
    # an inherited host-shell value cannot route around kow.
    for key in _PROXY_OVERRIDE_KEYS:
        env[key] = proxy_url
    for key in _PROXY_BYPASS_KEYS:
        env.pop(key, None)
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
    """Set kow env and exec the requested command. Replaces this process."""
    command = list(args.argv or [])
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("usage: kow run [--sandvault] [--] CMD [ARGS...]")

    ca_path = Path(args.ca_cert) if args.ca_cert else _default_ca_path()
    if not ca_path.exists():
        raise SystemExit(f"kow CA not found at {ca_path}: run `sudo kow setup` first")

    if args.no_env_file:
        placeholder_env: dict[str, str] = {}
    else:
        env_file = Path(args.env_file).expanduser()
        placeholder_env = _load_env_file(env_file)

    env = _build_avp_env(ca_path, args.proxy, placeholder_env)

    if not _proxy_is_loopback(args.proxy):
        print(
            f"[kow run] WARNING: --proxy {args.proxy!r} is not loopback; "
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
        help="Path to kow CA cert (default: platform confdir ca.pem).",
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
            "written by `kow env`). Missing file is a no-op."
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
        help="Launch CMD with kow env routing scoped to its process tree.",
        description=(
            "Set HTTPS_PROXY, NODE_EXTRA_CA_CERTS, SSL_CERT_FILE, and "
            "NODE_USE_ENV_PROXY for CMD only — the host shell never inherits "
            "them. Also load placeholder exports from ~/.config/kow/env "
            "(written by `kow env`) so the host shell can stay free of "
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
        help="Alias for `kow run --sandvault`.",
        description=(
            "Wrap CMD with SandVault and kow env routing. Equivalent to "
            "`kow run --sandvault -- CMD`."
        ),
    )
    sv_p.add_argument(
        "argv",
        nargs=argparse.REMAINDER,
        metavar="CMD",
        help="Command and arguments to execute.",
    )
    sv_p.set_defaults(sandvault=True)
