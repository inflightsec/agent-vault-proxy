"""``avp mcp install`` — broker an MCP server's upstream credential through AVP.

ADR-0040. An MCP server is a subprocess that holds a long-lived upstream secret
(a GitHub PAT, a Slack token, a Brave key) in cleartext in the client config. This
command replaces that standing secret with a placeholder and routes the server's
egress through the proxy, so the credential value is never in the config and never
visible to the (possibly supply-chained) server process.

It composes two existing pieces plus the new env plumbing:

1. The vault **binding note** — built and self-validated exactly like ``avp binding
   new`` (marker + ``{secret}`` + valid host, ADR-0029 stored placeholder). This
   command is **propose-only for the vault**: it prints the note to paste and never
   writes the secret value anywhere.
2. The per-server **env block** — proxy vars + the per-runtime CA-trust var(s) + the
   node/undici bypass flag + the placeholder, rendered as the client's native
   ``claude mcp add --env`` / ``codex mcp add --env`` command. The placeholder is a
   non-secret sentinel, so writing it into client config is safe.

Security posture (ADR-0040 §5):
- The credential **value** is never emitted — only the placeholder sentinel and the
  note template. The host allowlist + response-echo scrubbing keep the value hidden
  even from a compromised server; scope caps its *use*.
- CA trust is granted **per-server** (an env var pointing at the AVP CA), never a
  system trust store — the MITM-capable CA is trusted by exactly the servers you
  install, nothing else.
- The ``host`` field is the trust-critical one (a wrong host leaks the key). The
  caller/skill confirms it with a human before invoking this command; the CLI is
  mechanical plumbing.
"""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
import unicodedata

from kow.cli.run import _DEFAULT_PROXY, _default_ca_path, _proxy_is_loopback
from kow.notes_binding import (
    NOTES_MARKER,
    InvalidBinding,
    ParsedBinding,
    parse_notes_binding,
)
from kow.placeholders import PLACEHOLDER_PREFIX, mint_placeholder

_SECRET_TOKEN = "{secret}"  # noqa: S105  # nosec B105 — public template slot, not a credential
_VALIDATE_PLACEHOLDER = PLACEHOLDER_PREFIX + "mcpinstallvalidatesentinel"

# Consumer-visible sentinel when the operator opts out of a stored placeholder
# (--no-placeholder). The real placeholder is then salt-derived on the daemon host
# and discovered with `avp env`; we cannot know it here, so we flag it loudly.
_DERIVE_SENTINEL = "avp-DERIVE-VIA-avp-env"

# client id -> the CLI binary that owns its config schema (we drive the client's own
# `mcp add`, never hand-write its config file — ADR-0040 §2).
_CLIENT_BIN = {"claude-code": "claude", "codex": "codex"}
_CLIENTS = tuple(_CLIENT_BIN)

# The server name and env-var flow into the client `mcp add` argv as a positional and
# an `--env NAME=…` key. Even with a no-shell argv, a value that begins with `-` or
# carries metachars would be reparsed by the client CLI as a FLAG, not data (argv
# flag-smuggling). Positive grammars, fail-closed — no leading dash, no URL/authority
# characters. Host injection is separately fail-closed by the daemon's own
# parse_notes_binding (a URL-shaped host never parses).
_SERVER_NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_ENV_NAME_RE = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*\Z")

# The note is flat YAML assembled line-by-line; a line break in any note-bound field
# (header/format/methods/paths/host) injects a SECOND key — a `host:` line that
# overrides the operator-confirmed host (credential exfil), or a `methods:`/`paths:`
# line that silently WIDENS scope (defeats ADR-0040 §5 method-scoping). PyYAML honors
# more break chars than ASCII \n\r\t: NEL (U+0085), LS (U+2028), PS (U+2029). Reject the
# whole Unicode control/format/separator space (categories Cc, Cf, Zl, Zp) so no current
# or future break char can split the note. Fail-closed; legit header/format/method/path
# values are printable and never fall in these categories.
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


def _has_forbidden_char(value: str) -> bool:
    return any(unicodedata.category(ch) in _FORBIDDEN_CATEGORIES for ch in value)


def _die(msg: str) -> int:
    print(f"avp mcp: {msg}", file=sys.stderr)
    return 1


def _build_note(
    *,
    hosts: list[str],
    header: str,
    fmt: str,
    methods: list[str],
    paths: list[str],
    placeholder: str | None,
) -> str:
    """Flat-YAML note, marker first, canonical field order (mirrors cli/binding.py)."""
    lines = [NOTES_MARKER]
    if len(hosts) == 1:
        lines.append(f"host: {hosts[0]}")
    else:
        lines.append("host: [" + ", ".join(hosts) + "]")
    if placeholder is not None:
        lines.append(f"placeholder: {placeholder}")
    lines.append(f"header: {header}")
    lines.append(f'format: "{fmt}"')
    if methods:
        lines.append("methods: [" + ", ".join(methods) + "]")
    if paths:
        lines.append("paths: [" + ", ".join(f'"{p}"' for p in paths) + "]")
    return "\n".join(lines) + "\n"


def _env_block(
    *, runtime: str, proxy_url: str, ca_cert: str, env_var: str, placeholder_value: str
) -> dict[str, str]:
    """The per-server env vars, ordered deterministically.

    Because MCP clients start the server from a restricted env allowlist
    (ADR-0040 §Context), every var — proxy, CA trust, bypass — must be listed
    explicitly; nothing is inherited from the shell.
    """
    # Both cases: some runtimes / HTTP stacks honor only the lowercase forms.
    block: dict[str, str] = {
        "HTTPS_PROXY": proxy_url,
        "HTTP_PROXY": proxy_url,
        "NO_PROXY": "localhost,127.0.0.1",
        "https_proxy": proxy_url,
        "http_proxy": proxy_url,
        "no_proxy": "localhost,127.0.0.1",
    }
    if runtime in ("node", "auto"):
        # undici ignores HTTPS_PROXY unless this is set — the #1 silent-failure trap.
        block["NODE_USE_ENV_PROXY"] = "1"
        block["NODE_EXTRA_CA_CERTS"] = ca_cert
    if runtime in ("python", "auto"):
        block["REQUESTS_CA_BUNDLE"] = ca_cert
        block["SSL_CERT_FILE"] = ca_cert
    if runtime == "go":
        block["SSL_CERT_FILE"] = ca_cert
    block[env_var] = placeholder_value
    return block


def _client_argv(
    *, client: str, server: str, env_block: dict[str, str], server_cmd: list[str]
) -> list[str]:
    """Build the argv for `<client> mcp add` — a list, never a shell string, so no
    value is ever shell-interpolated."""
    argv = [_CLIENT_BIN[client], "mcp", "add", server]
    for key, value in env_block.items():
        argv += ["--env", f"{key}={value}"]
    argv.append("--")
    argv += server_cmd if server_cmd else ["<SERVER_COMMAND...>"]
    return argv


def _split_csv(value: str | None) -> list[str]:
    return [x.strip() for x in value.split(",") if x.strip()] if value else []


def _validate_install(args: argparse.Namespace) -> str | None:
    """Return an error message if the install args are unsafe/invalid, else None.

    Fail closed on argv flag-smuggling: the server name and env-var become an argv
    positional / `--env NAME=…` key in the client command; a leading dash or a
    metachar would be reparsed as a flag by `claude`/`codex mcp add`. (Host
    injection is separately fail-closed by parse_notes_binding — a URL-shaped host
    never parses.)
    """
    if not _SERVER_NAME_RE.match(args.server):
        return (
            f"server name {args.server!r} must be alphanumeric with . _ - "
            "(no leading dash, no URL/metacharacters)."
        )
    if not _ENV_NAME_RE.match(args.env_var):
        return (
            f"--env-var {args.env_var!r} must be a valid environment identifier "
            "([A-Za-z_][A-Za-z0-9_]*)."
        )
    if _SECRET_TOKEN not in args.format:
        return (
            f"--format must contain the {_SECRET_TOKEN} token "
            f'(e.g. "Bearer {_SECRET_TOKEN}"); got {args.format!r}.'
        )
    # Reject control/format/separator chars in every note-bound field — closes the
    # YAML line-injection class (host override AND scope widening) for every break
    # character PyYAML honors, ASCII or Unicode (see _FORBIDDEN_CATEGORIES).
    note_fields = [("--header", args.header), ("--format", args.format)]
    note_fields += [("--methods", args.methods), ("--paths", args.paths)]
    note_fields += [("--host", h) for h in args.host]
    for label, value in note_fields:
        if value and _has_forbidden_char(value):
            return (
                f"{label} must not contain control, format, or line-separator "
                "characters (newline, tab, NEL, U+2028/U+2029, zero-width, etc.)."
            )
    if args.apply and args.no_placeholder:
        return (
            "--apply cannot be combined with --no-placeholder: it would write the "
            "non-functional derive sentinel into the client config as if it were live."
        )
    if args.apply and not args.server_cmd:
        return (
            "--apply requires --server-cmd: applying without the real launch command "
            "registers a broken client entry (the literal <SERVER_COMMAND...> token)."
        )
    return None


def _emit_client_commands(
    args: argparse.Namespace, env_block: dict[str, str], server_cmd: list[str]
) -> bool:
    """Render (default) or run (--apply) each client's `mcp add --env` command.

    Returns False if any --apply invocation failed (missing binary or non-zero exit),
    so the caller can propagate a non-zero exit — an install that silently fails to
    register the server is worse than a loud one.
    """
    ok = True
    for client in dict.fromkeys(args.client) if args.client else list(_CLIENTS):
        argv = _client_argv(
            client=client, server=args.server, env_block=env_block, server_cmd=server_cmd
        )
        # shlex.join so the printed copy-paste command is shell-safe — a metachar in
        # --proxy-url / --ca-cert / --server-cmd must not inject into the operator's shell.
        rendered = shlex.join(argv)
        if args.apply:
            print(f"avp mcp: applying [{client}]: {rendered}", file=sys.stderr)
            try:
                proc = subprocess.run(argv, check=False)  # noqa: S603 — argv list, no shell
            except FileNotFoundError:
                ok = False
                print(
                    f"avp mcp: [{client}] binary {_CLIENT_BIN[client]!r} not found on PATH "
                    "— install the client, or drop --apply and run the printed command.",
                    file=sys.stderr,
                )
                continue
            if proc.returncode != 0:
                ok = False
                print(f"avp mcp: [{client}] `mcp add` exited {proc.returncode}", file=sys.stderr)
        else:
            print(f"avp mcp: add to [{client}] — run:\n  {rendered}", file=sys.stderr)
    return ok


def _emit_reminders(*, minted: str | None, name: str) -> None:
    print(
        "avp mcp: paste the note above into the secret's vault entry (the secret "
        "VALUE is never touched by this command).",
        file=sys.stderr,
    )
    if minted is not None:
        print(
            f"avp mcp: the placeholder {minted!r} is a non-secret sentinel — it is what "
            f"the client emits and the daemon swaps for the real {name}.",
            file=sys.stderr,
        )
    else:
        print(
            "avp mcp: --no-placeholder set; resolve the salt-derived placeholder on the "
            f"daemon host with `avp env` and replace {_DERIVE_SENTINEL!r} in the client env.",
            file=sys.stderr,
        )
    print("avp mcp: the daemon picks the note up on its next reload.", file=sys.stderr)


def _emit_smoke(args: argparse.Namespace, placeholder_value: str) -> None:
    # This string is printed for the operator to copy-paste into a shell, so every
    # interpolated field is shlex.quote'd — a single quote in a docs-derived --header
    # would otherwise break out and inject commands into the operator's shell.
    header_value = args.format.replace(_SECRET_TOKEN, placeholder_value)
    smoke = (
        f"HTTPS_PROXY={shlex.quote(args.proxy_url)} curl -sS -o /dev/null -w '%{{http_code}}' "
        f"--cacert {shlex.quote(args.ca_cert)} "
        f"-H {shlex.quote(f'{args.header}: {header_value}')} "
        f"{shlex.quote(f'https://{args.host[0]}/')}"
    )
    print(
        "avp mcp: smoke — with the daemon running and the note live, this should "
        f"authenticate using the placeholder (never the real key):\n  {smoke}",
        file=sys.stderr,
    )


def run_mcp(args: argparse.Namespace) -> int:
    if getattr(args, "mcp_cmd", None) != "install":
        return _die(
            "unknown subcommand; use `avp mcp install <server> --host <host> --env-var <VAR>`."
        )

    error = _validate_install(args)
    if error is not None:
        return _die(error)

    minted = None if args.no_placeholder else mint_placeholder()
    placeholder_value = minted if minted is not None else _DERIVE_SENTINEL
    name = args.env_var  # the secret name IS the env var the server reads

    note = _build_note(
        hosts=args.host,
        header=args.header,
        fmt=args.format,
        methods=_split_csv(args.methods),
        paths=_split_csv(args.paths),
        placeholder=minted,
    )

    # Self-validate against the daemon's own parser — never emit a binding it rejects.
    result = parse_notes_binding(secret_name=name, placeholder=_VALIDATE_PLACEHOLDER, note=note)
    if isinstance(result, InvalidBinding):
        return _die(f"generated binding is invalid: {result.diagnostic}")
    if not isinstance(result, ParsedBinding):
        return _die(
            "generated note did not resolve to a binding (no usable host). "
            "Pass at least one valid --host (dot-separated DNS labels)."
        )

    # Load-bearing host-intent check (defense in depth behind the control-char
    # reject): the human confirmed `--host`, but self-validation only proves the
    # note PARSES — it does not prove the parsed host equals what was confirmed. If
    # any injected field shifted the bound host, the parsed set won't match. Refuse.
    expected_hosts = {h.strip().lower().rstrip(".") for h in args.host}
    parsed_hosts = {b.host.lower().rstrip(".") for b in result.spec.bindings}
    if parsed_hosts != expected_hosts:
        return _die(
            f"host-intent mismatch: the validated note binds {sorted(parsed_hosts)} "
            f"but --host requested {sorted(expected_hosts)}. Refusing (possible "
            "injection via header/format/methods/paths)."
        )

    # --server-cmd is shell-quoted by the operator; a malformed quote must fail cleanly
    # (not a raw ValueError traceback).
    try:
        server_cmd = shlex.split(args.server_cmd) if args.server_cmd else []
    except ValueError as exc:
        return _die(f"--server-cmd is not valid shell-quoting: {exc}")

    if not _proxy_is_loopback(args.proxy_url):
        print(
            f"avp mcp: WARNING: --proxy-url {args.proxy_url!r} is not loopback. AVP's "
            "model assumes a local proxy; only the placeholder (never the real secret) "
            "reaches client env, so this fails closed — but double-check the URL.",
            file=sys.stderr,
        )

    env_block = _env_block(
        runtime=args.runtime,
        proxy_url=args.proxy_url,
        ca_cert=args.ca_cert,
        env_var=name,
        placeholder_value=placeholder_value,
    )

    # stdout stays the pure paste artifact (the vault note), like `avp binding new`;
    # all operator guidance goes to stderr.
    print(note, end="")
    applied_ok = _emit_client_commands(args, env_block, server_cmd)
    _emit_reminders(minted=minted, name=name)
    if args.smoke:
        _emit_smoke(args, placeholder_value)
    return 0 if applied_ok else 1


def register_mcp_subparser(parent_subparsers: argparse._SubParsersAction) -> None:
    mcp_p = parent_subparsers.add_parser(
        "mcp",
        help="Broker an MCP server's upstream credential through AVP (ADR-0040).",
        description=(
            "Compose the vault binding note and emit the per-server env block "
            "(proxy + per-runtime CA trust + placeholder) as the client's native "
            "`mcp add --env` command. Propose-only for the vault; the secret value "
            "is never written."
        ),
    )
    mcp_sub = mcp_p.add_subparsers(dest="mcp_cmd")
    install_p = mcp_sub.add_parser(
        "install",
        help="Print the vault note + the `claude/codex mcp add --env` command for a server.",
        description=(
            "Build and self-validate an ADR-0029 binding note, then render the "
            "env block a client needs to route the server through AVP. Prints "
            "both; writes nothing unless --apply is given (and even then, only the "
            "env block, never the secret value)."
        ),
    )
    install_p.add_argument("server", help="MCP server id/name (used for the `mcp add` entry).")
    install_p.add_argument(
        "--host",
        action="append",
        required=True,
        metavar="HOST",
        help="Upstream host the credential is sent to. Repeat for multi-host.",
    )
    install_p.add_argument(
        "--env-var",
        required=True,
        dest="env_var",
        help="Env var the MCP server reads its credential from (e.g. GITHUB_TOKEN).",
    )
    install_p.add_argument(
        "--header",
        default="Authorization",
        help="HTTP header to inject into (default: Authorization).",
    )
    install_p.add_argument(
        "--format",
        default="Bearer {secret}",
        help='Header value template; MUST contain {secret} (default: "Bearer {secret}").',
    )
    install_p.add_argument(
        "--methods",
        default=None,
        help="Comma-separated HTTP methods to scope the binding (recommended; default: all).",
    )
    install_p.add_argument(
        "--paths",
        default=None,
        help="Comma-separated URL path globs to scope the binding (optional; default: all).",
    )
    install_p.add_argument(
        "--runtime",
        choices=("node", "python", "go", "auto"),
        default="auto",
        help="Server runtime — selects the CA-trust env var(s). auto = node+python superset.",
    )
    install_p.add_argument(
        "--client",
        action="append",
        choices=_CLIENTS,
        default=None,
        help="Target client (repeatable). Default: both claude-code and codex.",
    )
    install_p.add_argument(
        "--proxy-url",
        dest="proxy_url",
        default=_DEFAULT_PROXY,
        help=f"AVP proxy URL for HTTPS_PROXY/HTTP_PROXY (default: {_DEFAULT_PROXY}).",
    )
    install_p.add_argument(
        "--ca-cert",
        dest="ca_cert",
        default=str(_default_ca_path()),
        help="Path the runtime CA-trust vars point at (the AVP CA; platform default).",
    )
    install_p.add_argument(
        "--server-cmd",
        dest="server_cmd",
        default=None,
        help='MCP server launch command, quoted (e.g. "npx -y server-github").',
    )
    install_p.add_argument(
        "--apply",
        action="store_true",
        help="Run the client `mcp add` command(s) (env block only; never the secret value).",
    )
    install_p.add_argument(
        "--smoke",
        action="store_true",
        help="Also print the smoke command that verifies injection through a live daemon.",
    )
    install_p.add_argument(
        "--no-placeholder",
        action="store_true",
        help="Legacy salt-derived flow: omit the stored placeholder from the note.",
    )
