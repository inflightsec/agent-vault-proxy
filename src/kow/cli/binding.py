"""``kow binding`` — generate a paste-ready binding note/annotation.

Deterministic authoring of the per-secret binding metadata (BWS ``notes`` field
or GSM ``avp-binding`` annotation). The tool builds the note from flags and
**validates it through the daemon's own** ``parse_notes_binding`` **parser
before printing it**, so it can only ever emit a binding the daemon will
accept — the mandatory ``# avp-binding`` marker present, the ``{secret}`` token
present, a valid host.

This is the code-before-prompts backbone the ``kow`` skill wraps: the
security-critical note is produced by code, not authored free-hand by an LLM.
Two real outages came from hand-authored notes — a missing marker (2026-07-18,
silent fleet un-brokering) and a host-shaped description mistaken for a host —
both structurally impossible to emit from this tool.
"""

from __future__ import annotations

import argparse
import sys

from kow.notes_binding import (
    NOTES_MARKER,
    InvalidBinding,
    ParsedBinding,
    parse_notes_binding,
)
from kow.placeholders import PLACEHOLDER_PREFIX, mint_placeholder

# The generic substitution token the note carries (the parser rewrites it to
# ``{<secret_name>}``). Kept in sync with notes_binding by contract.
_SECRET_TOKEN = "{secret}"  # noqa: S105  # nosec B105 — public template slot, not a credential

# Any non-empty placeholder validates; it is only stamped into the SecretSpec
# during self-validation (never emitted). Built from the prefix constant so it
# tracks the format automatically and stays regex-valid.
_VALIDATE_PLACEHOLDER = PLACEHOLDER_PREFIX + "bindingnewvalidatesentinel"


def _die(msg: str) -> int:
    print(f"kow binding: {msg}", file=sys.stderr)
    return 1


def _build_note(
    *,
    hosts: list[str],
    header: str,
    fmt: str,
    methods: list[str],
    paths: list[str],
    placeholder: str | None = None,
) -> str:
    """Build the flat-YAML note, marker first, in the canonical field order."""
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


def _gsm_command(name: str, note: str) -> str:
    """Render the gcloud annotation-update command, printf-embedding the note so
    the multi-line YAML survives as a single shell argument (matches the
    kow skill's GSM example)."""
    embedded = note.rstrip("\n").replace('"', '\\"').replace("\n", "\\n")
    return (
        f"gcloud secrets update {name} --update-annotations=\"kow-binding=$(printf '{embedded}')\""
    )


def run_binding(args: argparse.Namespace) -> int:
    if getattr(args, "binding_cmd", None) != "new":
        return _die("unknown subcommand; use `kow binding new --host <host>`.")

    fmt: str = args.format
    if _SECRET_TOKEN not in fmt:
        return _die(
            f"--format must contain the {_SECRET_TOKEN} token "
            f'(e.g. "Bearer {_SECRET_TOKEN}"); got {fmt!r}.'
        )

    methods = [m.strip() for m in args.methods.split(",") if m.strip()] if args.methods else []
    paths = [p.strip() for p in args.paths.split(",") if p.strip()] if args.paths else []

    # ADR-0029: mint a stored placeholder by default so the note itself pins
    # what the consumer must emit — no salt, no sudo `kow env` discovery.
    # `--no-placeholder` keeps the legacy salt-derived flow.
    minted = None if getattr(args, "no_placeholder", False) else mint_placeholder()

    note = _build_note(
        hosts=args.host,
        header=args.header,
        fmt=fmt,
        methods=methods,
        paths=paths,
        placeholder=minted,
    )

    # Self-validate against the REAL parser: refuse to print anything the daemon
    # would reject. This is the entire point of the tool.
    result = parse_notes_binding(
        secret_name=args.name, placeholder=_VALIDATE_PLACEHOLDER, note=note
    )
    if isinstance(result, InvalidBinding):
        return _die(f"generated binding is invalid: {result.diagnostic}")
    if not isinstance(result, ParsedBinding):
        return _die(
            "generated note did not resolve to a binding (no usable host). "
            "Pass at least one valid --host (dot-separated DNS labels)."
        )

    if args.backend == "gsm":
        print(_gsm_command(args.name, note))
    else:
        print(note, end="")
    if minted is not None:
        # Wiring hint on stderr (stdout stays a pure paste artifact): the
        # placeholder is a sentinel, not a secret — safe to print and to
        # write into the consumer's env/config.
        print(
            "kow binding: wire the consumer now — add this line to the "
            f"calling app's env:\n  export {args.name}='{minted}'\n"
            "kow binding: the daemon picks the note up on its next reload.",
            file=sys.stderr,
        )
    return 0


def register_binding_subparser(parent_subparsers: argparse._SubParsersAction) -> None:
    binding_p = parent_subparsers.add_parser(
        "binding",
        help="Generate a paste-ready binding note/annotation for a secret.",
        description=(
            "Author the per-secret binding metadata deterministically. The note is "
            "validated through the daemon's own parser before it is printed, so it "
            "always carries the mandatory marker, the {secret} token, and a valid host."
        ),
    )
    binding_sub = binding_p.add_subparsers(dest="binding_cmd")
    new_p = binding_sub.add_parser(
        "new",
        help="Print the binding note (BWS) or annotation command (GSM) to paste.",
        description=(
            "Build and validate a binding, then print the exact artifact to paste "
            "into the secret's BWS Notes field (default) or run for a GSM annotation. "
            "Prints nothing and exits non-zero if the binding would not parse."
        ),
    )
    new_p.add_argument(
        "--host",
        action="append",
        required=True,
        metavar="HOST",
        help="Destination hostname the credential is sent to. Repeat for multi-host.",
    )
    new_p.add_argument(
        "--header",
        default="Authorization",
        help="HTTP header to inject into (default: Authorization).",
    )
    new_p.add_argument(
        "--format",
        default="Bearer {secret}",
        help='Header value template; MUST contain {secret} (default: "Bearer {secret}").',
    )
    new_p.add_argument(
        "--methods",
        default=None,
        help="Comma-separated HTTP methods to scope the binding to (default: all).",
    )
    new_p.add_argument(
        "--paths",
        default=None,
        help="Comma-separated URL path globs to scope the binding to (default: all).",
    )
    new_p.add_argument(
        "--name",
        default="SECRET",
        help="Secret name — used for the GSM command and the {secret} token rewrite.",
    )
    new_p.add_argument(
        "--backend",
        choices=("bws", "gsm"),
        default="bws",
        help="Output style: bws notes block (default) or gsm gcloud command.",
    )
    new_p.add_argument(
        "--no-placeholder",
        action="store_true",
        help=(
            "Do not mint a stored placeholder into the note; the daemon then "
            "derives one from the install salt (legacy flow — the consumer "
            "must discover it via `kow env` on the daemon host)."
        ),
    )
