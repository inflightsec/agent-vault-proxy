"""Parse a BWS secret's ``notes`` field into a binding spec (ADR-0011 items 2 & 4).

The note is a flat top-level YAML blob. ``host`` is the only required
field; everything else defaults. The substitution token in the note is
the generic ``{secret}`` (the note has no separate name key); the parser
rewrites it to ``{<secret_name>}`` so config.py's per-entry placeholder
invariant holds.

Three outcomes (a small tagged union), so the caller can audit each
distinctly per the ADR amendment:

  * :class:`NoBinding`      — empty/missing note, or a well-formed mapping
                              with no ``host``. NOT malformed. Audit reason
                              ``no_binding_in_notes``.
  * :class:`InvalidBinding` — malformed YAML, wrong shape, unknown key,
                              bad value. FAIL CLOSED. Audit reason
                              ``invalid_binding_metadata`` + diagnostic.
  * :class:`ParsedBinding`  — a validated, file-parity SecretSpec plus any
                              companion headers from the exception table.

Validation is NOT forked: the built dict is fed through config.py's
``SecretSpec`` (which runs HeaderInjector + BindingSpec validators — host
normalization, method/path rules, extra=forbid). A note that fails those
validators surfaces as InvalidBinding, exactly like the file path rejects
a bad bindings.yaml entry.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import yaml
from pydantic import ValidationError

from agent_vault_proxy.config import SecretSpec

# Generic substitution token in a note (vs the file path's {SECRET_NAME}).
# Not a credential — it's the literal placeholder marker the operator types.
_NOTE_SECRET_TOKEN = "{secret}"  # noqa: S105  # nosec B105 — substitution token, not a secret

# Flat note keys we accept. A key outside this set is a typo and fails
# closed (mirrors config.py's extra="forbid" for bindings.yaml). The note
# parser owns this list because the note schema is flat/defaulted, unlike
# the nested file schema — but the VALUES still go through config.py
# validators, so semantics stay identical across sources.
_ALLOWED_NOTE_KEYS = {"host", "header", "format", "methods", "paths"}

_DEFAULT_HEADER = "Authorization"
_DEFAULT_FORMAT = f"Bearer {_NOTE_SECRET_TOKEN}"


@dataclass(frozen=True)
class _ExceptionRow:
    """One host-keyed exception-table row. Supplies non-Bearer defaults for
    a known host. Any field left None falls back to the bare Bearer default
    (or, for scope, to no narrowing). ``companion_headers`` are extra static
    headers the integration requires alongside the credential header."""

    header: str = _DEFAULT_HEADER
    # format uses the generic {secret} token; rewritten per-secret later.
    format: str = _DEFAULT_FORMAT
    companion_headers: dict[str, str] = field(default_factory=dict)
    default_methods: list[str] | None = None
    default_paths: list[str] | None = None


# Bundled exception table (ADR-0011 amendment table, verbatim). Keyed on the
# host the human typed — NEVER inferred from key bytes. Default scopes ship
# TIGHT: the GitHub row is the worked example (a PAT bound to api.github.com
# with no scope could POST /gists and exfiltrate to a public gist, so the
# default is GET-read-only across documented read paths; writes require an
# explicit methods/paths override in the note).
EXCEPTION_TABLE: dict[str, _ExceptionRow] = {
    "api.anthropic.com": _ExceptionRow(
        header="x-api-key",
        format=_NOTE_SECRET_TOKEN,  # raw value, no Bearer
        companion_headers={"anthropic-version": "2023-06-01"},
        default_methods=["POST"],
        default_paths=["/v1/**"],
    ),
    "api.openai.com": _ExceptionRow(  # Bearer default
        default_methods=["POST"],
        default_paths=["/v1/**"],
    ),
    "api.github.com": _ExceptionRow(
        # Bearer default; GET read-only scope — NO POST, NO /gists, no writes.
        default_methods=["GET"],
        default_paths=["/repos/**", "/user", "/users/**", "/orgs/**", "/search/**"],
    ),
    "api.stripe.com": _ExceptionRow(  # Bearer default; Stripe also accepts Basic
        default_methods=["POST"],
        default_paths=["/v1/**"],
    ),
    "api.notion.com": _ExceptionRow(  # Bearer default
        companion_headers={"Notion-Version": "2022-06-28"},
        default_methods=["POST", "PATCH"],
        default_paths=["/v1/**"],
    ),
    "api.linear.app": _ExceptionRow(
        header=_DEFAULT_HEADER,
        format=_NOTE_SECRET_TOKEN,  # raw Authorization: {secret}, no Bearer
        default_methods=["POST"],
        default_paths=["/graphql"],
    ),
}


@dataclass(frozen=True)
class NoBinding:
    """The note carries no binding (empty / missing / no host). Fail-closed
    by omission, but distinguished from malformed in the audit log."""

    secret_name: str


@dataclass(frozen=True)
class InvalidBinding:
    """The note is malformed — fail closed, with a precise human diagnostic
    (ADR diagnostic-UX requirement)."""

    secret_name: str
    diagnostic: str


@dataclass(frozen=True)
class ParsedBinding:
    """A validated binding built from a note."""

    secret_name: str
    spec: SecretSpec
    companion_headers: dict[str, str]


def _rewrite_token(fmt: str, secret_name: str) -> str:
    """Rewrite the generic ``{secret}`` token to ``{<secret_name>}`` so the
    SecretSpec satisfies config.py's per-entry format invariant. Only the
    exact ``{secret}`` token is rewritten; an operator who hand-wrote
    ``{secret}`` in the note for some other reason still maps to the value
    (that IS the substitution token by spec), and any other ``{...}`` is
    left untouched — config.py's HeaderInjector validator will reject a
    format that ends up with no matching placeholder."""
    return fmt.replace(_NOTE_SECRET_TOKEN, "{" + secret_name + "}")


def _load_note_mapping(secret_name: str, note: str) -> dict | NoBinding | InvalidBinding:
    """YAML-load + shape/key checks. Returns the raw mapping on success, or
    the terminal NoBinding/InvalidBinding outcome. Split from
    parse_notes_binding to keep each function under the complexity gate."""
    try:
        raw = yaml.safe_load(note)
    except yaml.YAMLError as e:
        return InvalidBinding(
            secret_name,
            f"note is not valid YAML: {type(e).__name__}. "
            "Expected a flat mapping like `host: api.example.com`.",
        )
    if raw is None:
        # e.g. a note that is only a YAML comment.
        return NoBinding(secret_name)
    if not isinstance(raw, dict):
        return InvalidBinding(
            secret_name,
            f"note must be a YAML mapping (got {type(raw).__name__}). "
            "Expected flat keys like `host:`, `header:`, `format:`.",
        )
    # Unknown key -> fail closed (mirror extra="forbid"). Catch typos like
    # `hosts:` / `methdos:` before they become a silent unscoped binding.
    unknown = set(raw) - _ALLOWED_NOTE_KEYS
    if unknown:
        return InvalidBinding(
            secret_name,
            f"unknown note key(s) {sorted(unknown)}; allowed keys: {sorted(_ALLOWED_NOTE_KEYS)}.",
        )
    return raw


def parse_notes_binding(
    *,
    secret_name: str,
    placeholder: str,
    note: str | None,
) -> NoBinding | InvalidBinding | ParsedBinding:
    """Parse one secret's note into a binding outcome.

    ``placeholder`` is the env-side placeholder the daemon assigned to this
    secret (from the placeholder map); it's stamped into the SecretSpec so
    the addon's placeholder matching works identically to the file path.
    """
    # Empty / whitespace-only / absent -> no binding (NOT malformed).
    if note is None or not note.strip():
        return NoBinding(secret_name)

    loaded = _load_note_mapping(secret_name, note)
    if isinstance(loaded, NoBinding | InvalidBinding):
        return loaded
    raw = loaded

    host = raw.get("host")
    if host is None:
        # Well-formed mapping with no host => no binding, not malformed.
        return NoBinding(secret_name)
    if not isinstance(host, str) or not host.strip():
        return InvalidBinding(
            secret_name,
            "`host` must be a non-empty string.",
        )

    # Exception-table row for the typed host (default Bearer when absent).
    # Host is matched case-insensitively against the table; config.py
    # lowercases the binding host downstream anyway.
    row = EXCEPTION_TABLE.get(host.strip().lower(), _ExceptionRow())

    # Precedence: explicit note field > exception table > bare Bearer default.
    header = raw.get("header", row.header)
    fmt = raw.get("format", row.format)

    # Scope: explicit note methods/paths override the table's default scope.
    # If the note omits BOTH and there's no table default, scope is "any"
    # (the bare-Bearer unknown-host case).
    methods = raw.get("methods", row.default_methods)
    paths = raw.get("paths", row.default_paths)

    if not isinstance(fmt, str):
        return InvalidBinding(secret_name, "`format` must be a string.")
    if not isinstance(header, str):
        return InvalidBinding(secret_name, "`header` must be a string.")

    rewritten_format = _rewrite_token(fmt, secret_name)

    binding: dict[str, object] = {"host": host}
    if methods is not None:
        binding["methods"] = methods
    if paths is not None:
        binding["paths"] = paths

    spec_dict = {
        "placeholder": placeholder,
        "inject": {"type": "header", "header": header, "format": rewritten_format},
        "bindings": [binding],
    }

    try:
        spec = SecretSpec.model_validate(spec_dict)
    except ValidationError as e:
        # Surface a tight diagnostic. pydantic's message carries the field +
        # reason; we prefix with the secret name so an operator can locate it.
        return InvalidBinding(
            secret_name,
            f"note failed binding validation: {_first_error(e)}",
        )

    return ParsedBinding(secret_name, spec, dict(row.companion_headers))


def _first_error(e: ValidationError) -> str:
    """Compact one-line diagnostic from a pydantic ValidationError. The full
    error is multi-line; operators want the first concrete cause."""
    errors = e.errors()
    if not errors:
        return str(e)
    first = errors[0]
    loc = ".".join(str(p) for p in first.get("loc", ()))
    msg = first.get("msg", "invalid")
    return f"{loc}: {msg}" if loc else msg
