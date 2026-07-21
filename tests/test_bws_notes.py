"""BWS-notes binding parser + exception table (ADR-0011 items 2 & 4).

The note in a BWS secret's ``notes`` field is a flat top-level YAML blob.
``host`` is the only required field; everything else defaults. The parser
returns one of three outcomes:

  * ``NoBinding``      — empty/missing note, or note with no ``host``.
                         Distinct audit reason ``no_binding_in_notes``.
  * ``InvalidBinding`` — malformed YAML, wrong shape, typo'd key, bad
                         value. Audit reason ``invalid_binding_metadata``,
                         carries a precise human diagnostic. FAIL CLOSED.
  * ``ParsedBinding``  — a validated SecretSpec-ready dict.

Validation reuses config.py's BindingSpec/HeaderInjector (host
normalization, method/path rules, extra=forbid) — the parser does NOT
fork validation.
"""

from __future__ import annotations

from agent_vault_proxy.notes_binding import (
    EXCEPTION_TABLE,
    InvalidBinding,
    NoBinding,
    ParsedBinding,
    parse_notes_binding,
)

_PH = "foo_PLACEHOLDER_01HXY1234567890"


# --------------------------------------------------------------------------
# No-binding outcomes (distinct from malformed)
# --------------------------------------------------------------------------


def test_empty_note_is_no_binding() -> None:
    result = parse_notes_binding(secret_name="FOO", placeholder=_PH, note=None)
    assert isinstance(result, NoBinding)


def test_empty_string_note_is_no_binding() -> None:
    result = parse_notes_binding(secret_name="FOO", placeholder=_PH, note="")
    assert isinstance(result, NoBinding)


def test_whitespace_note_is_no_binding() -> None:
    result = parse_notes_binding(secret_name="FOO", placeholder=_PH, note="   \n  ")
    assert isinstance(result, NoBinding)


def test_note_without_host_is_no_binding_not_malformed() -> None:
    """A well-formed YAML mapping that simply omits ``host`` has no binding;
    it is NOT malformed. This is the audit distinction the ADR amendment
    requires (no_binding_in_notes vs invalid_binding_metadata)."""
    result = parse_notes_binding(
        secret_name="FOO", placeholder=_PH, note="# avp-binding\nformat: 'Bearer {secret}'"
    )
    assert isinstance(result, NoBinding)


# --------------------------------------------------------------------------
# Minimal happy path — host only -> bare Bearer default
# --------------------------------------------------------------------------


def test_minimal_host_only_yields_bearer_default() -> None:
    result = parse_notes_binding(
        secret_name="FOO", placeholder=_PH, note="# avp-binding\nhost: api.example.com"
    )
    assert isinstance(result, ParsedBinding)
    spec = result.spec
    assert spec.placeholder == _PH
    assert spec.inject.type == "header"
    assert spec.inject.header == "Authorization"
    assert spec.inject.format == f"Bearer {{{result.secret_name}}}"
    assert [b.host for b in spec.bindings] == ["api.example.com"]
    # host-only -> no method/path scope (any)
    assert spec.bindings[0].methods is None
    assert spec.bindings[0].paths is None


def test_secret_token_is_rewritten_to_entry_name() -> None:
    """The note uses the generic {secret} token; the parser rewrites it to
    {<secret_name>} so config.py's per-entry placeholder invariant holds."""
    result = parse_notes_binding(
        secret_name="MYKEY", placeholder=_PH, note="# avp-binding\nhost: api.example.com"
    )
    assert isinstance(result, ParsedBinding)
    assert "{MYKEY}" in result.spec.inject.format


# --------------------------------------------------------------------------
# Full Tier-2 overrides
# --------------------------------------------------------------------------


def test_full_overrides_applied() -> None:
    note = """
# avp-binding
host: api.example.com
header: X-Api-Key
format: "Token {secret}"
methods: [GET, POST]
paths: ["/v1/**"]
"""
    result = parse_notes_binding(secret_name="FOO", placeholder=_PH, note=note)
    assert isinstance(result, ParsedBinding)
    spec = result.spec
    assert spec.inject.header == "X-Api-Key"
    assert spec.inject.format == "Token {FOO}"
    assert spec.bindings[0].methods == ["GET", "POST"]
    assert spec.bindings[0].paths == ["/v1/**"]


# --------------------------------------------------------------------------
# Malformed -> InvalidBinding, fail closed, precise diagnostic
# --------------------------------------------------------------------------


def test_malformed_yaml_is_invalid() -> None:
    result = parse_notes_binding(
        secret_name="FOO", placeholder=_PH, note="# avp-binding\nhost: [unclosed"
    )
    assert isinstance(result, InvalidBinding)
    assert result.diagnostic  # non-empty human message


def test_non_mapping_yaml_is_invalid() -> None:
    """A scalar or list at top level is not a binding mapping."""
    result = parse_notes_binding(
        secret_name="FOO", placeholder=_PH, note="# avp-binding\n- just a list item"
    )
    assert isinstance(result, InvalidBinding)


def test_unknown_key_is_invalid() -> None:
    """extra=forbid: a typo'd key (e.g. 'hosts' for 'host') must fail closed,
    not silently produce an unscoped binding."""
    note = "# avp-binding\nhost: api.example.com\nmethdos: [GET]"
    result = parse_notes_binding(secret_name="FOO", placeholder=_PH, note=note)
    assert isinstance(result, InvalidBinding)
    assert "methdos" in result.diagnostic or "extra" in result.diagnostic.lower()


def test_bad_method_is_invalid() -> None:
    note = "# avp-binding\nhost: api.example.com\nmethods: [FETCH]"
    result = parse_notes_binding(secret_name="FOO", placeholder=_PH, note=note)
    assert isinstance(result, InvalidBinding)


def test_overbroad_wildcard_host_is_invalid() -> None:
    result = parse_notes_binding(
        secret_name="FOO", placeholder=_PH, note="# avp-binding\nhost: '*.com'"
    )
    assert isinstance(result, InvalidBinding)


def test_bad_path_is_invalid() -> None:
    note = '# avp-binding\nhost: api.example.com\npaths: ["v1/no-leading-slash"]'
    result = parse_notes_binding(secret_name="FOO", placeholder=_PH, note=note)
    assert isinstance(result, InvalidBinding)


def test_host_not_a_string_is_invalid() -> None:
    result = parse_notes_binding(
        secret_name="FOO", placeholder=_PH, note="# avp-binding\nhost: [a, b]"
    )
    assert isinstance(result, InvalidBinding)


# --------------------------------------------------------------------------
# Exception table (item 4)
# --------------------------------------------------------------------------


def test_exception_table_has_required_rows() -> None:
    for host in (
        "api.anthropic.com",
        "api.openai.com",
        "api.github.com",
        "api.stripe.com",
        "api.notion.com",
        "api.linear.app",
    ):
        assert host in EXCEPTION_TABLE, f"{host} missing from exception table"


def test_anthropic_row_uses_x_api_key_and_companion_version() -> None:
    result = parse_notes_binding(
        secret_name="FOO", placeholder=_PH, note="# avp-binding\nhost: api.anthropic.com"
    )
    assert isinstance(result, ParsedBinding)
    spec = result.spec
    assert spec.inject.header == "x-api-key"
    assert spec.inject.format == "{FOO}"  # raw value, no Bearer
    assert result.companion_headers == {"anthropic-version": "2023-06-01"}
    # default scope POST /v1/**
    assert spec.bindings[0].methods == ["POST"]
    assert spec.bindings[0].paths == ["/v1/**"]


def test_notion_row_companion_version() -> None:
    result = parse_notes_binding(
        secret_name="FOO", placeholder=_PH, note="# avp-binding\nhost: api.notion.com"
    )
    assert isinstance(result, ParsedBinding)
    assert result.companion_headers == {"Notion-Version": "2022-06-28"}


def test_linear_row_raw_authorization_no_bearer() -> None:
    result = parse_notes_binding(
        secret_name="FOO", placeholder=_PH, note="# avp-binding\nhost: api.linear.app"
    )
    assert isinstance(result, ParsedBinding)
    assert result.spec.inject.header == "Authorization"
    assert result.spec.inject.format == "{FOO}"  # raw, no Bearer


def test_openai_row_bearer_post_v1() -> None:
    result = parse_notes_binding(
        secret_name="FOO", placeholder=_PH, note="# avp-binding\nhost: api.openai.com"
    )
    assert isinstance(result, ParsedBinding)
    assert result.spec.inject.format == "{FOO}".replace("{FOO}", "Bearer {FOO}")
    assert result.spec.bindings[0].methods == ["POST"]
    assert result.spec.bindings[0].paths == ["/v1/**"]


def test_github_default_scope_is_read_only_get() -> None:
    """The worked example: GitHub default scope is GET-read-only across the
    documented read paths. No POST, no /gists, no write paths."""
    result = parse_notes_binding(
        secret_name="FOO", placeholder=_PH, note="# avp-binding\nhost: api.github.com"
    )
    assert isinstance(result, ParsedBinding)
    binding = result.spec.bindings[0]
    assert binding.methods == ["GET"]
    assert binding.paths == ["/repos/**", "/user", "/users/**", "/orgs/**", "/search/**"]
    # POST /gists must NOT be in scope under the default
    assert not binding.matches_scope("POST", "/gists")
    # A normal read IS in scope
    assert binding.matches_scope("GET", "/repos/owner/repo")


def test_github_explicit_override_re_enables_writes() -> None:
    """A user who needs writes opts in explicitly via methods/paths; the
    explicit note overrides the exception-table default scope."""
    note = '# avp-binding\nhost: api.github.com\nmethods: [POST]\npaths: ["/gists"]'
    result = parse_notes_binding(secret_name="FOO", placeholder=_PH, note=note)
    assert isinstance(result, ParsedBinding)
    binding = result.spec.bindings[0]
    assert binding.matches_scope("POST", "/gists")


def test_explicit_header_overrides_exception_table() -> None:
    """Precedence: explicit note field > exception table. A user who sets
    header: on an anthropic host gets their header, not x-api-key."""
    note = "# avp-binding\nhost: api.anthropic.com\nheader: X-Custom"
    result = parse_notes_binding(secret_name="FOO", placeholder=_PH, note=note)
    assert isinstance(result, ParsedBinding)
    assert result.spec.inject.header == "X-Custom"


def test_unknown_host_falls_back_to_bearer_default() -> None:
    result = parse_notes_binding(
        secret_name="FOO", placeholder=_PH, note="# avp-binding\nhost: api.unknown-saas.example"
    )
    assert isinstance(result, ParsedBinding)
    assert result.spec.inject.header == "Authorization"
    assert result.spec.inject.format == "Bearer {FOO}"
    # bare default: no scope narrowing
    assert result.spec.bindings[0].methods is None
    assert result.spec.bindings[0].paths is None
    assert result.companion_headers == {}


def test_non_string_yaml_key_is_invalid_not_crash() -> None:
    # YAML permits non-string keys (`1: x`); the unknown-key diagnostic must
    # str()-coerce before sorting, else sorting a mixed int/str set raises
    # TypeError and escapes the parser instead of recording invalid metadata.
    result = parse_notes_binding(
        secret_name="FOO", placeholder=_PH, note="# avp-binding\n1: x\nhost: api.example.com"
    )
    assert isinstance(result, InvalidBinding)
    assert "unknown note key" in result.diagnostic.lower()
