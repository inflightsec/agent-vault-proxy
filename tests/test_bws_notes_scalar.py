"""Bare-hostname note shorthand (ADR-0018 §4 Tier 0).

A note that is just a host string (`api.openai.com`) parses as
`{host: <string>}`, so the GSM North-Star — add a secret, tag it with the
host, nothing else — needs no YAML. Mapping notes are unchanged.
"""

from __future__ import annotations

from agent_vault_proxy.notes_binding import (
    InvalidBinding,
    NoBinding,
    ParsedBinding,
    parse_notes_binding,
)

_PH = "sk-PLACEHOLDER-0123456789ABCDEF"


def test_bare_hostname_scalar_becomes_host_binding() -> None:
    r = parse_notes_binding(secret_name="OPENAI_API_KEY", placeholder=_PH, note="api.openai.com")
    assert isinstance(r, ParsedBinding)
    assert r.spec.bindings[0].host == "api.openai.com"


def test_blank_scalar_is_no_binding() -> None:
    r = parse_notes_binding(secret_name="X", placeholder=_PH, note="   ")
    assert isinstance(r, NoBinding)


def test_mapping_note_still_parses() -> None:
    r = parse_notes_binding(secret_name="X", placeholder=_PH, note="host: api.internal.acme.com")
    assert isinstance(r, ParsedBinding)
    assert r.spec.bindings[0].host == "api.internal.acme.com"


def test_non_string_scalar_is_invalid() -> None:
    # `12345` YAML-loads to an int — not a host string, not a mapping.
    r = parse_notes_binding(secret_name="X", placeholder=_PH, note="12345")
    assert isinstance(r, InvalidBinding)
