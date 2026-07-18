"""Multi-host note bindings (ADR-0021, Increment 1).

`host` accepts a list of hostnames (or the `hosts:` alias); a list fans out to
one binding per host under a single injector, gated by the multi-host trust
invariant: the note must be self-describing (explicit `format` — no silent
bare-Bearer broadcast) and may not list a host that carries curated per-host
defaults (those bind in their own single-host note).
"""

from __future__ import annotations

from agent_vault_proxy.notes_binding import (
    InvalidBinding,
    ParsedBinding,
    parse_notes_binding,
)

_PH = "hf-PLACEHOLDER-0123456789ABCDEF"

# The HuggingFace trigger: one token, three hosts, plain Bearer, none curated.
_HF_NOTE = (
    "host:\n"
    "  - huggingface.co\n"
    "  - api-inference.huggingface.co\n"
    "  - datasets-server.huggingface.co\n"
    'format: "Bearer {secret}"\n'
)


def _hosts(r: ParsedBinding) -> list[str]:
    return [b.host for b in r.spec.bindings]


def test_multihost_fans_out_to_one_binding_per_host() -> None:
    r = parse_notes_binding(secret_name="HF_TOKEN", placeholder=_PH, note=_HF_NOTE)
    assert isinstance(r, ParsedBinding)
    assert _hosts(r) == [
        "huggingface.co",
        "api-inference.huggingface.co",
        "datasets-server.huggingface.co",
    ]
    # One injector, token rewritten from the generic {secret} to {HF_TOKEN}.
    assert r.spec.inject.format == "Bearer {HF_TOKEN}"
    # Multi-host never carries companion headers (curated hosts are rejected).
    assert r.companion_headers == {}


def test_hosts_alias_is_equivalent_to_host_list() -> None:
    note = _HF_NOTE.replace("host:", "hosts:", 1)
    r = parse_notes_binding(secret_name="HF_TOKEN", placeholder=_PH, note=note)
    assert isinstance(r, ParsedBinding)
    assert len(r.spec.bindings) == 3


def test_host_and_hosts_together_is_invalid() -> None:
    note = 'host: a.example.com\nhosts: [b.example.com]\nformat: "Bearer {secret}"\n'
    r = parse_notes_binding(secret_name="X", placeholder=_PH, note=note)
    assert isinstance(r, InvalidBinding)
    assert "either `host` or `hosts`" in r.diagnostic


def test_single_element_list_equals_scalar_path() -> None:
    # A one-host list must behave exactly like the scalar path: the exception
    # table applies, so no explicit format is required and api.openai.com gets
    # its curated POST /v1/** default.
    r = parse_notes_binding(
        secret_name="OPENAI_API_KEY", placeholder=_PH, note="host: [api.openai.com]"
    )
    assert isinstance(r, ParsedBinding)
    assert _hosts(r) == ["api.openai.com"]
    assert r.spec.bindings[0].methods == ["POST"]


def test_empty_list_is_invalid() -> None:
    r = parse_notes_binding(secret_name="X", placeholder=_PH, note="host: []")
    assert isinstance(r, InvalidBinding)
    assert "empty" in r.diagnostic


def test_blank_element_is_invalid() -> None:
    note = 'host:\n  - a.example.com\n  - "  "\nformat: "Bearer {secret}"\n'
    r = parse_notes_binding(secret_name="X", placeholder=_PH, note=note)
    assert isinstance(r, InvalidBinding)
    assert "non-empty string" in r.diagnostic


def test_non_string_element_is_invalid() -> None:
    note = 'host:\n  - a.example.com\n  - 12345\nformat: "Bearer {secret}"\n'
    r = parse_notes_binding(secret_name="X", placeholder=_PH, note=note)
    assert isinstance(r, InvalidBinding)


def test_multihost_without_explicit_format_is_invalid() -> None:
    # Self-describing rule: no silent bare-Bearer broadcast across hosts.
    note = "host:\n  - a.example.com\n  - b.example.com\n"
    r = parse_notes_binding(secret_name="X", placeholder=_PH, note=note)
    assert isinstance(r, InvalidBinding)
    assert "explicit `format`" in r.diagnostic


def test_multihost_with_curated_host_is_invalid() -> None:
    # api.github.com carries a curated GET-only default; it may not be buried in
    # a multi-host note where that scope cannot be applied per-host.
    note = 'host:\n  - api.github.com\n  - api.example.com\nformat: "Bearer {secret}"\n'
    r = parse_notes_binding(secret_name="X", placeholder=_PH, note=note)
    assert isinstance(r, InvalidBinding)
    assert "api.github.com" in r.diagnostic
    assert "own note" in r.diagnostic


def test_multihost_scope_applies_to_every_host() -> None:
    note = (
        "host:\n"
        "  - a.example.com\n"
        "  - b.example.com\n"
        'format: "Bearer {secret}"\n'
        "methods: [GET]\n"
        "paths: [/v1/**]\n"
    )
    r = parse_notes_binding(secret_name="X", placeholder=_PH, note=note)
    assert isinstance(r, ParsedBinding)
    for b in r.spec.bindings:
        assert b.methods == ["GET"]
        assert b.paths == ["/v1/**"]


def test_case_variant_hosts_dedupe() -> None:
    note = (
        "host:\n"
        "  - HuggingFace.co\n"
        "  - huggingface.co\n"
        "  - api-inference.huggingface.co\n"
        'format: "Bearer {secret}"\n'
    )
    r = parse_notes_binding(secret_name="HF_TOKEN", placeholder=_PH, note=note)
    assert isinstance(r, ParsedBinding)
    assert _hosts(r) == ["huggingface.co", "api-inference.huggingface.co"]


def test_multihost_wrong_format_placeholder_is_invalid() -> None:
    # A foreign/typo placeholder would ship an unsubstituted literal header;
    # the note path must fail closed like the file path (Forge finding A).
    note = 'host:\n  - a.example.com\n  - b.example.com\nformat: "Bearer {OTHER}"\n'
    r = parse_notes_binding(secret_name="HF_TOKEN", placeholder=_PH, note=note)
    assert isinstance(r, InvalidBinding)
    assert "substitution token" in r.diagnostic


def test_scalar_wrong_format_placeholder_is_invalid() -> None:
    r = parse_notes_binding(
        secret_name="HF_TOKEN",
        placeholder=_PH,
        note='host: a.example.com\nformat: "Bearer {OTHER}"\n',
    )
    assert isinstance(r, InvalidBinding)
    assert "substitution token" in r.diagnostic


def test_multihost_format_without_placeholder_is_invalid() -> None:
    note = 'host:\n  - a.example.com\n  - b.example.com\nformat: "Bearer static"\n'
    r = parse_notes_binding(secret_name="HF_TOKEN", placeholder=_PH, note=note)
    assert isinstance(r, InvalidBinding)


def test_wildcard_element_in_multihost_is_invalid() -> None:
    # A `*.github.com` element supersets the curated api.github.com host and must
    # not ride along in a multi-host note (Forge finding B).
    note = 'host:\n  - "*.github.com"\n  - api.example.com\nformat: "Bearer {secret}"\n'
    r = parse_notes_binding(secret_name="X", placeholder=_PH, note=note)
    assert isinstance(r, InvalidBinding)
    assert "wildcard" in r.diagnostic


def test_dedupe_to_single_curated_host_applies_scalar_defaults() -> None:
    # A list that collapses to one curated host takes the scalar path, so the
    # curated GET-only default still applies (guard is not bypassed by dedup).
    note = "host:\n  - api.github.com\n  - API.GitHub.com\n"
    r = parse_notes_binding(secret_name="GH", placeholder=_PH, note=note)
    assert isinstance(r, ParsedBinding)
    assert _hosts(r) == ["api.github.com"]
    assert r.spec.bindings[0].methods == ["GET"]
