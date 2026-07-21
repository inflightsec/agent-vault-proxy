"""Bare-hostname note shorthand (ADR-0018 §4 Tier 0).

A note that is just a host string (`api.openai.com`) parses as
`{host: <string>}`, so the GSM North-Star — add a secret, tag it with the
host, nothing else — needs no YAML. Mapping notes are unchanged.
"""

from __future__ import annotations

import logging

import pytest

from agent_vault_proxy.notes_binding import (
    InvalidBinding,
    NoBinding,
    ParsedBinding,
    parse_notes_binding,
)

_PH = "sk-PLACEHOLDER-0123456789ABCDEF"


def test_bare_hostname_scalar_becomes_host_binding() -> None:
    r = parse_notes_binding(
        secret_name="OPENAI_API_KEY", placeholder=_PH, note="# avp-binding\napi.openai.com"
    )
    assert isinstance(r, ParsedBinding)
    assert r.spec.bindings[0].host == "api.openai.com"


def test_blank_scalar_is_no_binding() -> None:
    r = parse_notes_binding(secret_name="X", placeholder=_PH, note="   ")
    assert isinstance(r, NoBinding)


def test_mapping_note_still_parses() -> None:
    r = parse_notes_binding(
        secret_name="X", placeholder=_PH, note="# avp-binding\nhost: api.internal.acme.com"
    )
    assert isinstance(r, ParsedBinding)
    assert r.spec.bindings[0].host == "api.internal.acme.com"


def test_non_string_scalar_is_invalid() -> None:
    # `12345` YAML-loads to an int — not a host string, not a mapping.
    r = parse_notes_binding(secret_name="X", placeholder=_PH, note="# avp-binding\n12345")
    assert isinstance(r, InvalidBinding)


# --- regression (2026-07-18): a free-text DESCRIPTION note must never be
# mistaken for a host. Real vault secrets carry human descriptions in their
# note field; under binding_source `both` (notes win per secret) a
# description-as-host silently shadows the real bindings.yaml host and the
# secret stops injecting. Discovered live: the whole fleet stopped injecting
# because ~20 secrets' description notes became garbage hosts. ---
@pytest.mark.parametrize(
    "note",
    [
        "HackerOne API identifier",
        "GCP project ID",
        "Sentry API token (scope unknown)",
        "AWS claude-pai IAM user. Scoped read-only infra + CC Athena.",
        "Google OAuth refresh token (never expires, Sheets write scope)",
        "identifier",  # single label, no dot — still not a host
        "some free text",
    ],
)
def test_description_note_is_no_binding_not_a_host(note: str) -> None:
    r = parse_notes_binding(secret_name="X", placeholder=_PH, note=note)
    assert isinstance(r, NoBinding), f"description {note!r} was mistaken for a host"


@pytest.mark.parametrize(
    "note",
    ["api.openai.com", "postman-echo.com", "dataminelab.atlassian.net"],
)
def test_real_hostname_shorthand_still_binds(note: str) -> None:
    r = parse_notes_binding(secret_name="X", placeholder=_PH, note=f"# avp-binding\n{note}")
    assert isinstance(r, ParsedBinding)
    assert r.spec.bindings[0].host == note


# --- ADR-0025 marker gate: binding intent is explicit. A marked note with a
# non-hostname body is an operator ERROR (fail LOUD), an unmarked host-shaped
# note is inert but self-diagnosing (warning), and a marker with no body is
# declared intent with missing content (fail LOUD). ---


def test_marked_description_is_invalid() -> None:
    # With the marker present, a free-text body is no longer an ignorable
    # description — it is a typo'd binding and must fail closed, loudly.
    r = parse_notes_binding(secret_name="X", placeholder=_PH, note="# avp-binding\nGCP project ID")
    assert isinstance(r, InvalidBinding)


def test_unmarked_host_shaped_note_warns_but_is_no_binding(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # No marker -> no binding, even for a perfectly host-shaped note; a
    # forgotten marker must be self-diagnosing via a logged warning.
    with caplog.at_level(logging.WARNING, logger="agent_vault_proxy.notes_binding"):
        r = parse_notes_binding(secret_name="X", placeholder=_PH, note="api.openai.com")
    assert isinstance(r, NoBinding)
    assert "marker" in caplog.text


def test_marker_only_note_is_invalid() -> None:
    # Marker with nothing after it: binding intent declared, content missing.
    r = parse_notes_binding(secret_name="X", placeholder=_PH, note="# avp-binding\n")
    assert isinstance(r, InvalidBinding)
    assert "no binding content" in r.diagnostic
