"""Tests for `avp binding new` — the deterministic binding-note generator.

The load-bearing guarantee: whatever the tool prints MUST parse back through
the daemon's own `parse_notes_binding` into a valid `ParsedBinding`. That
round-trip is the smoke test — it proves the generated artifact is a binding
the daemon will actually accept (marker present, `{secret}` token, valid host),
which is exactly what an LLM authoring the note free-hand gets wrong.
"""

from __future__ import annotations

from agent_vault_proxy.cli.main import main
from agent_vault_proxy.notes_binding import (
    NOTES_MARKER,
    ParsedBinding,
    parse_notes_binding,
)

_PH = "avp-PLACEHOLDER-test-0000000000"


def _run(argv, capsys):
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _roundtrip(note: str, name: str = "SECRET"):
    return parse_notes_binding(secret_name=name, placeholder=_PH, note=note)


def test_default_bearer_note_shape(capsys):
    code, out, _ = _run(["binding", "new", "--host", "api.stripe.com"], capsys)
    assert code == 0
    assert out.splitlines()[0] == NOTES_MARKER  # marker is first line, always
    assert "host: api.stripe.com" in out
    assert "header: Authorization" in out
    assert 'format: "Bearer {secret}"' in out


def test_emitted_note_roundtrips_to_valid_binding(capsys):
    # THE smoke: the printed note must parse back to a real binding.
    code, out, _ = _run(
        ["binding", "new", "--host", "api.stripe.com", "--name", "STRIPE_API_KEY"],
        capsys,
    )
    assert code == 0
    result = _roundtrip(out, name="STRIPE_API_KEY")
    assert isinstance(result, ParsedBinding)
    assert result.spec.bindings[0].host == "api.stripe.com"


def test_format_without_secret_token_is_rejected(capsys):
    code, _out, err = _run(
        ["binding", "new", "--host", "api.stripe.com", "--format", "Bearer nope"],
        capsys,
    )
    assert code != 0
    assert "{secret}" in err


def test_malformed_host_is_refused(capsys):
    # A URL pasted where a hostname belongs is a realistic mistake; the tool
    # self-validates against the parser and must refuse, not emit junk.
    code, _out, err = _run(["binding", "new", "--host", "http://api.x.com"], capsys)
    assert code != 0
    assert "invalid" in err.lower()  # the parser's diagnostic surfaced


def test_token_scheme_custom_format_roundtrips(capsys):
    code, out, _ = _run(
        ["binding", "new", "--host", "api.github.com", "--format", "token {secret}"],
        capsys,
    )
    assert code == 0
    assert 'format: "token {secret}"' in out
    assert isinstance(_roundtrip(out), ParsedBinding)


def test_custom_header_roundtrips(capsys):
    code, out, _ = _run(
        [
            "binding",
            "new",
            "--host",
            "api.acme.com",
            "--header",
            "X-API-Key",
            "--format",
            "{secret}",
        ],
        capsys,
    )
    assert code == 0
    assert "header: X-API-Key" in out
    assert isinstance(_roundtrip(out), ParsedBinding)


def test_scope_methods_paths_roundtrip(capsys):
    code, out, _ = _run(
        [
            "binding",
            "new",
            "--host",
            "api.example.com",
            "--methods",
            "GET,POST",
            "--paths",
            "/v1/**",
        ],
        capsys,
    )
    assert code == 0
    assert "methods:" in out
    assert "paths:" in out
    assert isinstance(_roundtrip(out), ParsedBinding)


def test_multihost_roundtrips(capsys):
    code, out, _ = _run(
        ["binding", "new", "--host", "api.example.com", "--host", "files.example.com"],
        capsys,
    )
    assert code == 0
    result = _roundtrip(out)
    assert isinstance(result, ParsedBinding)
    hosts = {b.host for b in result.spec.bindings}
    assert hosts == {"api.example.com", "files.example.com"}


def test_gsm_backend_emits_gcloud_command_with_marker(capsys):
    code, out, _ = _run(
        ["binding", "new", "--host", "api.example.com", "--name", "X_KEY", "--backend", "gsm"],
        capsys,
    )
    assert code == 0
    assert "gcloud secrets update X_KEY" in out
    assert "avp-binding=" in out
    assert NOTES_MARKER in out


def test_binding_with_no_subcommand_errors(capsys):
    code, _out, err = _run(["binding"], capsys)
    assert code != 0
    assert err
