"""BindingsResolver — two sources, one precedence (ADR-0011 item 3).

The resolver merges binding policy from two sources into a single
{secret_name: SecretSpec} map, tagging each spec with its origin
("bws_notes" | "file"). Precedence: BWS-notes WINS over file for the
same placeholder/secret. Both sources go through the SAME structural
validation (config.py's SecretSpec/BindingSpec) — they differ only in
where the YAML comes from.

The file source reuses the existing bindings.yaml Config. The BWS-notes
source builds specs from each secret's note via parse_notes_binding.
"""

from __future__ import annotations

from kow.bindings_resolver import (
    BindingsResolver,
    FileSource,
    NotesSource,
)

_PH_A = "aaa_PLACEHOLDER_01HXY1234567890"
_PH_B = "bbb_PLACEHOLDER_01HXY1234567890"


# --------------------------------------------------------------------------
# BWS-notes source
# --------------------------------------------------------------------------


def test_bws_notes_source_builds_specs_from_notes() -> None:
    # name -> note map drives which secrets the source considers.
    src = NotesSource(
        placeholders={"ANTHROPIC": _PH_A},
        notes={"ANTHROPIC": "# avp-binding\nhost: api.anthropic.com"},
    )
    specs = src.resolve()
    assert "ANTHROPIC" in specs
    spec, source, _companion = specs["ANTHROPIC"]
    assert source == "bws_notes"
    assert spec.inject.header == "x-api-key"


def test_bws_notes_source_skips_secrets_with_no_binding() -> None:
    src = NotesSource(
        placeholders={"FOO": _PH_A},
        notes={"FOO": ""},  # empty -> NoBinding
    )
    assert src.resolve() == {}


def test_bws_notes_source_skips_malformed_but_records_diagnostic() -> None:
    """A malformed note yields no binding (fail closed) AND a recorded
    diagnostic the operator can inspect — never a silent unscoped binding."""
    src = NotesSource(
        placeholders={"FOO": _PH_A},
        notes={"FOO": "# avp-binding\nhost: [unclosed"},
    )
    assert src.resolve() == {}
    assert "FOO" in src.invalid
    assert src.invalid["FOO"]  # non-empty diagnostic
    assert "FOO" not in src.no_binding  # malformed != no-binding


def test_bws_notes_source_tracks_no_binding_distinctly() -> None:
    """A note with no host is no-binding, tracked separately from malformed so
    the two audit reasons (no_binding_in_notes vs invalid_binding_metadata)
    stay distinct."""
    src = NotesSource(
        placeholders={"EMPTY": _PH_A, "NOHOST": _PH_B},
        notes={"EMPTY": "", "NOHOST": "# avp-binding\nformat: 'Bearer {secret}'"},
    )
    assert src.resolve() == {}
    assert src.no_binding == {"EMPTY", "NOHOST"}
    assert src.invalid == {}


# --------------------------------------------------------------------------
# File source
# --------------------------------------------------------------------------


def _file_config(tmp_path, placeholder: str, host: str) -> str:
    yaml = f"""
version: 1
secrets:
  FOO:
    placeholder: "{placeholder}"
    inject:
      header: "Authorization"
      format: "Bearer {{FOO}}"
    bindings:
      - host: "{host}"
audit:
  path: /tmp/x.jsonl
"""
    p = tmp_path / "bindings.yaml"
    p.write_text(yaml)
    return str(p)


def test_file_source_yields_file_tagged_specs(tmp_path) -> None:
    from kow.config import load_config

    cfg = load_config(_file_config(tmp_path, _PH_A, "api.example.com"))
    src = FileSource(config=cfg)
    specs = src.resolve()
    assert "FOO" in specs
    spec, source, _companion = specs["FOO"]
    assert source == "file"
    assert spec.bindings[0].host == "api.example.com"


# --------------------------------------------------------------------------
# Precedence: BWS-notes wins over file for the same secret
# --------------------------------------------------------------------------


def test_bws_notes_wins_over_file_for_same_secret(tmp_path) -> None:
    from kow.config import load_config

    cfg = load_config(_file_config(tmp_path, _PH_A, "file-host.example.com"))
    file_src = FileSource(config=cfg)
    notes_src = NotesSource(
        placeholders={"FOO": _PH_A},
        notes={"FOO": "# avp-binding\nhost: notes-host.example.com"},
    )
    resolver = BindingsResolver(sources=[notes_src, file_src])
    merged = resolver.resolve()
    spec, source, _companion = merged["FOO"]
    assert source == "bws_notes"
    assert spec.bindings[0].host == "notes-host.example.com"


def test_file_used_when_no_notes_binding(tmp_path) -> None:
    """If a secret has a file binding but no (or empty) BWS note, the file
    binding is used — the file is the escape hatch, not dead weight."""
    from kow.config import load_config

    cfg = load_config(_file_config(tmp_path, _PH_A, "file-host.example.com"))
    file_src = FileSource(config=cfg)
    notes_src = NotesSource(
        placeholders={"FOO": _PH_A},
        notes={"FOO": ""},  # no binding in notes
    )
    resolver = BindingsResolver(sources=[notes_src, file_src])
    merged = resolver.resolve()
    spec, source, _companion = merged["FOO"]
    assert source == "file"
    assert spec.bindings[0].host == "file-host.example.com"


def test_invalid_notes_exclude_same_name_file_binding(tmp_path) -> None:
    """A malformed note terminal-denies the secret name; the file source may
    not revive it under the stale file binding."""
    from kow.config import load_config

    cfg = load_config(_file_config(tmp_path, _PH_A, "file-host.example.com"))
    file_src = FileSource(config=cfg)
    notes_src = NotesSource(
        placeholders={"FOO": _PH_A},
        notes={"FOO": "# avp-binding\nhost: [unclosed"},
    )
    merged = BindingsResolver(sources=[notes_src, file_src]).resolve()
    assert "FOO" not in merged


def test_both_sources_share_validation(tmp_path) -> None:
    """Structural validation is identical regardless of source: a host-only
    note produces a SecretSpec whose BindingSpec.matches_scope behaves the
    same as a file-loaded one."""
    notes_src = NotesSource(
        placeholders={"FOO": _PH_A},
        notes={"FOO": "# avp-binding\nhost: api.example.com\nmethods: [GET]"},
    )
    merged = BindingsResolver(sources=[notes_src]).resolve()
    spec, _src, _companion = merged["FOO"]
    binding = spec.bindings[0]
    assert binding.matches_scope("GET", "/anything")
    assert not binding.matches_scope("POST", "/anything")
