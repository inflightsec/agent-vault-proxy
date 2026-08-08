"""Runtime BWS-notes binding resolution (ADR-0011 item 3 activation).

``resolve_runtime_bindings`` is the daemon-side glue that turns "a BWS
backend + an install salt + a binding_source mode" into:

  * the resolved {secret_name: ResolvedSpec} map (merged per precedence),
  * the placeholder -> secret_name map for EVERY listed secret (so the
    request path can tell a no-binding/invalid placeholder from an
    unrelated string and fail closed with the right audit reason),
  * the no_binding and invalid sets (for the audit reason split).

It honours binding_source: file (no BWS listing at all), bws_notes (notes
only), both (notes win over file).
"""

from __future__ import annotations

from kow.placeholders import derive_placeholder
from kow.runtime_bindings import resolve_runtime_bindings

_SALT = b"\x05" * 32


class _FakeNotesListBackend:
    """Backend with list + fetch_with_meta for runtime resolution tests."""

    def __init__(self, secrets: dict[str, tuple[str, str | None]]) -> None:
        # name -> (value, note)
        self._secrets = secrets

    def list_secret_names(self) -> list[str]:
        return list(self._secrets)

    def fetch(self, name, ctx=None) -> str:
        return self._secrets[name][0]

    def fetch_with_meta(self, name, ctx=None) -> tuple[str, str | None]:
        return self._secrets[name]


def _load_file_config(tmp_path, secret_name: str, placeholder: str, host: str):
    from kow.config import load_config

    yaml = f"""
version: 1
secrets:
  {secret_name}:
    placeholder: "{placeholder}"
    inject:
      header: "Authorization"
      format: "Bearer {{{secret_name}}}"
    bindings:
      - host: "{host}"
audit:
  path: {tmp_path / "a.jsonl"}
binding_source: both
"""
    p = tmp_path / "bindings.yaml"
    p.write_text(yaml)
    return load_config(str(p))


def test_bws_notes_mode_builds_specs_and_placeholder_map() -> None:
    backend = _FakeNotesListBackend(
        {"ANTHROPIC": ("real-value", "# avp-binding\nhost: api.anthropic.com")}
    )
    resolved = resolve_runtime_bindings(
        backend=backend,
        binding_source="bws_notes",
        install_salt=_SALT,
        file_config=None,
    )
    ph = derive_placeholder("ANTHROPIC", _SALT)
    assert resolved.specs["ANTHROPIC"][1] == "bws_notes"
    # placeholder map covers the secret and points back at its name.
    assert resolved.placeholder_to_name[ph] == "ANTHROPIC"
    # The spec's placeholder is the derived one (so request matching works).
    spec = resolved.specs["ANTHROPIC"][0]
    assert spec.placeholder == ph


def test_no_binding_secret_recorded_and_in_placeholder_map() -> None:
    """A secret whose note has no host produces no spec, but its placeholder
    is still mapped (so a request carrying it fails closed with
    no_binding_in_notes, not a forward-as-unknown)."""
    backend = _FakeNotesListBackend({"FOO": ("v", "")})
    resolved = resolve_runtime_bindings(
        backend=backend,
        binding_source="bws_notes",
        install_salt=_SALT,
        file_config=None,
    )
    ph = derive_placeholder("FOO", _SALT)
    assert "FOO" not in resolved.specs
    assert resolved.placeholder_to_name[ph] == "FOO"
    assert "FOO" in resolved.no_binding
    assert "FOO" not in resolved.invalid


def test_invalid_binding_secret_recorded_distinctly() -> None:
    backend = _FakeNotesListBackend({"BAR": ("v", "# avp-binding\nhost: [unclosed")})
    resolved = resolve_runtime_bindings(
        backend=backend,
        binding_source="bws_notes",
        install_salt=_SALT,
        file_config=None,
    )
    ph = derive_placeholder("BAR", _SALT)
    assert "BAR" not in resolved.specs
    assert resolved.placeholder_to_name[ph] == "BAR"
    assert "BAR" in resolved.invalid
    assert "BAR" not in resolved.no_binding


def test_both_mode_notes_win_over_file(tmp_path) -> None:
    """In `both` mode a secret bound in BWS notes wins over the same-named
    file binding."""
    # File binding for ANTHROPIC -> file-host.
    file_ph = derive_placeholder("ANTHROPIC", _SALT)
    cfg = _load_file_config(tmp_path, "ANTHROPIC", file_ph, "file-host.example.com")
    backend = _FakeNotesListBackend(
        {"ANTHROPIC": ("v", "# avp-binding\nhost: notes-host.example.com")}
    )
    resolved = resolve_runtime_bindings(
        backend=backend,
        binding_source="both",
        install_salt=_SALT,
        file_config=cfg,
    )
    spec, source, _companion = resolved.specs["ANTHROPIC"]
    assert source == "bws_notes"
    assert spec.bindings[0].host == "notes-host.example.com"


def test_both_mode_file_used_when_no_note(tmp_path) -> None:
    file_ph = derive_placeholder("ANTHROPIC", _SALT)
    cfg = _load_file_config(tmp_path, "ANTHROPIC", file_ph, "file-host.example.com")
    backend = _FakeNotesListBackend({"ANTHROPIC": ("v", "")})  # no note binding
    resolved = resolve_runtime_bindings(
        backend=backend,
        binding_source="both",
        install_salt=_SALT,
        file_config=cfg,
    )
    spec, source, _companion = resolved.specs["ANTHROPIC"]
    assert source == "file"
    assert spec.bindings[0].host == "file-host.example.com"


def test_both_mode_file_only_binding_survives_alongside_noted(tmp_path) -> None:
    """Regression (2026-07-02 credential-drop): in `both` mode, a file-only
    binding (no BWS note) must STAY resolved even when OTHER secrets carry
    notes and even when the backend lists only the noted ones. The incident
    dropped every file-only binding once any secret had a note. This pins the
    merge core (`resolve_runtime_bindings`) as the union of file + notes."""
    noted_ph = derive_placeholder("NOTED", _SALT)
    fileonly_ph = derive_placeholder("FILEONLY", _SALT)
    yaml = f"""
version: 1
secrets:
  NOTED:
    placeholder: "{noted_ph}"
    inject:
      header: "Authorization"
      format: "Bearer {{NOTED}}"
    bindings:
      - host: "file-noted.example.com"
  FILEONLY:
    placeholder: "{fileonly_ph}"
    inject:
      header: "Authorization"
      format: "Bearer {{FILEONLY}}"
    bindings:
      - host: "file-only.example.com"
audit:
  path: {tmp_path / "a.jsonl"}
binding_source: both
"""
    from kow.config import load_config

    p = tmp_path / "bindings.yaml"
    p.write_text(yaml)
    cfg = load_config(str(p))

    class _ListsOnlyNoted(_FakeNotesListBackend):
        # Backend can fetch both but LISTS only NOTED — mirrors a machine
        # account that can see fewer secrets than the file references.
        def list_secret_names(self) -> list[str]:
            return ["NOTED"]

    backend = _ListsOnlyNoted(
        {"NOTED": ("v1", "# avp-binding\nhost: noted.example.com"), "FILEONLY": ("v2", "")}
    )
    resolved = resolve_runtime_bindings(
        backend=backend,
        binding_source="both",
        install_salt=_SALT,
        file_config=cfg,
    )
    assert "FILEONLY" in resolved.specs, "file-only binding was DROPPED in both mode (regression)"
    spec, source, _companion = resolved.specs["FILEONLY"]
    assert source == "file"
    assert spec.bindings[0].host == "file-only.example.com"
    assert "NOTED" in resolved.specs


def test_both_mode_invalid_note_excludes_same_name_file_binding(tmp_path) -> None:
    cfg = _load_file_config(
        tmp_path,
        "ANTHROPIC",
        derive_placeholder("ANTHROPIC", _SALT),
        "file-host.example.com",
    )
    backend = _FakeNotesListBackend({"ANTHROPIC": ("v", "# avp-binding\nhost: [unclosed")})
    resolved = resolve_runtime_bindings(
        backend=backend,
        binding_source="both",
        install_salt=_SALT,
        file_config=cfg,
    )
    assert "ANTHROPIC" not in resolved.specs
    assert "ANTHROPIC" in resolved.invalid


def test_collision_raises_hard(monkeypatch) -> None:
    """A derived-placeholder collision across the BWS secret set is a hard
    startup failure (never a silent coalesce)."""
    import kow.placeholders as pmod
    from kow.placeholders import PlaceholderCollisionError

    monkeypatch.setattr(pmod, "_derive_tail", lambda name, salt: "z" * 21)
    backend = _FakeNotesListBackend(
        {"A": ("v", "host: a.example.com"), "B": ("v", "host: b.example.com")}
    )
    import pytest

    with pytest.raises(PlaceholderCollisionError):
        resolve_runtime_bindings(
            backend=backend,
            binding_source="bws_notes",
            install_salt=_SALT,
            file_config=None,
        )
