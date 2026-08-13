"""Backward-compat guarantees for the agent-vault-proxy -> keys-on-the-wire rename.

The rename is deliberately byte-identical on the wire and on disk in 1.0.0
(ADR-0045): the minted placeholder prefix, config paths, and systemd unit are
UNCHANGED, so every existing deployment keeps injecting with zero migration. The
note/annotation marker now DEFAULTS to `# kow-binding` but still accepts the old
`# avp-binding` (both parse identically). What these lock:

  * minting/derivation still emit the `avp-PLACEHOLDER-` prefix — the on-wire
    contract the daemon matches by `spec.placeholder in value` (unchanged);
  * the deprecated `AVP_CONFDIR` env var still works, with a warning, and
    resolves the SAME salt path, so derivation is identical;
  * `KOW_CONFDIR` + `AVP_CONFDIR` set to DIFFERENT paths fails loud (never
    silently re-derives placeholders);
  * the deprecated `avp` CLI alias is still wired.

2.0.0 flips the minted prefix to `kow-` (with a migration) and drops the `avp`
CLI alias and `AVP_CONFDIR` fallback.
"""

from __future__ import annotations

import pathlib
import tomllib

import pytest

from kow.placeholders import (
    PLACEHOLDER_PREFIX,
    STORED_PLACEHOLDER_RE,
    InstallSaltError,
    _confdir_from_env,
    mint_placeholder,
)

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_minting_still_uses_avp_prefix() -> None:
    # The on-wire contract is unchanged in 1.0.0 — the daemon matches this exact
    # prefix, so an existing agent env file keeps injecting with zero migration.
    assert PLACEHOLDER_PREFIX == "avp-PLACEHOLDER-"
    ph = mint_placeholder()
    assert ph.startswith(PLACEHOLDER_PREFIX)
    assert STORED_PLACEHOLDER_RE.match(ph)


def test_kow_confdir_takes_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KOW_CONFDIR", "/same")
    monkeypatch.delenv("AVP_CONFDIR", raising=False)
    assert _confdir_from_env() == "/same"


def test_avp_confdir_still_works_but_warns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KOW_CONFDIR", raising=False)
    monkeypatch.setenv("AVP_CONFDIR", "/old")
    with pytest.warns(DeprecationWarning):
        assert _confdir_from_env() == "/old"


def test_both_confdir_same_path_is_fine(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KOW_CONFDIR", "/same")
    monkeypatch.setenv("AVP_CONFDIR", "/same")
    assert _confdir_from_env() == "/same"


def test_both_confdir_same_dir_trailing_slash_does_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # /etc/kow and /etc/kow/ are the SAME directory — must not trip the guard.
    monkeypatch.setenv("KOW_CONFDIR", "/etc/kow")
    monkeypatch.setenv("AVP_CONFDIR", "/etc/kow/")
    assert _confdir_from_env() == "/etc/kow"


def test_both_confdir_different_paths_fails_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    # Silently preferring one would re-derive every placeholder and brick injection.
    monkeypatch.setenv("KOW_CONFDIR", "/new")
    monkeypatch.setenv("AVP_CONFDIR", "/old")
    with pytest.raises(InstallSaltError):
        _confdir_from_env()


def test_no_confdir_env_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KOW_CONFDIR", raising=False)
    monkeypatch.delenv("AVP_CONFDIR", raising=False)
    assert _confdir_from_env() is None


def test_deprecated_cli_aliases_still_wired() -> None:
    scripts = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text())["project"]["scripts"]
    # canonical
    assert scripts["kow"] == "kow.cli.main:main"
    assert scripts["keys-on-the-wire"] == "kow.__main__:main"
    # deprecated aliases (removed in 2.0.0)
    assert scripts["avp"] == "kow.cli.main:main"
    assert scripts["agent-vault-proxy"] == "kow.__main__:main"


def test_kow_binding_marker_parses_as_binding() -> None:
    """`# kow-binding` (the new default marker) selects a binding."""
    from kow.notes_binding import ParsedBinding, parse_notes_binding

    result = parse_notes_binding(
        secret_name="SOME_KEY",
        placeholder="avp-PLACEHOLDER-a2b3c4d5e6f7g2h3j4k5m6n7p",
        note="# kow-binding\nhost: api.example.com\n",
    )
    assert isinstance(result, ParsedBinding)


def test_avp_binding_marker_still_parses_as_binding() -> None:
    """`# avp-binding` (the deprecated alias) still selects a binding (back-compat)."""
    from kow.notes_binding import ParsedBinding, parse_notes_binding

    result = parse_notes_binding(
        secret_name="SOME_KEY",
        placeholder="avp-PLACEHOLDER-a2b3c4d5e6f7g2h3j4k5m6n7p",
        note="# avp-binding\nhost: api.example.com\n",
    )
    assert isinstance(result, ParsedBinding)


def test_gsm_reads_both_binding_annotation_keys() -> None:
    """GSM reads the canonical `kow-binding` annotation and the `avp-binding` alias."""
    from kow.backends.gsm import _read_binding_annotation

    assert _read_binding_annotation({"kow-binding": "api.example.com"}) == "api.example.com"
    assert _read_binding_annotation({"avp-binding": "api.example.com"}) == "api.example.com"
    assert _read_binding_annotation({"other": "x"}) is None
    assert _read_binding_annotation(None) is None
