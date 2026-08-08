"""`binding_source` legacy-alias normalization (de-BWS-ify refactor).

`bws_notes` and `gsm_notes` are deprecated aliases for the single generic
`notes` mode; they normalize at config-load with a DeprecationWarning. The
per-spec audit provenance stays backend-typed (NOTES_SOURCE_LABEL), which is a
separate field and is unaffected.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kow.config import load_config


def _cfg(tmp_path: Path, value: str) -> Path:
    p = tmp_path / f"{value}.yaml"
    p.write_text(
        "version: 1\n"
        "secrets: {}\n"
        f"binding_source: {value}\n"
        f"audit:\n  path: {tmp_path / 'audit.jsonl'}\n"
        "backend:\n"
        "  type: static\n"
        "  config:\n"
        "    type: static\n"
        f"    path: {tmp_path / 'secrets.yaml'}\n"
    )
    return p


@pytest.mark.parametrize("legacy", ["bws_notes", "gsm_notes"])
def test_legacy_alias_normalizes_to_notes(tmp_path: Path, legacy: str) -> None:
    with pytest.warns(DeprecationWarning, match="deprecated alias for 'notes'"):
        cfg = load_config(_cfg(tmp_path, legacy))
    assert cfg.binding_source == "notes"


def test_notes_value_no_warning(tmp_path: Path, recwarn) -> None:
    cfg = load_config(_cfg(tmp_path, "notes"))
    assert cfg.binding_source == "notes"
    assert not [w for w in recwarn if issubclass(w.category, DeprecationWarning)]
