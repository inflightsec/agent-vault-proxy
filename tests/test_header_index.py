"""The per-request header index must never drift from the config it serves.

A stale index is a silent mis-injection (a live secret stops matching, or a
removed one keeps matching), so these pin the rebuild points rather than the
speedup.
"""

from __future__ import annotations

from pathlib import Path

from kow.policy import build_header_index, find_header_placeholder_matches


def _get(headers: dict[str, str]):
    lowered = {k.lower(): v for k, v in headers.items()}
    return lambda name: lowered.get(name.lower())


def test_index_matches_the_unindexed_scan(tmp_path: Path) -> None:
    """The index is an accelerator only — identical answers, identical order."""
    from kow.config import load_config

    cfg = tmp_path / "b.yaml"
    cfg.write_text(f"""
version: 1
secrets:
  A_KEY:
    placeholder: "sk-PLACEHOLDER-aaaa1111bbbb2222cccc"
    inject: {{header: "Authorization", format: "Bearer {{A_KEY}}"}}
    bindings: [{{host: "api.a.example.com"}}]
  B_KEY:
    placeholder: "sk-PLACEHOLDER-dddd3333eeee4444ffff"
    inject: {{header: "X-Api-Key", format: "{{B_KEY}}"}}
    bindings: [{{host: "api.b.example.com"}}]
audit: {{path: {tmp_path / "a.jsonl"}}}
""")
    config = load_config(cfg)
    index = build_header_index(config)
    for headers in (
        {"Authorization": "Bearer sk-PLACEHOLDER-aaaa1111bbbb2222cccc"},
        {"X-Api-Key": "sk-PLACEHOLDER-dddd3333eeee4444ffff"},
        {"Authorization": "Bearer nothing-here"},
        {},
    ):
        get = _get(headers)
        assert find_header_placeholder_matches(config, get, header_index=index) == (
            find_header_placeholder_matches(config, get)
        )


def test_notes_refresh_rebuilds_the_index(tmp_path: Path) -> None:
    """ADR-0032 refresh adds a secret; the index must gain it in the same pass.

    The index is built at the publish point precisely because notes activation
    populates config AFTER the snapshot is created — and mutates the same Config
    object, so an identity check alone would not catch the drift.
    """
    from tests.test_notes_refresh import _HOST_B, _addon, _MutableNotesBackend

    backend = _MutableNotesBackend({"AAA": ("val-a", "# avp-binding\nhost: api.aaa-example.com")})
    addon, _audit = _addon(tmp_path, backend)

    def indexed_names() -> set[str]:
        return {entry[1] for entries in addon._header_index.values() for entry in entries}

    assert indexed_names() == {"AAA"}

    backend.add("BBB", "val-b", _HOST_B)
    addon.refresh_notes()

    assert "BBB" in addon.config.secrets
    assert indexed_names() == {"AAA", "BBB"}, "index went stale across a notes refresh"


def test_index_is_rebuilt_when_config_object_changes(tmp_path: Path) -> None:
    """A new Config must never be served by the previous config's index."""
    from kow.addon import AgentVaultProxyAddon
    from kow.config import load_config

    def write(secret: str, placeholder: str) -> Path:
        p = tmp_path / f"{secret}.yaml"
        p.write_text(f"""
version: 1
secrets:
  {secret}:
    placeholder: "{placeholder}"
    inject: {{header: "Authorization", format: "Bearer {{{secret}}}"}}
    bindings: [{{host: "api.example.com"}}]
audit: {{path: {tmp_path / "a.jsonl"}}}
""")
        return p

    addon = AgentVaultProxyAddon()
    first = load_config(write("FIRST", "sk-PLACEHOLDER-1111aaaa2222bbbb3333"))
    second = load_config(write("SECOND", "sk-PLACEHOLDER-4444cccc5555dddd6666"))

    idx1 = addon._index_for(first)
    assert set(idx1) == {"Authorization"}
    assert idx1["Authorization"][0][1] == "FIRST"

    idx2 = addon._index_for(second)
    assert idx2 is not idx1
    assert idx2["Authorization"][0][1] == "SECOND"


def test_ambiguity_survives_the_index(tmp_path: Path) -> None:
    """Two placeholders in one header must still produce TWO matches, so the
    caller refuses. The index must not collapse or reorder them."""
    from kow.config import load_config

    cfg = tmp_path / "b.yaml"
    cfg.write_text(f"""
version: 1
secrets:
  FIRST:
    placeholder: "sk-PLACEHOLDER-1111aaaa2222bbbb3333"
    inject: {{header: "Authorization", format: "Bearer {{FIRST}}"}}
    bindings: [{{host: "api.example.com"}}]
  SECOND:
    placeholder: "sk-PLACEHOLDER-4444cccc5555dddd6666"
    inject: {{header: "Authorization", format: "Bearer {{SECOND}}"}}
    bindings: [{{host: "api.example.com"}}]
audit: {{path: {tmp_path / "a.jsonl"}}}
""")
    config = load_config(cfg)
    get = _get(
        {
            "Authorization": "Bearer sk-PLACEHOLDER-1111aaaa2222bbbb3333 "
            "sk-PLACEHOLDER-4444cccc5555dddd6666"
        }
    )
    indexed = find_header_placeholder_matches(config, get, header_index=build_header_index(config))
    assert len(indexed) == 2
    assert [m[0] for m in indexed] == ["FIRST", "SECOND"]  # config declaration order
    assert indexed == find_header_placeholder_matches(config, get)
