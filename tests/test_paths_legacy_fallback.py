"""kow paths are canonical; pre-rename installs keep working (ADR-0045)."""

from __future__ import annotations

from pathlib import Path

import pytest

from kow import _paths
from kow.cli.setup import _legacy_install_present, default_paths


def test_legacy_of_swaps_only_the_kow_segment() -> None:
    assert _paths.legacy_of("/etc/kow") == Path("/etc/agent-vault-proxy")
    assert _paths.legacy_of("/var/lib/kow") == Path("/var/lib/agent-vault-proxy")
    assert _paths.legacy_of(Path("/usr/local/etc/kow")) == Path("/usr/local/etc/agent-vault-proxy")


def test_resolve_prefers_kow_when_it_exists(tmp_path) -> None:
    new = tmp_path / "kow"
    new.mkdir()
    _paths.legacy_of(new).mkdir()
    assert _paths.resolve(new) == new


def test_resolve_falls_back_to_legacy(tmp_path) -> None:
    new = tmp_path / "kow"
    legacy = _paths.legacy_of(new)
    legacy.mkdir()
    assert _paths.resolve(new) == legacy


def test_resolve_returns_kow_when_neither_exists(tmp_path) -> None:
    new = tmp_path / "kow"
    assert _paths.resolve(new) == new


def test_exists_never_raises_on_unreadable_parent(tmp_path) -> None:
    """0750 install dirs make exists() raise for a non-service user. These
    resolvers run at import time, so a raise would crash the CLI outright."""
    parent = tmp_path / "locked"
    parent.mkdir()
    (parent / "kow").mkdir()
    parent.chmod(0o000)
    try:
        assert _paths.exists(parent / "kow") is False
        assert _paths.resolve(parent / "kow") == parent / "kow"
    finally:
        parent.chmod(0o755)


@pytest.mark.parametrize("os_name", ["linux", "macos"])
def test_default_paths_is_pure_and_defaults_to_kow(os_name: str) -> None:
    """The planner must not probe the host — same inputs, same layout."""
    paths = default_paths(os_name, None)
    assert "/kow" in paths.confdir
    assert "agent-vault-proxy" not in paths.confdir
    assert paths == default_paths(os_name, None)


@pytest.mark.parametrize("os_name", ["linux", "macos"])
def test_default_paths_legacy_returns_the_old_layout(os_name: str) -> None:
    paths = default_paths(os_name, None, legacy=True)
    assert "agent-vault-proxy" in paths.confdir
    assert paths.audit_path.endswith("agent-vault-proxy/audit.jsonl")


def test_default_paths_prefix_is_always_literal() -> None:
    """A staging prefix is never resolved against the real filesystem."""
    paths = default_paths("linux", "/tmp/stage")
    assert paths.confdir == "/tmp/stage/etc/kow"


def test_legacy_install_present_is_false_when_kow_exists(monkeypatch, tmp_path) -> None:
    new, old = tmp_path / "kow", tmp_path / "agent-vault-proxy"
    new.mkdir()
    old.mkdir()
    monkeypatch.setattr(_paths, "LINUX_CONFDIR", new)
    assert _legacy_install_present("linux") is False


def test_legacy_install_present_is_true_when_only_legacy_exists(monkeypatch, tmp_path) -> None:
    new, old = tmp_path / "kow", tmp_path / "agent-vault-proxy"
    old.mkdir()
    monkeypatch.setattr(_paths, "LINUX_CONFDIR", new)
    assert _legacy_install_present("linux") is True


def test_service_identifiers_name_kow() -> None:
    assert _paths.LINUX_SERVICE == "kow.service"
    assert _paths.MACOS_PLIST_LABEL == "io.inflightsec.kow"


def test_service_users_default_to_kow() -> None:
    from kow.cli.setup import default_service_user

    assert default_service_user("linux") == "kow"
    assert default_service_user("macos") == "_kow"


def test_service_users_adopt_the_legacy_account_on_an_existing_install() -> None:
    """Renaming the account on an adopted install would orphan the ownership of
    every file already on disk."""
    from kow.cli.setup import default_service_user

    assert default_service_user("linux", legacy=True) == "avp"
    assert default_service_user("macos", legacy=True) == "_avp"
