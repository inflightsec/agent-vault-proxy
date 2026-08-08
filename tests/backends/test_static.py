from __future__ import annotations

import logging
from pathlib import Path

import pytest

from kow.backends.static import (
    StaticSecretsBackend,
    StaticSecretsConfig,
    _file_is_safe,
)


def _write_secrets(path: Path, body: str, *, mode: int = 0o600) -> Path:
    path.write_text(body)
    path.chmod(mode)
    return path


def test_file_is_safe_returns_true_for_owner_only_0600_in_0700_parent(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    path = _write_secrets(tmp_path / "secrets.yaml", "secrets:\n  K: v\n", mode=0o600)

    assert _file_is_safe(path) is True


def test_file_is_safe_false_for_world_readable(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    path = _write_secrets(tmp_path / "secrets.yaml", "secrets:\n  K: v\n", mode=0o644)

    assert _file_is_safe(path) is False


def test_file_is_safe_false_for_loose_parent_dir(tmp_path: Path) -> None:
    tmp_path.chmod(0o755)
    path = _write_secrets(tmp_path / "secrets.yaml", "secrets:\n  K: v\n", mode=0o600)

    assert _file_is_safe(path) is False


def test_file_is_safe_false_for_missing_file(tmp_path: Path) -> None:
    assert _file_is_safe(tmp_path / "missing.yaml") is False


def test_warn_downgraded_to_info_when_safe(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tmp_path.chmod(0o700)
    path = _write_secrets(tmp_path / "secrets.yaml", "secrets:\n  K: v\n", mode=0o600)
    backend = StaticSecretsBackend(config=StaticSecretsConfig(type="static", path=str(path)))
    caplog.set_level(logging.INFO, logger="kow.backends.static")

    assert backend.fetch("K") == "v"

    assert capsys.readouterr().err == ""
    assert any(
        record.levelno == logging.INFO and "static backend in use at" in record.getMessage()
        for record in caplog.records
    )


def test_warn_stays_on_stderr_when_unsafe(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tmp_path.chmod(0o755)
    path = _write_secrets(tmp_path / "secrets.yaml", "secrets:\n  K: v\n", mode=0o600)
    backend = StaticSecretsBackend(config=StaticSecretsConfig(type="static", path=str(path)))

    assert backend.fetch("K") == "v"

    assert "static secrets backend is in use" in capsys.readouterr().err


def test_file_is_safe_rejects_symlink(tmp_path: Path) -> None:
    # A symlinked configured path is rejected outright, even when the target
    # happens to satisfy the modes — the link itself is the attack surface.
    tmp_path.chmod(0o700)
    real = _write_secrets(tmp_path / "real.yaml", "secrets: {}\n", mode=0o600)
    link = tmp_path / "secrets.yaml"
    link.symlink_to(real)
    assert _file_is_safe(link) is False


def test_file_is_safe_rejects_symlinked_parent(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir(mode=0o700)
    link_parent = tmp_path / "link"
    link_parent.symlink_to(real_parent)
    path = _write_secrets(link_parent / "secrets.yaml", "secrets: {}\n", mode=0o600)
    assert _file_is_safe(path) is False
