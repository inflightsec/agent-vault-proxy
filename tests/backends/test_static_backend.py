from __future__ import annotations

from pathlib import Path

import pytest

from kow.backends import SecretNotFoundError
from kow.backends.static import StaticSecretsBackend, StaticSecretsConfig


def _write_secrets(tmp_path: Path, body: str, *, mode: int = 0o600) -> Path:
    p = tmp_path / "secrets.yml"
    p.write_text(body)
    p.chmod(mode)
    return p


def test_fetch_returns_value(tmp_path: Path) -> None:
    p = _write_secrets(
        tmp_path,
        "secrets:\n  OPENAI_API_KEY: sk-real-value-1\n",
    )
    backend = StaticSecretsBackend(config=StaticSecretsConfig(type="static", path=str(p)))
    assert backend.fetch("OPENAI_API_KEY").reveal() == "sk-real-value-1"


def test_fetch_missing_name_raises(tmp_path: Path) -> None:
    p = _write_secrets(tmp_path, "secrets:\n  FOO: bar\n")
    backend = StaticSecretsBackend(config=StaticSecretsConfig(type="static", path=str(p)))
    with pytest.raises(SecretNotFoundError):
        backend.fetch("MISSING")


def test_fetch_inline_secrets_works() -> None:
    backend = StaticSecretsBackend(secrets={"K": "v"})
    assert backend.fetch("K").reveal() == "v"


def test_world_readable_file_rejected(tmp_path: Path) -> None:
    p = _write_secrets(tmp_path, "secrets:\n  K: v\n", mode=0o644)
    backend = StaticSecretsBackend(config=StaticSecretsConfig(type="static", path=str(p)))
    with pytest.raises(Exception, match="world-readable"):
        backend.fetch("K")


def test_missing_file_raises(tmp_path: Path) -> None:
    backend = StaticSecretsBackend(
        config=StaticSecretsConfig(type="static", path=str(tmp_path / "nope.yml"))
    )
    with pytest.raises(Exception, match="not found"):
        backend.fetch("K")


def test_malformed_yaml_rejected(tmp_path: Path) -> None:
    p = _write_secrets(tmp_path, "secrets: {unclosed\n")
    backend = StaticSecretsBackend(config=StaticSecretsConfig(type="static", path=str(p)))
    with pytest.raises(Exception, match="malformed"):
        backend.fetch("K")


def test_missing_secrets_key_rejected(tmp_path: Path) -> None:
    p = _write_secrets(tmp_path, "other_top_key: foo\n")
    backend = StaticSecretsBackend(config=StaticSecretsConfig(type="static", path=str(p)))
    with pytest.raises(Exception, match="missing top-level 'secrets:'"):
        backend.fetch("K")


def test_warning_logged_on_first_fetch(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The static backend must surface a clear in-use warning so an
    operator who selects it cannot miss that this isn't a production path.

    The downgrade-to-info path is exercised in tests/backends/test_static.py;
    here we widen the parent dir mode to the unsafe range so the canonical
    stderr WARNING is what fires."""
    tmp_path.chmod(0o755)
    p = _write_secrets(tmp_path, "secrets:\n  K: v\n")
    backend = StaticSecretsBackend(config=StaticSecretsConfig(type="static", path=str(p)))
    backend.fetch("K")
    captured = capsys.readouterr()
    assert "static secrets backend is in use" in captured.err
    assert "production" in captured.err


def test_warning_emitted_only_once(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    tmp_path.chmod(0o755)
    p = _write_secrets(tmp_path, "secrets:\n  K: v\n")
    backend = StaticSecretsBackend(config=StaticSecretsConfig(type="static", path=str(p)))
    backend.fetch("K")
    capsys.readouterr()  # drain
    backend.fetch("K")
    captured = capsys.readouterr()
    assert captured.err == ""


def test_values_coerced_to_str(tmp_path: Path) -> None:
    """YAML autoparses bare numbers; the backend must coerce to str so
    header substitution doesn't trip on a non-string value."""
    p = _write_secrets(tmp_path, "secrets:\n  PORT_TOKEN: 12345\n")
    backend = StaticSecretsBackend(config=StaticSecretsConfig(type="static", path=str(p)))
    assert backend.fetch("PORT_TOKEN").reveal() == "12345"


def test_unreadable_file_raises_backend_unavailable(tmp_path: Path) -> None:
    """Regression: docker-e2e harness 2026-05-30 surfaced a PermissionError
    on a bind-mounted secrets.yml owned by a host UID the container couldn't
    read. The previous implementation only stat()'d the file before reading,
    so the read-time OSError bubbled up as an uncaught exception in the
    addon — and the placeholder was silently forwarded to the upstream.
    Wrapping the read in BackendUnavailableError closes that path."""
    import os

    from kow.backends import BackendUnavailableError

    p = _write_secrets(tmp_path, "secrets:\n  K: v\n", mode=0o600)
    # Make the file unreadable by the current process. stat() will still
    # succeed (only needs parent-dir read); read_text() will fail.
    os.chmod(p, 0o200)  # write-only — the world-readable check (0o004) passes
    try:
        backend = StaticSecretsBackend(config=StaticSecretsConfig(type="static", path=str(p)))
        with pytest.raises(BackendUnavailableError, match="unreadable"):
            backend.fetch("K")
    finally:
        # Restore so pytest's tmp_path teardown can clean up.
        os.chmod(p, 0o600)
