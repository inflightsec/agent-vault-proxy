"""Static-file secrets backend.

Reads `{name: value}` pairs from a YAML file on disk. Intended for
development, integration testing, and the docker-e2e harness. NOT
intended for production: the file is plaintext and the runtime emits a
clear warning to stderr + the addon logger when this backend is
selected. Keep your production deployments on a real vault adapter
(BWS today; 1Password / HashiCorp Vault / Doppler in the future).

File format::

    secrets:
      OPENAI_API_KEY: "sk-real-test-value"
      ANTHROPIC_API_KEY: "sk-ant-real-test-value"

Permissions: the backend refuses to read a file that is world-readable
(other-bit set). Hardens against shipping a test secrets file into a
container layer or a misconfigured volume.
"""

from __future__ import annotations

import logging
import os
import stat
import sys
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict

_log = logging.getLogger("kow.backends.static")


class StaticSecretsConfig(BaseModel):
    """`backend.config` schema for `type: static`."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    type: Literal["static"] = "static"
    path: str


class StaticSecretsBackend:
    """File-backed `SecretsBackend`. Reads on first fetch, caches in
    memory. Calling `flush_name_map()` re-reads on the next fetch."""

    def __init__(
        self,
        config: StaticSecretsConfig | None = None,
        *,
        secrets: dict[str, str] | None = None,
    ) -> None:
        # Two construction paths:
        #   1. Production-style: StaticSecretsBackend(config=StaticSecretsConfig(path=...))
        #   2. Tests: StaticSecretsBackend(secrets={"NAME": "value"})
        self._config = config
        self._secrets: dict[str, str] | None = secrets
        self._warned_in_use = False

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}>"

    def fetch(self, name: str, ctx: Any = None) -> str:
        from kow.backends import SecretNotFoundError

        self._maybe_warn_in_use()
        secrets = self._load_secrets()
        if name not in secrets:
            raise SecretNotFoundError(f"secret {name!r} not in static file")
        return secrets[name]

    def list_secret_names(self) -> list[str]:
        """Return every secret name in the static file (drives ``avp env``
        in dev/e2e). Reuses the same load+validate path as fetch()."""
        return list(self._load_secrets().keys())

    def flush_name_map(self) -> None:
        """Invalidate the in-memory cache. Next fetch re-reads the file."""
        if self._config is not None:
            self._secrets = None

    def _maybe_warn_in_use(self) -> None:
        if self._warned_in_use:
            return
        self._warned_in_use = True
        path = Path(self._config.path) if self._config is not None else None
        if path is not None and _file_is_safe(path):
            _log.info("static backend in use at %s", path)
            return
        msg = (
            "static secrets backend is in use — this reads plaintext "
            "secrets from a file and is intended for development, "
            "integration testing, and the docker-e2e harness ONLY. "
            "Use a vault-backed backend (bws, …) for production."
        )
        _log.warning(msg)
        print(f"[agent-vault-proxy] WARNING: {msg}", file=sys.stderr)

    def _load_secrets(self) -> dict[str, str]:
        if self._secrets is not None:
            return self._secrets
        from kow.backends import BackendUnavailableError

        if self._config is None:
            raise BackendUnavailableError(
                "static backend constructed without config and without inline secrets"
            )
        path = Path(self._config.path)
        try:
            stat = path.stat()
        except FileNotFoundError as e:
            raise BackendUnavailableError(
                f"static secrets file not found: {self._config.path}"
            ) from e
        except OSError as e:
            raise BackendUnavailableError(
                f"static secrets file unreadable: {type(e).__name__}"
            ) from None
        # Refuse world-readable files. Catches the "test secrets accidentally
        # 0644 in a shared container layer" footgun.
        if stat.st_mode & 0o004:
            raise BackendUnavailableError(
                f"static secrets file {self._config.path!r} is world-readable "
                f"(mode {oct(stat.st_mode & 0o777)}); chmod 0640 or 0600 to "
                "block other-bit reads before the backend will read it"
            )
        try:
            text = path.read_text()
        except OSError as e:
            # PermissionError (e.g., docker bind-mounted file owned by a
            # host UID the container can't read), file disappeared between
            # stat() and read(), etc. Without wrapping, this bubbles up as
            # an uncaught exception in the addon and the request is
            # forwarded unmodified — placeholder leaks to upstream.
            raise BackendUnavailableError(
                f"static secrets file unreadable: {type(e).__name__}"
            ) from None
        try:
            raw = yaml.safe_load(text)
        except yaml.YAMLError as e:
            raise BackendUnavailableError(
                f"static secrets file malformed: {type(e).__name__}"
            ) from None
        if not isinstance(raw, dict) or "secrets" not in raw:
            raise BackendUnavailableError(
                f"static secrets file {self._config.path!r} missing top-level 'secrets:' map"
            )
        secrets_raw = raw["secrets"]
        if not isinstance(secrets_raw, dict):
            raise BackendUnavailableError("'secrets:' must be a mapping of name → value")
        # Coerce values to str so YAML autoparsing (e.g., bare 12345)
        # doesn't surface as int and break the addon's header-substitution.
        self._secrets = {str(k): str(v) for k, v in secrets_raw.items()}
        return self._secrets


def _file_is_safe(path: Path) -> bool:
    """True iff path is a regular file (not a symlink), owner-only 0600,
    inside an owner-only 0700 non-symlink parent dir. Uses lstat so a
    symlinked path is rejected outright — a symlink whose target happens
    to satisfy the modes is not a safe configured path."""
    try:
        st = path.lstat()
        dst = path.parent.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode) or stat.S_ISLNK(dst.st_mode):
        return False
    if not stat.S_ISREG(st.st_mode) or not stat.S_ISDIR(dst.st_mode):
        return False
    euid = os.geteuid()
    file_mode = stat.S_IMODE(st.st_mode)
    dir_mode = stat.S_IMODE(dst.st_mode)
    return st.st_uid == euid and dst.st_uid == euid and file_mode == 0o600 and dir_mode == 0o700


def _register() -> None:
    from kow.backends import register_backend

    register_backend("static", StaticSecretsBackend, StaticSecretsConfig)


_register()
