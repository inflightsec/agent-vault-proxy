"""Canonical kow filesystem paths, with pre-rename fallbacks.

``kow`` is canonical everywhere. An install laid down before ADR-0045 still
lives under ``agent-vault-proxy``, so :func:`resolve` prefers the kow path and
falls back to the legacy one only when the kow path is absent and the legacy
one exists. New installs get kow; existing installs keep working. The legacy
fallback drops in 2.0.0, alongside ``AVP_CONFDIR`` and the ``avp-`` markers.
"""

from __future__ import annotations

from pathlib import Path

LEGACY_NAME = "agent-vault-proxy"
_LEGACY = LEGACY_NAME

# Linux (systemd) layout.
LINUX_CONFDIR = Path("/etc/kow")
LINUX_STATEDIR = Path("/var/lib/kow")
LINUX_LOGDIR = Path("/var/log/kow")

# macOS (launchd) layout, under /usr/local.
MACOS_CONFDIR = Path("/usr/local/etc/kow")
MACOS_STATEDIR = Path("/usr/local/var/lib/kow")
MACOS_LOGDIR = Path("/usr/local/var/log/kow")

# Service identifiers written by `kow setup`.
LINUX_SERVICE = "kow.service"
LINUX_SERVICE_UNIT = "kow"

# Service accounts. macOS convention prefixes system users with an underscore.
# The pre-rename users are adopted when an existing install is detected — a
# rename would orphan the ownership of every file already on disk.
LINUX_SERVICE_USER = "kow"
MACOS_SERVICE_USER = "_kow"
LEGACY_LINUX_SERVICE_USER = "avp"
LEGACY_MACOS_SERVICE_USER = "_avp"
MACOS_PLIST_LABEL = "io.inflightsec.kow"


def legacy_of(path: Path | str) -> Path:
    """The pre-rename twin of ``path`` (``kow`` segment → ``agent-vault-proxy``)."""
    return Path(str(path).replace("/kow", f"/{_LEGACY}"))


def exists(path: Path) -> bool:
    """``Path.exists()`` that cannot raise.

    The install dirs are 0750 root:kow, so a probe from a non-service user
    raises PermissionError on the parent rather than returning False. These
    resolvers run at import time — an unreadable directory must not crash the
    CLI. Unreadable is treated as absent; the caller opens the path anyway and
    gets a real error at the point of use.
    """
    try:
        return path.exists()
    except OSError:
        return False


def resolve(path: Path | str) -> Path:
    """Prefer the kow path; fall back to the legacy path only if it is the one
    that exists. Returns the kow path when neither exists (fresh install)."""
    path = Path(path)
    if exists(path):
        return path
    legacy = legacy_of(path)
    return legacy if exists(legacy) else path


def default_config() -> Path:
    """Bindings file: kow path, else the pre-rename one, else the kow path."""
    linux = resolve(LINUX_CONFDIR / "bindings.yaml")
    if exists(linux):
        return linux
    return resolve(MACOS_CONFDIR / "bindings.yaml")
