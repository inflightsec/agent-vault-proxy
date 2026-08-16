"""Startup security preflight checks.

Each check returns a list of warning strings (possibly empty). The addon
runs `run_preflight(config)` from `running()` — once, before serving
traffic and BEFORE writing the proxy_restart audit event — and emits any
warnings to stderr + logger.warning so they appear in `docker compose
logs` AND `journalctl -u kow`.

By default these are NON-FATAL nags. The proxy still starts. The goal is
to surface "you're running in a way the docs flagged as a footgun" so
operators catch misconfigurations before they hit production.

Set `preflight.fail_on_warning: true` in bindings.yaml to convert any
preflight warning into a startup-abort — useful for hardened
environments that want a hard-fail rather than an advisory.

Checks are scoped to the documented happy paths (docs/install-systemd.md
+ docs/docker.md); a quiet preflight on those paths is a feature — we
don't want to train operators to ignore the output.

Known limitations (documented rather than fixed — ):

- Container detection uses /.dockerenv, /run/.containerenv, and cgroup
  substring markers. cgroup v2 sparse paths and exotic runtimes may not
  match; bare-metal hosts running dockerd may match the cgroup heuristic
  even though they aren't IN a container. The two stub-file checks cover
  Docker + Podman, which is most of the real world.
- The audit-log append-only check silently fails open on missing
  `lsattr`, unsupported filesystems, or unreadable paths. The alternative
  (alarm-fatigue warnings when we can't check) was judged worse.
- The sensitive-host list is hardcoded and inherently incomplete.
  Operator threat models vary; the curated list catches the documented
  T-1.5 laundering vectors. Extend `_SENSITIVE_HOSTS_WITHOUT_SCOPE`
  locally if your bindings include other high-laundering-risk targets.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from kow.config import Config


# Hosts where a placeholder-laundering attack via the bound credential is
# realistic enough that we expect operators to scope explicitly. Not an
# exhaustive list — just the common ones we've documented as T-1.5
# laundering vectors in docs/architecture.md.
_SENSITIVE_HOSTS_WITHOUT_SCOPE = {
    "api.github.com",
    "uploads.github.com",
    "gist.github.com",
    "api.dropboxapi.com",
    "content.dropboxapi.com",
    "api.box.com",
    "slack.com",
    "hooks.slack.com",
    "discord.com",
}

# HTTP verbs that almost always indicate write/laundering surface on the
# above hosts. A binding with methods=[POST] would otherwise
# silence the loose-binding warning even though POST is the actual
# exfil vector.
_WRITE_VERBS = {"POST", "PUT", "PATCH", "DELETE"}

# Module-level once-per-process flag. mitmproxy may call
# running() multiple times on reload; the banner should appear once per
# process to avoid spamming logs and burying the actual change signal.
_PREFLIGHT_EMITTED = False


class PreflightFailedError(RuntimeError):
    """Raised when strict mode (`preflight.fail_on_warning: true`) is
    enabled AND at least one preflight check fired a warning. Propagates
    out of the addon's running() hook so mitmproxy aborts startup."""


def _in_container() -> bool:
    """Detect if we're running inside an OCI container.

    Checks four indicators in order:
      - /.dockerenv (docker creates this stub file)
      - /run/.containerenv (podman equivalent)
      - cgroup v1 path contains docker/containerd/podman markers
      - cgroup v2 single-line ``0::/`` form — modern containers with a
        cgroup namespace see PID 1's cgroup as bare ``0::/``, while a
        bare-metal systemd host shows ``0::/init.scope`` (or similar
        non-empty path). Without this check the BWS-token and root-UID
        warnings silently muted on cgroup v2 runtimes that didn't drop
        a ``/.dockerenv`` stub — the reviewer-flagged gap.

    Returns False if /proc isn't mounted (non-Linux test runners)."""
    if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists():
        return True
    try:
        cgroup = Path("/proc/1/cgroup").read_text()
    except OSError:
        return False
    if any(marker in cgroup for marker in ("docker", "containerd", "podman", "kubepods")):
        return True
    return cgroup.strip() == "0::/"


def check_bws_token_via_env_in_container() -> list[str]:
    """BWS_ACCESS_TOKEN as env var is leaked to `docker inspect`, shell
    history, and any process that can read /proc/<pid>/environ. Inside a
    container, the docs (docs/docker.md) tell operators to bind-mount the
    token as a file instead. Warn if the env path is in use."""
    if not os.environ.get("BWS_ACCESS_TOKEN"):
        return []
    if not _in_container():
        return []
    return [
        "INSECURE: BWS_ACCESS_TOKEN is set as an environment variable inside "
        "a container — it will leak via `docker inspect` and /proc/<pid>/environ. "
        "Mount the token as a file at /etc/kow/bws-token and remove "
        "the env var. See docs/docker.md."
    ]


def _resolve_lsattr() -> str | None:
    """Find lsattr, preferring well-known absolute paths over PATH
    resolution. PATH-resolved binaries depend on whatever
    PATH the proxy process was started with — fine under our systemd
    unit and Dockerfile, but anyone running the daemon from a shell
    inherits operator PATH. Pinning the trusted locations first keeps
    the privileged check from being PATH-tampering surface."""
    for candidate in ("/usr/bin/lsattr", "/bin/lsattr", "/usr/sbin/lsattr"):
        if Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    return shutil.which("lsattr")


def check_audit_log_append_only(audit_path: str) -> list[str]:
    """The audit log SHOULD have `chattr +a` applied so a compromised
    proxy UID can't rewrite history. Warn if the file exists and lacks
    the attribute.

    A non-existent file is fine — AuditWriter creates it on first emit,
    and the operator's deploy recipe applies +a as a separate step
    (privileged, since the proxy itself drops CAP_LINUX_IMMUTABLE).
    """
    raw_path = Path(audit_path)
    if not raw_path.exists():
        return []
    # Resolve symlinks so an attacker can't swap a +a file with a symlink
    # to a mutable target and silence the check.
    try:
        path = raw_path.resolve(strict=True)
    except OSError:
        return []
    lsattr_path = _resolve_lsattr()
    if lsattr_path is None:
        # Non-Linux or minimal container without e2fsprogs — silently skip
        # (chattr semantics don't exist; warning would be noise).
        return []
    try:
        # lsattr_path is an absolute well-known location (or PATH fallback
        # via shutil.which). Arg is the realpath of validated audit_path.
        result = subprocess.run(  # noqa: S603
            [lsattr_path, "-d", str(path)],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return []
    if result.returncode != 0:
        # Filesystem doesn't support extended attributes (overlayfs in some
        # configurations, tmpfs, etc.) — chattr is a no-op there.
        return []
    # lsattr output: "----i-a-------e------- audit.jsonl" or similar.
    attrs = result.stdout.split(maxsplit=1)
    if not attrs or "a" not in attrs[0]:
        return [
            f"INSECURE: audit log {audit_path} is NOT append-only at the "
            "filesystem level (chattr +a missing). A compromise of the proxy UID "
            "could rewrite history. Apply `chattr +a` via a privileged helper — "
            "see docs/install-systemd.md / docs/docker.md."
        ]
    return []


def check_root_uid_in_container() -> list[str]:
    """Running as root (UID 0) inside a container is contrary to the
    documented Dockerfile (`USER 65532`). If we got here as root, either
    the image was rebuilt without USER or operator overrode it — both
    erase a layer of containment."""
    if not _in_container():
        return []
    if os.geteuid() != 0:
        return []
    return [
        "INSECURE: proxy is running as root (UID 0) inside a container. "
        "The shipped Dockerfile sets USER 65532; if you overrode it (--user 0, "
        "or a custom image), the agent-side blast radius is wider than designed. "
        "See docs/docker.md threat model."
    ]


def check_loose_bindings_on_sensitive_hosts(config: Config) -> list[str]:
    """T-1.5 laundering: hosts like api.github.com let a prompt-injected
    agent POST a public gist using the GitHub PAT. The defense is per-binding
    method/path scope (R2 mitigation in docs/architecture.md). Warn if a
    binding to a known-risky host has neither `methods` nor `paths` set,
    OR if its declared methods include any write verb (— the
    actual laundering surface is POST/PUT/PATCH/DELETE; a binding that
    declares those is scoped-but-still-permissive)."""
    msgs: list[str] = []
    for secret_name, spec in config.secrets.items():
        for binding in spec.bindings:
            # Case-fold for the lookup. BindingSpec doesn't
            # currently normalize host case at load — defensive here.
            if binding.host.lower() not in _SENSITIVE_HOSTS_WITHOUT_SCOPE:
                continue
            if binding.methods is None and binding.paths is None:
                msgs.append(
                    f"INSECURE: secret {secret_name!r} binds {binding.host!r} "
                    "without `methods` or `paths` scope. This host is a known "
                    "laundering target (T-1.5 — agent can POST exfil through "
                    "the bound credential). Add `methods: [GET]` (or stricter) "
                    "to the binding. See docs/architecture.md §R2."
                )
                continue
            if binding.methods is not None:
                permitted_writes = set(binding.methods) & _WRITE_VERBS
                if permitted_writes:
                    msgs.append(
                        f"INSECURE: secret {secret_name!r} binds {binding.host!r} "
                        f"with write methods {sorted(permitted_writes)} permitted. "
                        "This host is a known laundering target — write verbs "
                        "are the exfil surface (T-1.5). Restrict to "
                        "read-only verbs (GET/HEAD/OPTIONS) if possible."
                    )
    return msgs


def check_secret_prefix_boundary(config: Config) -> list[str]:
    """``secret_prefix`` is a plain ``startswith`` test with no notion of a
    namespace boundary, so a prefix ending on an alphanumeric admits sibling
    namespaces: ``app`` also matches ``application-prod``. Warn — the guard
    still works, it is just wider than the operator almost certainly meant.

    Advisory by design (same genre as the loose-binding warning): a wide prefix
    is a working config, not a broken one, and a running proxy should not die
    over it. Operators who want hard-fail set ``preflight.fail_on_warning``.
    """
    backend = getattr(config, "backend", None)
    if backend is None:
        return []
    prefix = getattr(backend._validated_config, "secret_prefix", None)
    if not prefix or not prefix[-1].isalnum():
        return []
    return [
        f"WIDE SCOPE: backend secret_prefix {prefix!r} does not end on a separator. "
        "Scoping is a prefix test, so it admits every name merely STARTING with "
        "those characters, not just that namespace — a prefix of 'app' also admits "
        f"'application-prod'. End it on a separator ({prefix + '/'!r} or "
        f"{prefix + '-'!r}) to bound it to one namespace."
    ]


def check_keychain_backend_isolation(config: Config) -> list[str]:
    """The keychain backend's boundary is the USER ACCOUNT, and operators
    reliably assume otherwise.

    kow is not a Developer-ID-signed application under PyPI/Homebrew
    distribution, so a keychain item's ACL identity is ``/usr/bin/security``
    itself: any process running as the same user can read the same items with
    one command. If the agent kow is protecting runs as that user, it can read
    the credential directly and the proxy has bought nothing — which is the
    exact opposite of what "my keys are in the Keychain" sounds like.

    Advisory, not fatal, and deliberately so: the backend is a legitimate
    single-user setup (encryption at rest, no plaintext on disk, a GUI view),
    and we cannot detect the agent's uid from in here. Operators who want a
    hard stop set ``preflight.fail_on_warning``.
    """
    backend = getattr(config, "backend", None)
    if backend is None or backend.type != "keychain":
        return []
    return [
        "KEYCHAIN SCOPE: the keychain backend's access boundary is the USER "
        "ACCOUNT, not kow. kow is not Developer-ID-signed under PyPI/Homebrew, "
        "so any process running as this user can read these items directly with "
        "`security find-generic-password` — including the agent this proxy "
        "exists to keep credentials away from. Run the agent under a SEPARATE "
        "macOS account (SandVault creates one) so per-user keychain encryption "
        "is a real wall; it reaches the proxy over loopback and still gets "
        "substitution. Same-account agent + keychain backend is not a supported "
        "isolation story. See docs/macos-isolation.md."
    ]


def run_preflight(config: Config) -> list[str]:
    """Aggregate all checks. Returns the combined warning list."""
    msgs: list[str] = []
    msgs.extend(check_bws_token_via_env_in_container())
    msgs.extend(check_audit_log_append_only(config.audit.path))
    msgs.extend(check_root_uid_in_container())
    msgs.extend(check_loose_bindings_on_sensitive_hosts(config))
    msgs.extend(check_secret_prefix_boundary(config))
    msgs.extend(check_keychain_backend_isolation(config))
    return msgs


def emit_preflight(config: Config, *, force: bool = False) -> None:
    """Call once at startup. Prints warnings to stderr + emits via logger
    so they appear in BOTH container logs and journalctl. Silent on the
    documented happy paths.

    Module-level once-per-process guard prevents banner spam
    on mitmproxy hot-reload — pass `force=True` to override (tests).

    If `config.preflight.fail_on_warning` is True AND there are warnings,
    raises PreflightFailedError after emitting so mitmproxy aborts
    startup before serving traffic."""
    global _PREFLIGHT_EMITTED
    if _PREFLIGHT_EMITTED and not force:
        return
    _PREFLIGHT_EMITTED = True

    msgs = run_preflight(config)
    if not msgs:
        return
    logger = logging.getLogger("kow.preflight")
    banner = "═" * 70
    print(banner, file=sys.stderr)
    print(f"kow: {len(msgs)} insecure-configuration warning(s):", file=sys.stderr)
    for m in msgs:
        print(f"  - {m}", file=sys.stderr)
        logger.warning(m)
    print(banner, file=sys.stderr)

    if getattr(config.preflight, "fail_on_warning", False):
        # Hardened-environment opt-in: convert advisory to
        # fatal. The exception propagates out of running() and mitmproxy
        # aborts startup before any traffic is served.
        raise PreflightFailedError(
            f"preflight.fail_on_warning is set and {len(msgs)} warning(s) "
            "fired; aborting startup. Address the warnings above or set "
            "preflight.fail_on_warning: false in bindings.yaml."
        )


def _reset_for_tests() -> None:
    """Reset the once-per-process flag so tests can re-trigger emission."""
    global _PREFLIGHT_EMITTED
    _PREFLIGHT_EMITTED = False
