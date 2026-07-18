"""``avp doctor`` CA regression checks (ADR-0012 delta).

These are READ-ONLY health checks. ``avp doctor`` never mutates the trust
store, never touches the CA key — it only reports. Two checks ship here:

* :func:`check_ca_not_in_trust_store` — WARN if the AVP CA cert appears in
  any known OS/browser trust-store location. ADR-0012 makes "never add the
  AVP CA to the system store" a hard invariant; this is the regression
  guard. Matching is by the cert's base64 DER body (not filename), so a
  copy under any name is caught and an unrelated cert never false-positives.

* :func:`check_ca_key_perms` — WARN if the CA private key is group/other
  readable (must be 0600) or its confdir is looser than 0700, or it isn't
  owned by the running/service user. A same-UID-readable CA key is exactly
  the blast-radius ADR-0012 exists to prevent.

Both return a list of human-readable warning strings (empty == clean), the
same contract as :mod:`agent_vault_proxy._preflight`.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path

from agent_vault_proxy.config import build_backend, load_config

# Default CA locations under the systemd confdir (HOME=/var/lib/agent-vault-proxy).
# mitmproxy writes the CA on first proxied request to $HOME/.mitmproxy/.
_DEFAULT_CONFDIR = "/var/lib/agent-vault-proxy/.mitmproxy"
_CA_CERT_BASENAME = "mitmproxy-ca-cert.pem"  # public cert (world-readable OK)
_CA_KEY_BASENAME = "mitmproxy-ca.pem"  # PRIVATE key (must stay 0600)

# Known OS/browser trust-store locations to scan for a regressed CA. Linux
# system anchors + the common per-user NSS DB dirs. macOS keychains aren't
# flat files and aren't scanned here (a future check could shell out to
# `security`). This list is inherently incomplete; it covers the documented
# happy paths and locations an install script could plausibly write to.
DEFAULT_TRUST_STORE_PATHS = [
    "/etc/ssl/certs",
    "/etc/pki/ca-trust/source/anchors",
    "/usr/local/share/ca-certificates",
    "/etc/ca-certificates/trust-source/anchors",
]

# Match a PEM certificate's base64 DER body (between the BEGIN/END lines).
_PEM_BODY_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
    re.DOTALL,
)


def _normalized_der_bodies(text: str) -> set[str]:
    """Extract each certificate's base64 DER body from PEM ``text``, stripped
    of whitespace. The body uniquely identifies a cert regardless of the
    filename it's stored under or surrounding formatting."""
    bodies: set[str] = set()
    for m in _PEM_BODY_RE.finditer(text):
        body = re.sub(r"\s+", "", m.group(1))
        if body:
            bodies.add(body)
    return bodies


def _ca_cert_body(ca_cert_path: str) -> str | None:
    """The AVP CA cert's normalized DER body, or None if the cert file is
    absent/unreadable/not a PEM cert. A missing CA cert means the CA hasn't
    been generated yet — nothing to look for."""
    path = Path(ca_cert_path)
    try:
        text = path.read_text()
    except FileNotFoundError:
        return None
    except OSError:
        # PermissionError (e.g. running `avp doctor` as a non-service user
        # against the 0700 confdir), unreadable path, etc. Can't read the
        # CA -> can't compare it; skip rather than traceback.
        return None
    bodies = _normalized_der_bodies(text)
    # The AVP CA cert file holds exactly one certificate.
    return next(iter(bodies), None)


def check_ca_not_in_trust_store(
    ca_cert_path: str | None = None,
    *,
    trust_store_paths: list[str] | None = None,
) -> list[str]:
    """WARN if the AVP CA cert appears in any scanned trust-store location.

    Read-only. Scans each path (file or directory, recursively) for a
    certificate whose DER body matches the AVP CA. Unreadable files are
    skipped silently (a permission error scanning a system dir isn't a CA
    regression). Returns one warning per location the CA was found in.
    """
    cert_path = ca_cert_path or str(Path(_DEFAULT_CONFDIR) / _CA_CERT_BASENAME)
    target = _ca_cert_body(cert_path)
    if target is None:
        # CA not generated yet (or unreadable) — nothing to look for.
        return []

    paths = DEFAULT_TRUST_STORE_PATHS if trust_store_paths is None else trust_store_paths
    warnings: list[str] = []
    for store in paths:
        store_path = Path(store)
        if not store_path.exists():
            continue
        files = [store_path] if store_path.is_file() else _iter_files(store_path)
        for f in files:
            try:
                text = f.read_text(errors="ignore")
            except OSError:
                continue
            if target in _normalized_der_bodies(text):
                warnings.append(
                    f"INSECURE: the agent-vault-proxy CA cert appears in the trust "
                    f"store at {f}. ADR-0012 forbids adding the AVP CA to any OS/browser "
                    "trust store — same-UID malware could then mint certs for ANY host. "
                    "Remove it from the system store; trust the CA per-client via "
                    "NODE_EXTRA_CA_CERTS / SSL_CERT_FILE instead."
                )
    return warnings


def _iter_files(directory: Path) -> list[Path]:
    """All regular files under ``directory`` (one level deep is enough for
    the flat anchor dirs we scan, but rglob is cheap and catches nested
    NSS layouts). Symlink loops are avoided by skipping non-regular files."""
    out: list[Path] = []
    try:
        for p in directory.rglob("*"):
            if p.is_file():
                out.append(p)
    except OSError:
        pass
    return out


def check_ca_key_perms(ca_key_path: str | None = None) -> list[str]:
    """WARN if the CA private key isn't owner-only (0600) in a 0700 confdir,
    or isn't owned by the running user.

    Read-only. A non-existent key file is fine (mitmproxy generates the CA
    on first proxied request) — silent skip. Returns one warning per
    deviation found.
    """
    key_path = ca_key_path or str(Path(_DEFAULT_CONFDIR) / _CA_KEY_BASENAME)
    path = Path(key_path)

    warnings: list[str] = []
    try:
        st = path.stat()
    except FileNotFoundError:
        # CA key not generated yet — mitmproxy creates it on first proxied
        # request. Not an error; silent skip.
        return []
    except PermissionError:
        # Can't stat the key (running as a non-service user against the 0700
        # confdir). Report informationally; this is not itself a finding.
        return [
            f"NOTE: could not read CA key perms at {key_path} (permission denied). "
            "Run `avp doctor` as the agent-vault-proxy service user to check key perms."
        ]
    except OSError as e:
        return [f"could not stat CA key {key_path}: {type(e).__name__}"]

    mode = stat.S_IMODE(st.st_mode)
    # Any group/other bit set on the private key is a finding.
    if mode & 0o077:
        warnings.append(
            f"INSECURE: CA private key {key_path} has mode {oct(mode)}; it must be "
            "0600 (owner read/write only). A group/other-readable CA key lets a "
            "same-UID or same-group process forge TLS certs for any host. "
            "Run: chmod 0600 on the key."
        )

    # The containing confdir should be 0700 so the key can't be reached via a
    # loose directory even if the key mode were somehow widened.
    parent = path.parent
    try:
        dir_mode = stat.S_IMODE(parent.stat().st_mode)
        if dir_mode & 0o077:
            warnings.append(
                f"INSECURE: CA confdir {parent} has mode {oct(dir_mode)}; it must be "
                "0700 (owner-only). ADR-0012 keeps the CA key off other UIDs by "
                "isolating the directory. Run: chmod 0700 on the directory."
            )
    except OSError:
        pass

    # Ownership: the key should be owned by the user running the daemon (the
    # service user in production). We can only meaningfully compare against
    # the current euid; warn if the key is owned by a DIFFERENT uid AND we're
    # not root (root legitimately inspects any file).
    euid = os.geteuid()
    if euid != 0 and st.st_uid != euid:
        warnings.append(
            f"WARNING: CA private key {key_path} is owned by uid {st.st_uid}, not the "
            f"current user (uid {euid}). Confirm it is owned by the agent-vault-proxy "
            "service user and not readable by the agent's UID."
        )
    return warnings


def run_doctor(
    *,
    ca_cert_path: str | None = None,
    ca_key_path: str | None = None,
    config_path: str | None = None,
    probe_oauth: bool = False,
    binding_filter: str | None = None,
    do_exchange: bool = False,
    probe_gcp: bool = False,
) -> int:
    """Execute the ``avp doctor`` checks.

    Always runs the CA regression checks (ADR-0012). When ``probe_oauth``
    is set, ALSO runs the per-binding OAuth2 probes (ADR-0017 slice 8) —
    the probes load ``config_path`` and build the configured backend,
    then dispatch through :mod:`agent_vault_proxy.cli.doctor_oauth`. The
    backend is NEVER built when ``probe_oauth`` is false so a missing or
    mis-permissioned config can't break the CA-only flow.

    Returns 0 (clean) or 1 (any FAIL — CA warning OR OAuth probe FAIL).
    """
    all_warnings: list[str] = []
    all_warnings.extend(check_ca_not_in_trust_store(ca_cert_path))
    all_warnings.extend(check_ca_key_perms(ca_key_path))

    any_oauth_fail = False
    if probe_oauth:
        any_oauth_fail = _run_oauth_probes(
            config_path=config_path,
            binding_filter=binding_filter,
            do_exchange=do_exchange,
        )

    any_gcp_fail = False
    if probe_gcp:
        from agent_vault_proxy.cli.doctor_gcp import run_gcp_probe

        any_gcp_fail = run_gcp_probe(config_path=config_path)

    if not all_warnings:
        print("avp doctor: CA checks passed (CA not in any OS trust store; key perms OK).")
    else:
        print(f"avp doctor: {len(all_warnings)} CA warning(s):", file=sys.stderr)
        for w in all_warnings:
            print(f"  - {w}", file=sys.stderr)

    if all_warnings or any_oauth_fail or any_gcp_fail:
        return 1
    return 0


def _run_oauth_probes(
    *,
    config_path: str | None,
    binding_filter: str | None,
    do_exchange: bool,
) -> bool:
    """Drive the OAuth probe path and print results. Returns True if any
    ``FAIL`` rolled up — caller folds into exit code.

    Config / backend errors prior to the probes themselves print to
    stderr and roll up as a FAIL so an unreadable config doesn't pass
    silently.
    """
    # Defer import so loading the OAuth probe surface (urllib, the
    # injector) doesn't happen on a plain `avp doctor` invocation.
    from agent_vault_proxy.cli.doctor_oauth import probe_all_oauth_bindings

    if config_path is None:
        print(
            "avp doctor --probe-oauth: --config <path> is required to load bindings.",
            file=sys.stderr,
        )
        return True
    try:
        config = load_config(config_path)
    except Exception as e:  # noqa: BLE001 - operator-facing CLI surface
        print(
            f"avp doctor --probe-oauth: cannot load config {config_path}: {type(e).__name__}: {e}",
            file=sys.stderr,
        )
        return True
    try:
        backend, _ = build_backend(config)
    except Exception as e:  # noqa: BLE001 - operator-facing CLI surface
        print(
            f"avp doctor --probe-oauth: cannot build backend: {type(e).__name__}: {e}",
            file=sys.stderr,
        )
        return True

    results, any_fail = probe_all_oauth_bindings(
        config,
        backend,
        binding_filter=binding_filter,
        do_exchange=do_exchange,
    )

    # Group results by binding for readable output.
    by_binding: dict[str, list] = {}
    for r in results:
        by_binding.setdefault(r.binding_name, []).append(r)

    print()
    print("avp doctor --probe-oauth: results")
    for name, items in by_binding.items():
        print(f"  [{name}]")
        for r in items:
            print(f"    {r.status:5s} {r.check:24s} {r.message}")
    print()
    if any_fail:
        print("avp doctor --probe-oauth: one or more FAIL results", file=sys.stderr)
    else:
        print("avp doctor --probe-oauth: all probes OK or WARN")
    return any_fail
