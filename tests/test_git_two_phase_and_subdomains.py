"""End-to-end addon tests for two adopted hardenings:

1. Git smart-HTTP two-phase scoping — a `paths:` scope that permits clone
   (`git-upload-pack`) but not push (`git-receive-pack`) must deny the push
   *discovery* GET, not just the data POST. The write intent lives in the
   `?service=` query the path scope strips; the addon canonicalises the
   discovery request to its data-phase path so both phases scope as one.

2. Wildcard-host `subdomains:` discriminator — a `*.jfrog.io` binding scoped
   to `subdomains: [mycompany]` must inject only for `mycompany.jfrog.io`,
   never for an attacker-controlled `evil.jfrog.io`.

Both drive the real ``addon.requestheaders`` path (same harness as
``test_addon.py``) so the addon wiring is covered, not only ``decide``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mitmproxy.test import tflow

from kow.addon import AgentVaultProxyAddon
from kow.audit import AuditWriter
from kow.backends import FetchContext
from kow.caching import CachingSecretsClient
from kow.secret import Secret

GITHUB_PLACEHOLDER = "ghp-PLACEHOLDER-01HXY1234567890AB"
JFROG_PLACEHOLDER = "jfrog-PLACEHOLDER-01HXY1234567890AB"
REAL_SECRET = "real-secret-value-XYZ"


class _ConstBackend:
    def fetch(self, name: str, ctx: FetchContext | None = None) -> Secret:
        return Secret(REAL_SECRET)


def _client() -> CachingSecretsClient:
    return CachingSecretsClient(_ConstBackend(), ttl_seconds=300, jitter_seconds=0, max_entries=100)


def _addon(tmp_path: Path, config_yaml: str) -> tuple[AgentVaultProxyAddon, Path]:
    from kow.config import load_config

    audit_path = tmp_path / "audit.jsonl"
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(
        config_yaml + f"\naudit:\n  path: {audit_path}\n  fail_on_unwritable: true\n"
    )
    addon = AgentVaultProxyAddon()
    addon.config = load_config(config_path)
    addon.audit = AuditWriter(str(audit_path))
    addon.client = _client()
    return addon, audit_path


def _read_audit(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def _request(host: str, method: str, path: str, headers: dict[str, str]) -> Any:
    flow = tflow.tflow()
    flow.request.host = host
    flow.request.port = 443
    flow.request.scheme = "https"
    flow.request.method = method
    flow.request.path = path
    for k, v in headers.items():
        flow.request.headers[k] = v
    return flow


_GIT_CONFIG = f"""
version: 1

secrets:
  GITHUB_PAT:
    placeholder: "{GITHUB_PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "token {{GITHUB_PAT}}"
    bindings:
      - host: "github.com"
        paths: ["/**/git-upload-pack"]   # clone-only; push must be denied

unmatched_destination_policy: forward_unmodified
"""


def _run(addon: AgentVaultProxyAddon, flow: Any) -> None:
    addon.http_connect(flow)
    if flow.response is None:
        addon.requestheaders(flow)


def test_git_clone_discovery_injects(tmp_path: Path) -> None:
    """upload-pack discovery GET → canonicalises to `.../git-upload-pack`,
    matches the clone-only paths scope → credential injected."""
    addon, audit = _addon(tmp_path, _GIT_CONFIG)
    flow = _request(
        "github.com",
        "GET",
        "/owner/repo.git/info/refs?service=git-upload-pack",
        {"Authorization": f"token {GITHUB_PLACEHOLDER}"},
    )
    _run(addon, flow)
    assert flow.request.headers["Authorization"] == f"token {REAL_SECRET}"
    assert any(
        e.get("decision") == "allowed" and e.get("reason") == "binding_matched"
        for e in _read_audit(audit)
    )


def test_git_push_discovery_denied_and_forwarded(tmp_path: Path) -> None:
    """receive-pack discovery GET → canonicalises to `.../git-receive-pack`,
    OUTSIDE the clone-only scope → scope violation, placeholder forwarded
    verbatim (G5), audited path is the data-phase service path."""
    addon, audit = _addon(tmp_path, _GIT_CONFIG)
    flow = _request(
        "github.com",
        "GET",
        "/owner/repo.git/info/refs?service=git-receive-pack",
        {"Authorization": f"token {GITHUB_PLACEHOLDER}"},
    )
    _run(addon, flow)
    # Placeholder forwarded unchanged — no real secret leaked into the push.
    assert flow.request.headers["Authorization"] == f"token {GITHUB_PLACEHOLDER}"
    scope_denials = [e for e in _read_audit(audit) if e.get("reason") == "binding_scope_violation"]
    assert scope_denials, "expected a binding_scope_violation for the push discovery"
    assert scope_denials[-1]["path"] == "/owner/repo.git/git-receive-pack"


def test_git_push_data_post_denied(tmp_path: Path) -> None:
    """The data-phase push POST is also out of scope (belt and suspenders)."""
    addon, audit = _addon(tmp_path, _GIT_CONFIG)
    flow = _request(
        "github.com",
        "POST",
        "/owner/repo.git/git-receive-pack",
        {"Authorization": f"token {GITHUB_PLACEHOLDER}"},
    )
    _run(addon, flow)
    assert flow.request.headers["Authorization"] == f"token {GITHUB_PLACEHOLDER}"
    assert any(e.get("reason") == "binding_scope_violation" for e in _read_audit(audit))


def test_git_clone_data_post_injects(tmp_path: Path) -> None:
    """The data-phase clone POST is in scope → injected."""
    addon, _ = _addon(tmp_path, _GIT_CONFIG)
    flow = _request(
        "github.com",
        "POST",
        "/owner/repo.git/git-upload-pack",
        {"Authorization": f"token {GITHUB_PLACEHOLDER}"},
    )
    _run(addon, flow)
    assert flow.request.headers["Authorization"] == f"token {REAL_SECRET}"


_JFROG_CONFIG = f"""
version: 1
allow_wildcard_hosts: true

secrets:
  JFROG_TOKEN:
    placeholder: "{JFROG_PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "Bearer {{JFROG_TOKEN}}"
    bindings:
      - host: "*.jfrog.io"
        subdomains: ["mycompany"]

unmatched_destination_policy: forward_unmodified
"""


def test_wildcard_allowed_subdomain_injects(tmp_path: Path) -> None:
    addon, _ = _addon(tmp_path, _JFROG_CONFIG)
    flow = _request(
        "mycompany.jfrog.io",
        "GET",
        "/artifactory/api/foo",
        {"Authorization": f"Bearer {JFROG_PLACEHOLDER}"},
    )
    _run(addon, flow)
    assert flow.request.headers["Authorization"] == f"Bearer {REAL_SECRET}"


def test_wildcard_disallowed_subdomain_forwarded(tmp_path: Path) -> None:
    """An attacker subdomain matches the `*.jfrog.io` pattern but not the
    `subdomains:` allowlist → no binding → placeholder forwarded verbatim."""
    addon, audit = _addon(tmp_path, _JFROG_CONFIG)
    flow = _request(
        "evil.jfrog.io",
        "GET",
        "/artifactory/api/foo",
        {"Authorization": f"Bearer {JFROG_PLACEHOLDER}"},
    )
    _run(addon, flow)
    assert flow.request.headers["Authorization"] == f"Bearer {JFROG_PLACEHOLDER}"
    assert any(e.get("reason") == "destination_not_in_binding" for e in _read_audit(audit))
