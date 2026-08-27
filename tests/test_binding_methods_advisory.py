from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mitmproxy.test import tflow

from kow.addon import AgentVaultProxyAddon
from kow.audit import AuditWriter
from kow.backends import FetchContext
from kow.caching import CachingSecretsClient
from kow.config import load_config
from kow.secret import Secret

PLACEHOLDER = "adv_PLACEHOLDER_01HXY1234567890AB"
REAL_SECRET = "rl-real-secret"


class _FakeBackend:
    def fetch(self, name: str, ctx: FetchContext | None = None) -> Secret:
        return Secret(REAL_SECRET)


def _write_config(
    tmp_path: Path,
    *,
    binding_lines: str,
    audit_path: Path | None = None,
) -> Path:
    audit = audit_path or tmp_path / "audit.jsonl"
    cfg = tmp_path / "bindings.yaml"
    cfg.write_text(f"""
version: 1
secrets:
  RATE_LIMITED:
    placeholder: "{PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "Bearer {{RATE_LIMITED}}"
    bindings:
      - host: "api.example.com"
{binding_lines}
audit:
  path: {audit}
  fail_on_unwritable: true
""")
    return cfg


def _build_addon(
    tmp_path: Path,
    *,
    binding_lines: str,
) -> tuple[AgentVaultProxyAddon, Path]:
    audit_path = tmp_path / "audit.jsonl"
    cfg = _write_config(tmp_path, binding_lines=binding_lines, audit_path=audit_path)
    addon = AgentVaultProxyAddon()
    addon.config = load_config(cfg)
    addon.audit = AuditWriter(str(audit_path))
    addon.client = CachingSecretsClient(
        _FakeBackend(),
        ttl_seconds=300,
        jitter_seconds=0,
        max_entries=100,
    )
    return addon, audit_path


def _flow(*, method: str = "GET") -> Any:
    flow = tflow.tflow()
    flow.request.host = "api.example.com"
    flow.request.port = 443
    flow.request.scheme = "https"
    flow.request.method = method
    flow.request.path = "/v1/resource"
    flow.request.headers["Authorization"] = f"Bearer {PLACEHOLDER}"
    return flow


def _drive(addon: AgentVaultProxyAddon, *, method: str = "GET") -> Any:
    flow = _flow(method=method)
    addon.http_connect(flow)
    addon.requestheaders(flow)
    return flow


def _events(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def test_methods_default_deprecation_fires_for_post(tmp_path: Path) -> None:
    addon, audit_path = _build_addon(tmp_path, binding_lines="")
    flow = _drive(addon, method="POST")

    assert flow.response is None
    assert flow.request.headers["Authorization"] == f"Bearer {REAL_SECRET}"
    assert any(e.get("reason") == "binding_methods_unscoped" for e in _events(audit_path))


def test_methods_default_deprecation_fires_for_put(tmp_path: Path) -> None:
    addon, audit_path = _build_addon(tmp_path, binding_lines="")
    flow = _drive(addon, method="PUT")

    assert flow.response is None
    assert any(
        e.get("reason") == "binding_methods_unscoped" and e.get("method") == "PUT"
        for e in _events(audit_path)
    )


def test_methods_default_deprecation_does_not_fire_for_get(tmp_path: Path) -> None:
    addon, audit_path = _build_addon(tmp_path, binding_lines="")
    flow = _drive(addon, method="GET")

    assert flow.response is None
    assert not any(e.get("reason") == "binding_methods_unscoped" for e in _events(audit_path))


def test_methods_default_deprecation_does_not_fire_for_explicit_methods(
    tmp_path: Path,
) -> None:
    addon, audit_path = _build_addon(tmp_path, binding_lines="        methods: [POST]\n")
    flow = _drive(addon, method="POST")

    assert flow.response is None
    assert not any(e.get("reason") == "binding_methods_unscoped" for e in _events(audit_path))


def test_unscoped_advisory_emitted_once_per_secret_host_verb(tmp_path: Path) -> None:
    """The advisory is a config smell, not a per-request event (ADR-0047)."""
    addon, audit_path = _build_addon(tmp_path, binding_lines="")
    for _ in range(5):
        _drive(addon, method="POST")

    advisories = [e for e in _events(audit_path) if e.get("reason") == "binding_methods_unscoped"]
    assert len(advisories) == 1
    injections = [e for e in _events(audit_path) if e.get("reason") == "binding_matched"]
    assert len(injections) == 5

    # A different verb is a different smell and gets its own single line.
    _drive(addon, method="DELETE")
    _drive(addon, method="DELETE")
    advisories = [e for e in _events(audit_path) if e.get("reason") == "binding_methods_unscoped"]
    assert sorted(e["method"] for e in advisories) == ["DELETE", "POST"]


def test_unscoped_advisory_keyed_on_binding_host_not_request_host(tmp_path: Path) -> None:
    """Oracle C3: a wildcard binding must not let subdomains grow the set."""
    audit_path = tmp_path / "audit.jsonl"
    cfg = tmp_path / "bindings.yaml"
    cfg.write_text(f"""
version: 1
allow_wildcard_hosts: true
secrets:
  RATE_LIMITED:
    placeholder: "{PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "Bearer {{RATE_LIMITED}}"
    bindings:
      - host: "*.example.com"
audit:
  path: {audit_path}
  fail_on_unwritable: true
""")
    addon = AgentVaultProxyAddon()
    addon.config = load_config(cfg)
    addon.audit = AuditWriter(str(audit_path))
    addon.client = CachingSecretsClient(
        _FakeBackend(), ttl_seconds=300, jitter_seconds=0, max_entries=100
    )

    for sub in ("a", "b", "c", "d", "e"):
        flow = _flow(method="POST")
        flow.request.host = f"{sub}.example.com"
        addon.http_connect(flow)
        addon.requestheaders(flow)

    # One configured binding, one verb: one advisory and one set entry, no
    # matter how many attacker-chosen subdomains showed up.
    assert len(addon._unscoped_advised) == 1  # noqa: SLF001
    advisories = [e for e in _events(audit_path) if e.get("reason") == "binding_methods_unscoped"]
    assert len(advisories) == 1
