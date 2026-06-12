"""Declarative policy regression fixtures — ADR-0013, architecture.md §8.1.

Each tests/fixtures/policy/*.yaml is a spec-derived (config, request) -> decision
assertion pinned to the T-/G- id it guards. Fixtures drive the real addon headless
against a static backend: one decision path, no real secret in play.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from mitmproxy.test import tflow

from agent_vault_proxy.addon import AgentVaultProxyAddon
from agent_vault_proxy.audit import AuditWriter
from agent_vault_proxy.backends import BackendUnavailableError, FetchContext
from agent_vault_proxy.caching import CachingSecretsClient
from agent_vault_proxy.config import load_config

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "policy"


class _StaticBackend:
    """In-memory secrets; never touches BWS. fail=True exercises G4 fail-closed."""

    def __init__(self, secrets: dict[str, str], *, fail: bool = False) -> None:
        self._secrets = secrets
        self._fail = fail

    def fetch(self, name: str, ctx: FetchContext | None = None) -> str:
        if self._fail:
            raise BackendUnavailableError("fixture: simulated outage")
        return self._secrets[name]


def run_policy_fixture(fix: dict[str, Any], tmp_path: Path) -> dict[str, Any]:
    """Run one fixture through the live addon; return the observed decision.
    Nondeterministic audit fields (ts, request_id) are never compared."""
    audit_path = tmp_path / "audit.jsonl"
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(
        fix["config"] + f"\naudit:\n  path: {audit_path}\n  fail_on_unwritable: true\n"
    )

    addon = AgentVaultProxyAddon()
    addon.config = load_config(config_path)
    addon.audit = AuditWriter(str(audit_path))
    addon.client = CachingSecretsClient(
        _StaticBackend(fix.get("secrets", {}), fail=fix.get("backend", {}).get("fail", False)),
        ttl_seconds=300,
        jitter_seconds=0,
        max_entries=100,
    )

    req = fix["request"]
    flow = tflow.tflow()
    flow.request.host = req["host"]
    flow.request.port = req.get("port", 443)
    flow.request.scheme = "https"
    flow.request.method = req.get("method", "GET")
    flow.request.path = req.get("path", "/")
    for key, value in req.get("headers", {}).items():
        flow.request.headers[key] = value
    if "connect" in req:
        # CONNECT host != inner Host is what trips the SNI/Host check (G3).
        flow.metadata["avp_connect_host"] = req["connect"]
        flow.metadata["avp_request_id"] = "fixture"

    addon.requestheaders(flow)

    lines = audit_path.read_text().splitlines() if audit_path.exists() else []
    events = [json.loads(x) for x in lines if x]
    e = next((x for x in reversed(events) if x.get("type") in ("inject_decision", "deny")), {})
    return {
        "decision": e.get("decision", "denied" if e else "forward_unmodified"),
        "reason": e.get("reason"),
        "secret_name": e.get("secret_name"),
        "injected": e.get("decision") == "allowed",
        "status": flow.response.status_code if flow.response else None,
        # Final Authorization value: the rendered secret when injected, or the
        # untouched placeholder on a verbatim-forward denial (proves G5).
        "header": flow.request.headers.get("Authorization"),
    }


@pytest.mark.parametrize("fix", sorted(FIXTURE_DIR.glob("*.yaml")), ids=lambda p: p.stem)
def test_policy_fixture(fix: Path, tmp_path: Path) -> None:
    data = yaml.safe_load(fix.read_text())
    observed = run_policy_fixture(data, tmp_path)
    pins = ",".join(data.get("pins", []))
    for key, want in data["expect"].items():
        got = observed.get(key)
        assert got == want, f"{fix.stem} [{pins}]: {key} expected {want!r}, got {got!r}"
