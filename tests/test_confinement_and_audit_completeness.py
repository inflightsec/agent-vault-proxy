"""Red-team guards for surfaces 4 (site confinement) and 5 (audit completeness).

Surface 4 — a placeholder must only be substituted at its CONFIGURED site type.
The header path (find_header_placeholder_matches) skips body leaves; the body
path (_collect_candidates) picks only body leaves. So a header-only secret whose
placeholder lands in the body, or a body-only secret whose placeholder lands in
a header, must be forwarded verbatim — never fetched, never substituted at the
wrong site. test_multi_injector.py covers the schema; this covers the runtime.

Surface 5 — every real-secret injection must leave exactly one `inject_decision`
/ `allowed` audit event naming the secret (no silent credential use). The
no-leak machines assert the secret never appears IN the audit; these assert the
audit EXISTS whenever an injection happens.

All four pass on current code — the guards are refutations kept as regressions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mitmproxy.test import tflow

from agent_vault_proxy.addon import AgentVaultProxyAddon
from agent_vault_proxy.audit import AuditWriter
from agent_vault_proxy.backends import FetchContext
from agent_vault_proxy.caching import CachingSecretsClient
from agent_vault_proxy.config import load_config

H_PLACEHOLDER = "sk-PLACEHOLDER-01HXY1234567890ABCDEFGHIJ"
H_REAL = "sk-REAL-hdr-DO-NOT-LEAK-0xAAAA"
B_PLACEHOLDER = "tok_PLACEHOLDER_01HXY1234567890ABC"  # 35 chars
B_REAL = "tok-REAL-body-DO-NOT-LEAK-0xBBBB"


class _FakeBackend:
    def __init__(self, per_name: dict[str, str]) -> None:
        self._per_name = per_name

    def fetch(self, name: str, ctx: FetchContext | None = None) -> str:
        return self._per_name[name]


def _build(
    tmp_path: Path, yaml: str, per_name: dict[str, str]
) -> tuple[AgentVaultProxyAddon, Path]:
    audit = tmp_path / "audit.jsonl"
    cfg = tmp_path / "bindings.yaml"
    cfg.write_text(yaml.replace("__AUDIT__", str(audit)))
    addon = AgentVaultProxyAddon()
    addon.config = load_config(cfg)
    addon.audit = AuditWriter(str(audit))
    addon.client = CachingSecretsClient(
        _FakeBackend(per_name), ttl_seconds=300, jitter_seconds=0, max_entries=100
    )
    return addon, audit


def _audit_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def _flow(host: str, *, method: str = "POST", path: str = "/v1/x") -> Any:
    flow = tflow.tflow()
    flow.request.host = host
    flow.request.port = 443
    flow.request.scheme = "https"
    flow.request.method = method
    flow.request.path = path
    return flow


def _run(addon: AgentVaultProxyAddon, flow: Any) -> None:
    addon.http_connect(flow)
    if flow.response is None:
        addon.requestheaders(flow)


def _stream_body(flow: Any, body: bytes) -> bytes:
    replacer = flow.request.stream
    if not callable(replacer):
        return body  # no replacer attached => forwarded verbatim
    out = bytearray()
    out.extend(replacer(body))
    out.extend(replacer(b""))
    return bytes(out)


_HEADER_ONLY = f"""
version: 1
secrets:
  HKEY:
    placeholder: "{H_PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "Bearer {{HKEY}}"
    bindings:
      - host: "api.example.com"
unmatched_destination_policy: deny
audit:
  path: __AUDIT__
  fail_on_unwritable: true
"""

_BODY_ONLY = f"""
version: 1
secrets:
  BKEY:
    placeholder: "{B_PLACEHOLDER}"
    inject:
      type: body
      format: "{{BKEY}}"
    bindings:
      - host: "hooks.example.com"
unmatched_destination_policy: deny
audit:
  path: __AUDIT__
  fail_on_unwritable: true
"""


# --- Surface 4: site confinement --------------------------------------------


def test_header_only_secret_placeholder_in_body_is_not_substituted(tmp_path: Path) -> None:
    """A header-injector secret whose placeholder appears in the BODY must not
    be fetched or substituted — the body path ignores non-body leaves."""
    addon, audit = _build(tmp_path, _HEADER_ONLY, {"HKEY": H_REAL})
    flow = _flow("api.example.com")
    flow.request.content = json.dumps({"leaked": H_PLACEHOLDER}).encode()
    _run(addon, flow)

    assert not callable(flow.request.stream), "no body replacer for a header-only secret"
    body_out = _stream_body(flow, flow.request.content)
    assert H_REAL.encode() not in body_out, "header-only secret leaked into the body"
    assert not [e for e in _audit_events(audit) if e.get("decision") == "allowed"]


def test_body_only_secret_placeholder_in_header_is_not_substituted(tmp_path: Path) -> None:
    """A body-injector secret whose placeholder appears in a HEADER must be
    forwarded verbatim — the header path skips body leaves."""
    addon, audit = _build(tmp_path, _BODY_ONLY, {"BKEY": B_REAL})
    flow = _flow("hooks.example.com")
    flow.request.headers["X-Custom"] = B_PLACEHOLDER
    _run(addon, flow)

    assert flow.request.headers["X-Custom"] == B_PLACEHOLDER, "placeholder must forward verbatim"
    assert B_REAL not in flow.request.headers.get("X-Custom", ""), (
        "body secret leaked into a header"
    )
    assert not [e for e in _audit_events(audit) if e.get("decision") == "allowed"]


# --- Surface 5: audit completeness ------------------------------------------


def test_header_injection_emits_exactly_one_allowed_audit(tmp_path: Path) -> None:
    addon, audit = _build(tmp_path, _HEADER_ONLY, {"HKEY": H_REAL})
    flow = _flow("api.example.com")
    flow.request.headers["Authorization"] = f"Bearer {H_PLACEHOLDER}"
    _run(addon, flow)

    assert H_REAL in flow.request.headers["Authorization"], "precondition: injection happened"
    allowed = [e for e in _audit_events(audit) if e.get("decision") == "allowed"]
    assert len(allowed) == 1
    assert allowed[0]["reason"] == "binding_matched"
    assert allowed[0]["secret_name"] == "HKEY"


def test_body_injection_emits_exactly_one_allowed_audit(tmp_path: Path) -> None:
    addon, audit = _build(tmp_path, _BODY_ONLY, {"BKEY": B_REAL})
    flow = _flow("hooks.example.com")
    _run(addon, flow)

    body_out = _stream_body(flow, json.dumps({"t": B_PLACEHOLDER}).encode())
    assert B_REAL.encode() in body_out, "precondition: body injection happened"
    allowed = [e for e in _audit_events(audit) if e.get("decision") == "allowed"]
    assert len(allowed) == 1
    assert allowed[0]["reason"] == "body_binding_matched"
    assert allowed[0]["secret_name"] == "BKEY"
