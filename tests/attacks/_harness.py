"""Shared rig for the adversarial attack gallery (ADR-0043).

Every exploit drives the **real** addon pipeline — ``http_connect`` ->
``requestheaders`` -> (``request`` for body-signers) -> ``response`` — with no
mock of the inject path, exactly like ``tests/test_addon_noleak_stateful.py``.
The only thing simulated is the *upstream*: a hostile or buggy server that
echoes or stores what kow injected. That is the attacker's lever, not ours.

The distinctive sentinel values make a substring search over headers, bodies,
and the audit stream unambiguous: if ``REAL`` appears anywhere the agent can
read, the secret leaked.
"""

from __future__ import annotations

from pathlib import Path

from mitmproxy import http
from mitmproxy.test import tflow

from kow.addon import AgentVaultProxyAddon
from kow.audit import AuditWriter
from kow.backends import FetchContext
from kow.caching import CachingSecretsClient
from kow.config import load_config
from kow.secret import Secret

# Distinctive so a substring search is unambiguous (mirrors the stateful test).
REAL = "sk-REAL-DO-NOT-LEAK-0xDEADBEEF"
PLACEHOLDER = "sk-PLACEHOLDER-01HXY1234567890ABCDEFGHIJ"
BOUND_HOST = "api.openai.com"

# Scope variants for the SAME secret+host. WIDE = any method/path; NARROW =
# only POST under /v1/**. NARROW is what the laundering/scope exploits push on.
WIDE = '      - host: "api.openai.com"\n'
NARROW = '      - host: "api.openai.com"\n        methods: ["POST"]\n        paths: ["/v1/**"]\n'


# A SECOND secret on a SECOND host, for cross-binding exploits (Oracle C7).
# Values are disjoint substrings from REAL/PLACEHOLDER so "not in" is unambiguous.
REAL_B = "gh-REAL-OTHER-SECRET-0xC0FFEE00"
PLACEHOLDER_B = "gh-PLACEHOLDER-02ABCDEFGHIJKLMNOPQRSTUV"
BOUND_HOST_B = "api.github.com"

_SECRET_VALUES = {"OPENAI_API_KEY": REAL, "GITHUB_TOKEN": REAL_B}


def _yaml(bindings: str, audit: Path) -> str:
    return f"""
version: 1
secrets:
  OPENAI_API_KEY:
    placeholder: "{PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "Bearer {{OPENAI_API_KEY}}"
    bindings:
{bindings}
unmatched_destination_policy: deny
audit:
  path: {audit}
  fail_on_unwritable: true
"""


def _yaml_two_secrets(audit: Path) -> str:
    """Two secrets, each bound to its OWN host — the cross-binding fixture."""
    return f"""
version: 1
secrets:
  OPENAI_API_KEY:
    placeholder: "{PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "Bearer {{OPENAI_API_KEY}}"
    bindings:
      - host: "{BOUND_HOST}"
  GITHUB_TOKEN:
    placeholder: "{PLACEHOLDER_B}"
    inject:
      header: "Authorization"
      format: "Bearer {{GITHUB_TOKEN}}"
    bindings:
      - host: "{BOUND_HOST_B}"
unmatched_destination_policy: deny
audit:
  path: {audit}
  fail_on_unwritable: true
"""


class _FakeBackend:
    """Constant-value backend; first I/O is fetch (Protocol contract)."""

    def fetch(self, name: str, ctx: FetchContext | None = None) -> Secret:
        return Secret(REAL)


class _KeyedBackend:
    """Per-name backend so two bindings resolve to two distinct real values."""

    def fetch(self, name: str, ctx: FetchContext | None = None) -> Secret:
        return Secret(_SECRET_VALUES[name])


def build_addon(tmp_path: Path, *, bindings: str = WIDE) -> tuple[AgentVaultProxyAddon, Path]:
    """A fully wired addon over a temp policy + audit log. Returns (addon, audit_path)."""
    audit = Path(tmp_path) / "audit.jsonl"
    cfg = Path(tmp_path) / "bindings.yaml"
    cfg.write_text(_yaml(bindings, audit))
    addon = AgentVaultProxyAddon()
    addon.audit = AuditWriter(str(audit))
    addon.client = CachingSecretsClient(
        _FakeBackend(), ttl_seconds=300, jitter_seconds=0, max_entries=100
    )
    addon.config = load_config(cfg)
    return addon, audit


def build_addon_two_secrets(tmp_path: Path) -> tuple[AgentVaultProxyAddon, Path]:
    """Addon with OPENAI_API_KEY on BOUND_HOST and GITHUB_TOKEN on BOUND_HOST_B,
    each resolving to its own real value via _KeyedBackend."""
    audit = Path(tmp_path) / "audit.jsonl"
    cfg = Path(tmp_path) / "bindings.yaml"
    cfg.write_text(_yaml_two_secrets(audit))
    addon = AgentVaultProxyAddon()
    addon.audit = AuditWriter(str(audit))
    addon.client = CachingSecretsClient(
        _KeyedBackend(), ttl_seconds=300, jitter_seconds=0, max_entries=100
    )
    addon.config = load_config(cfg)
    return addon, audit


def make_flow(
    host: str,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    content: bytes = b"",
) -> http.HTTPFlow:
    flow = tflow.tflow()
    flow.request.host = host
    flow.request.port = 443
    flow.request.scheme = "https"
    flow.request.method = method
    flow.request.path = path
    for name, value in (headers or {}).items():
        flow.request.headers[name] = value
    if content:
        flow.request.content = content
    return flow


def drive_outbound(addon: AgentVaultProxyAddon, flow: http.HTTPFlow) -> http.HTTPFlow:
    """Run the true inject path up to (not including) the upstream response.

    Mirrors what mitmproxy does on the wire: connect gate, then header
    injection, then the body/signing hook if a signer stashed a verdict.
    """
    addon.http_connect(flow)
    if flow.response is None:
        addon.requestheaders(flow)
    if flow.response is None and flow.metadata.get("avp_signing") is not None:
        addon.request(flow)
    return flow


def simulate_upstream(
    addon: AgentVaultProxyAddon,
    flow: http.HTTPFlow,
    *,
    status: int = 200,
    content: bytes = b"",
    headers: dict[str, str] | None = None,
) -> http.Response:
    """Attach an upstream response and run the ``response`` hook — the ONLY
    place a response-side scrub/redact (ADR-0031) could act. Returns what
    the agent receives back."""
    flow.response = http.Response.make(status, content, headers or {"Content-Type": "text/plain"})
    addon.response(flow)
    return flow.response


def agent_visible(response: http.Response) -> str:
    """Everything the agent can read from the response: headers + body."""
    header_blob = "\n".join(f"{name}: {value}" for name, value in response.headers.items())
    body = response.content.decode("utf-8", errors="replace") if response.content else ""
    return f"{header_blob}\n{body}"
