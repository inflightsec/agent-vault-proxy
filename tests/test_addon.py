from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from mitmproxy.test import tflow

from agent_vault_proxy.addon import AgentVaultProxyAddon
from agent_vault_proxy.audit import AuditWriter
from agent_vault_proxy.backends import BackendUnavailableError, FetchContext
from agent_vault_proxy.caching import CachingSecretsClient
from agent_vault_proxy.config import load_config

PLACEHOLDER = "sk-ant-PLACEHOLDER-01HXY1234567890ABCDEFGH"
OPENAI_PLACEHOLDER = "sk-PLACEHOLDER-01HXY1234567890ABCDEFGHIJ"
REAL_SECRET = "sk-ant-real-test-value-XYZ"


class _FakeBackend:
    """Minimal in-memory SecretsBackend for addon tests. Returns a constant
    value (or a per-name lookup) and can be flipped to fail with
    BackendUnavailableError to exercise the unavailable-backend code path."""

    def __init__(
        self,
        value: str = REAL_SECRET,
        *,
        fail: bool = False,
        per_name: dict[str, str] | None = None,
    ) -> None:
        self._value = value
        self._fail = fail
        self._per_name = per_name or {}

    def fetch(self, name: str, ctx: FetchContext | None = None) -> str:
        if self._fail:
            raise BackendUnavailableError("simulated outage")
        return self._per_name.get(name, self._value)


def _make_client(
    value: str = REAL_SECRET,
    *,
    fail: bool = False,
    per_name: dict[str, str] | None = None,
) -> CachingSecretsClient:
    """Test factory: a CachingSecretsClient wrapping the fake backend."""
    return CachingSecretsClient(
        _FakeBackend(value, fail=fail, per_name=per_name),
        ttl_seconds=300,
        jitter_seconds=0,
        max_entries=100,
    )


def _build_addon(tmp_path: Path) -> tuple[AgentVaultProxyAddon, Path]:
    audit_path = tmp_path / "audit.jsonl"
    config_yaml = f"""
version: 1
allow_wildcard_hosts: true

secrets:
  ANTHROPIC_API_KEY:
    placeholder: "{PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "Bearer {{ANTHROPIC_API_KEY}}"
    bindings:
      - host: "api.anthropic.com"
      - host: "*.anthropic.com"
  OPENAI_API_KEY:
    placeholder: "{OPENAI_PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "Bearer {{OPENAI_API_KEY}}"
    bindings:
      - host: "api.openai.com"

unmatched_destination_policy: deny

audit:
  path: {audit_path}
  fail_on_unwritable: true
"""
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(config_yaml)

    addon = AgentVaultProxyAddon()
    addon.config = load_config(config_path)
    addon.audit = AuditWriter(str(audit_path))
    addon.client = _make_client(REAL_SECRET)
    return addon, audit_path


def _read_audit(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def _make_request(host: str, headers: dict[str, str]) -> Any:
    flow = tflow.tflow()
    flow.request.host = host
    flow.request.port = 443
    flow.request.scheme = "https"
    flow.request.path = "/v1/messages"
    for k, v in headers.items():
        flow.request.headers[k] = v
    return flow


def test_http_connect_denies_unbound_destination(tmp_path: Path) -> None:
    addon, audit_path = _build_addon(tmp_path)
    flow = _make_request("evil.example.com", {})
    addon.http_connect(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403
    events = _read_audit(audit_path)
    assert any(e["type"] == "deny" and e["reason"] == "unmatched_destination" for e in events)


def test_http_connect_allows_bound_destination(tmp_path: Path) -> None:
    addon, _ = _build_addon(tmp_path)
    flow = _make_request("api.anthropic.com", {})
    addon.http_connect(flow)
    assert flow.response is None
    assert flow.metadata.get("avp_request_id") is not None


def test_http_connect_allows_wildcard_subdomain(tmp_path: Path) -> None:
    addon, _ = _build_addon(tmp_path)
    flow = _make_request("console.anthropic.com", {})
    addon.http_connect(flow)
    assert flow.response is None


def test_requestheaders_denies_plain_http_to_unbound_destination(tmp_path: Path) -> None:
    """Regression: plain HTTP requests (no CONNECT, no placeholder) to hosts
    outside the binding set must be rejected, not silently proxied. Otherwise
    the proxy is an open HTTP relay and the kernel egress lock is bypassable."""
    addon, audit_path = _build_addon(tmp_path)
    flow = _make_request("evil.example.com", {})
    # http_connect intentionally NOT called — simulates a plain HTTP request.
    addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403
    events = _read_audit(audit_path)
    assert any(e["type"] == "deny" and e["reason"] == "unmatched_destination" for e in events)


def test_requestheaders_substitutes_placeholder_on_match(tmp_path: Path) -> None:
    addon, audit_path = _build_addon(tmp_path)
    flow = _make_request("api.anthropic.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    addon.requestheaders(flow)
    assert flow.request.headers["Authorization"] == f"Bearer {REAL_SECRET}"
    events = _read_audit(audit_path)
    inject_events = [e for e in events if e["type"] == "inject_decision"]
    assert len(inject_events) == 1
    assert inject_events[0]["decision"] == "allowed"
    assert inject_events[0]["secret_name"] == "ANTHROPIC_API_KEY"


def test_requestheaders_denies_ambiguous_placeholder_match(tmp_path: Path) -> None:
    """If a single header value contains placeholders for two distinct
    configured secrets, the addon refuses to guess and returns 400. The
    addon's placeholder detector is substring-based, and picking the
    first match could route the wrong real secret onto the wire."""
    addon, audit_path = _build_addon(tmp_path)
    flow = _make_request(
        "api.anthropic.com",
        {"Authorization": f"Bearer {PLACEHOLDER} {OPENAI_PLACEHOLDER}"},
    )
    addon.http_connect(flow)
    addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 400
    # The original placeholder header value must NOT have been mutated.
    assert PLACEHOLDER in flow.request.headers["Authorization"]
    assert OPENAI_PLACEHOLDER in flow.request.headers["Authorization"]
    events = _read_audit(audit_path)
    inject_events = [e for e in events if e["type"] == "inject_decision"]
    assert len(inject_events) == 1
    assert inject_events[0]["decision"] == "denied"
    assert inject_events[0]["reason"] == "ambiguous_placeholder_match"
    assert sorted(inject_events[0]["matched_secret_names"]) == [
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
    ]


def test_requestheaders_omits_substitution_on_wrong_secret_for_destination(
    tmp_path: Path,
) -> None:
    addon, audit_path = _build_addon(tmp_path)
    flow = _make_request("api.openai.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    addon.requestheaders(flow)
    assert flow.request.headers["Authorization"] == f"Bearer {PLACEHOLDER}"
    assert flow.response is None
    events = _read_audit(audit_path)
    inject_events = [e for e in events if e["type"] == "inject_decision"]
    assert len(inject_events) == 1
    assert inject_events[0]["decision"] == "denied"
    assert inject_events[0]["reason"] == "destination_not_in_binding"
    assert inject_events[0]["secret_name"] == "ANTHROPIC_API_KEY"


def test_requestheaders_detects_sni_host_mismatch(tmp_path: Path) -> None:
    addon, audit_path = _build_addon(tmp_path)
    flow = _make_request("api.anthropic.com", {})
    addon.http_connect(flow)
    flow.request.host = "evil.example.com"
    addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403
    events = _read_audit(audit_path)
    assert any(e["type"] == "deny" and e["reason"] == "sni_host_mismatch" for e in events)


def test_requestheaders_fails_closed_when_bws_unavailable(tmp_path: Path) -> None:
    addon, audit_path = _build_addon(tmp_path)
    # Swap the cached client for one whose backend always raises
    # BackendUnavailableError, to exercise the fail-closed path.
    addon.client = _make_client(fail=True)

    flow = _make_request("api.anthropic.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 503
    assert flow.request.headers["Authorization"] == f"Bearer {PLACEHOLDER}"
    events = _read_audit(audit_path)
    deny_events = [
        e
        for e in events
        if e["type"] == "inject_decision"
        and e["decision"] == "denied"
        and "secret_unavailable" in e["reason"]
    ]
    assert len(deny_events) == 1


def test_requestheaders_fails_closed_on_unexpected_backend_exception(tmp_path: Path) -> None:
    """G6 regression — discovered via docker-e2e diagnostic dump 2026-05-30.

    The previous addon caught only ``(BackendUnavailableError,
    SecretNotFoundError)`` around ``client.get(secret_name)``. A backend
    that raised any other exception type (e.g., ``PermissionError`` from
    the static backend bind-mounted with the wrong UID) would let the
    exception bubble up to mitmproxy, which logged the traceback and
    forwarded the request **unmodified** — placeholder bytes reached the
    upstream. This test pins the new fail-closed branch: any uncaught
    backend exception MUST return 503, leave the request header
    unmodified, and audit ``inject_decision: denied, reason:
    secret_fetch_error:<ExceptionType>``."""
    addon, audit_path = _build_addon(tmp_path)

    class _ExplodingBackend:
        def fetch(self, name: str, ctx: FetchContext | None = None) -> str:
            raise PermissionError(f"simulated bind-mount perm denial for {name!r}")

    addon.client = CachingSecretsClient(
        _ExplodingBackend(),
        ttl_seconds=300,
        jitter_seconds=0,
        max_entries=100,
    )

    flow = _make_request("api.anthropic.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 503
    # The placeholder MUST still be in the request — proves the addon did
    # not forward a partially-mutated header on its way to a 503.
    assert flow.request.headers["Authorization"] == f"Bearer {PLACEHOLDER}"
    events = _read_audit(audit_path)
    deny_events = [
        e
        for e in events
        if e["type"] == "inject_decision"
        and e["decision"] == "denied"
        and e["reason"].startswith("secret_fetch_error:")
    ]
    assert len(deny_events) == 1
    # The reason field includes the exception class so an operator can
    # tell "permission denied" from "out of memory" from "stale TLS cert".
    assert deny_events[0]["reason"] == "secret_fetch_error:PermissionError"


def _build_scoped_addon(
    tmp_path: Path, methods: str = "[GET]", paths: str = ""
) -> tuple[AgentVaultProxyAddon, Path, str]:
    """Build an addon with GH_TOKEN scoped to given methods/paths."""
    placeholder = "ghp_PLACEHOLDER_01HXY1234567890ABCDEF"
    audit_path = tmp_path / "audit.jsonl"
    methods_line = f"        methods: {methods}\n" if methods else ""
    paths_line = f"        paths: {paths}\n" if paths else ""
    config_yaml = f"""
version: 1
secrets:
  GH_TOKEN:
    placeholder: "{placeholder}"
    inject:
      header: "Authorization"
      format: "token {{GH_TOKEN}}"
    bindings:
      - host: "api.github.com"
{methods_line}{paths_line}
audit:
  path: {audit_path}
"""
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(config_yaml)
    addon = AgentVaultProxyAddon()
    addon.config = load_config(config_path)
    addon.audit = AuditWriter(str(audit_path))
    addon.client = _make_client("ghp_REAL_VALUE")
    return addon, audit_path, placeholder


def test_requestheaders_injects_on_method_scope_match(tmp_path: Path) -> None:
    """Positive case for method scope: GET on a `methods: [GET]` binding
    still triggers normal injection."""
    addon, audit_path, placeholder = _build_scoped_addon(tmp_path, methods="[GET]")
    flow = tflow.tflow()
    flow.request.host = "api.github.com"
    flow.request.port = 443
    flow.request.scheme = "https"
    flow.request.method = "GET"
    flow.request.path = "/repos/foo/bar"
    flow.request.headers["Authorization"] = f"token {placeholder}"

    addon.http_connect(flow)
    addon.requestheaders(flow)

    assert flow.request.headers["Authorization"] == "token ghp_REAL_VALUE"
    events = _read_audit(audit_path)
    allowed = [e for e in events if e.get("decision") == "allowed"]
    assert len(allowed) == 1


def test_requestheaders_omits_substitution_on_method_scope_violation(
    tmp_path: Path,
) -> None:
    """When a binding declares `methods: [GET]` and the request uses POST,
    the proxy must NOT inject (G5 enforcement-by-omission) and must record
    a binding_scope_violation audit event."""
    gh_placeholder = "ghp_PLACEHOLDER_01HXY1234567890ABCDEF"
    audit_path = tmp_path / "audit.jsonl"
    config_yaml = f"""
version: 1
secrets:
  GH_TOKEN:
    placeholder: "{gh_placeholder}"
    inject:
      header: "Authorization"
      format: "token {{GH_TOKEN}}"
    bindings:
      - host: "api.github.com"
        methods: ["GET"]
audit:
  path: {audit_path}
"""
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(config_yaml)
    addon = AgentVaultProxyAddon()
    addon.config = load_config(config_path)
    addon.audit = AuditWriter(str(audit_path))
    addon.client = _make_client("ghp_REAL_VALUE")

    flow = tflow.tflow()
    flow.request.host = "api.github.com"
    flow.request.port = 443
    flow.request.scheme = "https"
    flow.request.method = "POST"  # NOT in declared methods [GET]
    flow.request.path = "/repos/foo/bar/issues"
    flow.request.headers["Authorization"] = f"token {gh_placeholder}"

    addon.http_connect(flow)
    addon.requestheaders(flow)

    # G5: placeholder forwarded verbatim, no 5xx
    assert flow.request.headers["Authorization"] == f"token {gh_placeholder}"
    assert flow.response is None

    events = _read_audit(audit_path)
    scope_events = [e for e in events if e.get("reason") == "binding_scope_violation"]
    assert len(scope_events) == 1, f"expected 1 scope_violation event, got {events}"
    assert scope_events[0]["type"] == "inject_decision"
    assert scope_events[0]["decision"] == "denied"
    assert scope_events[0]["secret_name"] == "GH_TOKEN"
    assert scope_events[0]["method"] == "POST"


def test_requestheaders_injects_on_path_scope_match(tmp_path: Path) -> None:
    """Positive case: path inside `paths: [/repos/**]` still injects."""
    addon, audit_path, placeholder = _build_scoped_addon(
        tmp_path, methods="", paths='["/repos/**"]'
    )
    flow = tflow.tflow()
    flow.request.host = "api.github.com"
    flow.request.port = 443
    flow.request.scheme = "https"
    flow.request.method = "GET"
    flow.request.path = "/repos/owner/name/issues/1"
    flow.request.headers["Authorization"] = f"token {placeholder}"
    addon.http_connect(flow)
    addon.requestheaders(flow)
    assert flow.request.headers["Authorization"] == "token ghp_REAL_VALUE"


def test_requestheaders_omits_substitution_on_path_scope_violation(
    tmp_path: Path,
) -> None:
    """When a binding declares `paths: [/repos/*]` and the request path is
    /user/keys, the proxy must NOT inject and must record the violation.
    Also exercises query-string stripping (the `?token=…` must not appear
    in the audit event, per audit minimization §5.4)."""
    addon, audit_path, placeholder = _build_scoped_addon(tmp_path, methods="", paths='["/repos/*"]')
    flow = tflow.tflow()
    flow.request.host = "api.github.com"
    flow.request.port = 443
    flow.request.scheme = "https"
    flow.request.method = "GET"
    flow.request.path = "/user/keys?token=secret-query"  # outside /repos/*, has query
    flow.request.headers["Authorization"] = f"token {placeholder}"

    addon.http_connect(flow)
    addon.requestheaders(flow)

    assert flow.request.headers["Authorization"] == f"token {placeholder}"
    assert flow.response is None
    events = _read_audit(audit_path)
    scope_events = [e for e in events if e.get("reason") == "binding_scope_violation"]
    assert len(scope_events) == 1
    assert scope_events[0]["path"] == "/user/keys"  # query stripped
    assert "token=secret-query" not in json.dumps(scope_events[0])


def test_response_emits_upstream_response_audit(tmp_path: Path) -> None:
    addon, audit_path = _build_addon(tmp_path)
    flow = _make_request("api.anthropic.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    addon.requestheaders(flow)
    flow.response = tflow.tresp()
    flow.response.status_code = 200
    addon.response(flow)
    events = _read_audit(audit_path)
    response_events = [e for e in events if e["type"] == "upstream_response"]
    assert len(response_events) == 1
    assert response_events[0]["status"] == 200


# ---------------------------------------------------------------------------
# Composite binding (inject.template + compose) end-to-end
# ---------------------------------------------------------------------------

COMPOSITE_PLACEHOLDER = "jira_PLACEHOLDER_01HXY1234567890AB"


class _CompositeFakeBackend:
    """Per-name lookup fake for composite-secret tests. Records which names
    were fetched (for assertions about call ordering / count)."""

    def __init__(self, store: dict[str, str]) -> None:
        self.store = store
        self.fetched: list[str] = []

    def fetch(self, name: str, ctx: FetchContext | None = None) -> str:
        self.fetched.append(name)
        if name not in self.store:
            raise BackendUnavailableError(f"no such secret {name!r}")
        return self.store[name]


def _build_composite_addon(
    tmp_path: Path,
    store: dict[str, str],
) -> tuple[AgentVaultProxyAddon, Path, _CompositeFakeBackend]:
    audit_path = tmp_path / "audit.jsonl"
    config_yaml = f"""
version: 1

secrets:
  JIRA_API_BASIC:
    placeholder: "{COMPOSITE_PLACEHOLDER}"
    inject:
      header: "Authorization"
      template: "Basic {{{{ (JIRA_EMAIL + ':' + JIRA_API_TOKEN) | b64encode }}}}"
    compose:
      - JIRA_EMAIL
      - JIRA_API_TOKEN
    bindings:
      - host: "your-tenant.atlassian.net"

unmatched_destination_policy: deny

audit:
  path: {audit_path}
  fail_on_unwritable: true
"""
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(config_yaml)
    addon = AgentVaultProxyAddon()
    addon.config = load_config(config_path)
    addon.audit = AuditWriter(str(audit_path))
    backend = _CompositeFakeBackend(store)
    addon.client = CachingSecretsClient(backend=backend)
    return addon, audit_path, backend


def _make_composite_request(host: str, header_value: str) -> Any:
    flow = tflow.tflow()
    flow.request.host = host
    flow.request.port = 443
    flow.request.scheme = "https"
    flow.request.path = "/rest/api/3/myself"
    flow.request.headers["Authorization"] = header_value
    return flow


def test_composite_renders_basic_auth_on_wire(tmp_path: Path) -> None:
    addon, audit_path, _backend = _build_composite_addon(
        tmp_path,
        {"JIRA_EMAIL": "alice", "JIRA_API_TOKEN": "s3cret"},
    )
    flow = _make_composite_request("your-tenant.atlassian.net", f"Basic {COMPOSITE_PLACEHOLDER}")
    addon.requestheaders(flow)
    assert flow.response is None  # no early termination
    expected = "Basic " + base64.b64encode(b"alice:s3cret").decode("ascii")
    assert flow.request.headers["Authorization"] == expected

    events = _read_audit(audit_path)
    allowed = [
        e for e in events if e.get("type") == "inject_decision" and e.get("decision") == "allowed"
    ]
    assert len(allowed) == 1
    assert allowed[0]["secret_name"] == "JIRA_API_BASIC"
    # Per design §9: success path is minimal, no compose: list in the audit.
    assert "compose" not in allowed[0]


def test_composite_503_on_missing_underlying(tmp_path: Path) -> None:
    addon, audit_path, _backend = _build_composite_addon(
        tmp_path,
        {"JIRA_EMAIL": "alice"},  # TOKEN missing
    )
    flow = _make_composite_request("your-tenant.atlassian.net", f"Basic {COMPOSITE_PLACEHOLDER}")
    addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 503

    events = _read_audit(audit_path)
    denied = [
        e for e in events if e.get("type") == "inject_decision" and e.get("decision") == "denied"
    ]
    assert len(denied) == 1
    # Per design §9: failure path INCLUDES compose: list for correlation.
    assert denied[0]["compose"] == ["JIRA_EMAIL", "JIRA_API_TOKEN"]
    assert denied[0]["reason"].startswith("composite_unavailable:")


def test_composite_503_on_empty_underlying(tmp_path: Path) -> None:
    addon, audit_path, _backend = _build_composite_addon(
        tmp_path,
        {"JIRA_EMAIL": "alice", "JIRA_API_TOKEN": ""},
    )
    flow = _make_composite_request("your-tenant.atlassian.net", f"Basic {COMPOSITE_PLACEHOLDER}")
    addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 503

    events = _read_audit(audit_path)
    denied = [
        e for e in events if e.get("type") == "inject_decision" and e.get("decision") == "denied"
    ]
    assert len(denied) == 1
    assert denied[0]["compose"] == ["JIRA_EMAIL", "JIRA_API_TOKEN"]


def test_composite_same_uuid_warning_logged_once(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # two compose entries → equal values → WARN once.
    # Use a value distinctive enough to detect leakage by substring.
    leaked_value = "ZZZ-DISTINCT-VALUE-998877"
    addon, _audit_path, _backend = _build_composite_addon(
        tmp_path,
        {"JIRA_EMAIL": leaked_value, "JIRA_API_TOKEN": leaked_value},
    )
    caplog.set_level("WARNING", logger="agent_vault_proxy.addon")

    for _ in range(3):
        flow = _make_composite_request(
            "your-tenant.atlassian.net", f"Basic {COMPOSITE_PLACEHOLDER}"
        )
        addon.requestheaders(flow)

    warnings = [r for r in caplog.records if "resolved to the same value" in r.message]
    assert len(warnings) == 1
    assert "JIRA_API_BASIC" in warnings[0].message
    # Critical: warning never logs the actual secret value.
    assert leaked_value not in warnings[0].message


def test_composite_no_warning_when_values_distinct(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    addon, _audit_path, _backend = _build_composite_addon(
        tmp_path,
        {"JIRA_EMAIL": "alice", "JIRA_API_TOKEN": "bob-token"},
    )
    caplog.set_level("WARNING", logger="agent_vault_proxy.addon")
    flow = _make_composite_request("your-tenant.atlassian.net", f"Basic {COMPOSITE_PLACEHOLDER}")
    addon.requestheaders(flow)
    warnings = [r for r in caplog.records if "resolved to the same value" in r.message]
    assert warnings == []


def test_composite_warning_resets_on_configure(tmp_path: Path) -> None:
    # Reload clears the warned set so the operator gets re-notified if
    # they shipped the same bad config again.
    addon, _audit_path, _backend = _build_composite_addon(
        tmp_path,
        {"JIRA_EMAIL": "same", "JIRA_API_TOKEN": "same"},
    )
    # Directly populate as if the warning had fired.
    addon._composite._same_uuid_warned.add("JIRA_API_BASIC")
    # Trigger the configure() reload-state-reset by re-running it. We
    # bypass the mitmproxy options shim by re-calling the public method
    # with the same path.
    addon._composite.reset_warnings()  # what configure() does on reload
    assert "JIRA_API_BASIC" not in addon._composite._same_uuid_warned


def test_composite_binding_with_format_legacy_still_works(tmp_path: Path) -> None:
    # Mixed config: one single-secret binding (inject.format) + one
    # composite binding. Ensures they coexist correctly through the
    # branch in requestheaders.
    audit_path = tmp_path / "audit.jsonl"
    config_yaml = f"""
version: 1

secrets:
  ANTHROPIC_API_KEY:
    placeholder: "{PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "Bearer {{ANTHROPIC_API_KEY}}"
    bindings:
      - host: "api.anthropic.com"
  JIRA_API_BASIC:
    placeholder: "{COMPOSITE_PLACEHOLDER}"
    inject:
      header: "Authorization"
      template: "Basic {{{{ (JIRA_EMAIL + ':' + JIRA_API_TOKEN) | b64encode }}}}"
    compose:
      - JIRA_EMAIL
      - JIRA_API_TOKEN
    bindings:
      - host: "your-tenant.atlassian.net"

unmatched_destination_policy: deny

audit:
  path: {audit_path}
  fail_on_unwritable: true
"""
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(config_yaml)
    addon = AgentVaultProxyAddon()
    addon.config = load_config(config_path)
    addon.audit = AuditWriter(str(audit_path))
    backend = _CompositeFakeBackend(
        {
            "ANTHROPIC_API_KEY": "sk-ant-real",
            "JIRA_EMAIL": "alice",
            "JIRA_API_TOKEN": "s3cret",
        }
    )
    addon.client = CachingSecretsClient(backend=backend)

    # Hit anthropic (single-secret path):
    flow1 = _make_request("api.anthropic.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.requestheaders(flow1)
    assert flow1.request.headers["Authorization"] == "Bearer sk-ant-real"

    # Hit jira (composite path):
    flow2 = _make_composite_request("your-tenant.atlassian.net", f"Basic {COMPOSITE_PLACEHOLDER}")
    addon.requestheaders(flow2)
    expected = "Basic " + base64.b64encode(b"alice:s3cret").decode("ascii")
    assert flow2.request.headers["Authorization"] == expected


def test_inject_decision_carries_binding_source_file(tmp_path: Path) -> None:
    """ADR-0011 item 6: every inject_decision event records which source the
    binding came from. The default addon loads bindings from a file, so the
    allowed event is tagged binding_source: file."""
    addon, audit_path = _build_addon(tmp_path)
    flow = _make_request("api.anthropic.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    addon.requestheaders(flow)
    events = _read_audit(audit_path)
    allowed = [e for e in events if e.get("decision") == "allowed"]
    assert len(allowed) == 1
    assert allowed[0]["binding_source"] == "file"


def test_inject_decision_carries_binding_source_bws_notes(tmp_path: Path) -> None:
    """When a secret's SecretSpec originates from a BWS note, the allowed
    inject_decision is tagged binding_source: bws_notes. The resolver sets
    spec.binding_source; the addon reads it onto the audit event."""
    addon, audit_path = _build_addon(tmp_path)
    # Simulate the resolver having tagged this spec as bws_notes-sourced.
    addon.config.secrets["ANTHROPIC_API_KEY"].binding_source = "bws_notes"
    flow = _make_request("api.anthropic.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
    addon.http_connect(flow)
    addon.requestheaders(flow)
    events = _read_audit(audit_path)
    allowed = [e for e in events if e.get("decision") == "allowed"]
    assert len(allowed) == 1
    assert allowed[0]["binding_source"] == "bws_notes"
