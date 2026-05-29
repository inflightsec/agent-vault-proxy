from __future__ import annotations

import logging
import threading
import uuid
from pathlib import Path

from mitmproxy import http
from mitmproxy.addonmanager import Loader

from agent_vault_proxy.audit import AuditWriter
from agent_vault_proxy.backends import BackendUnavailableError, SecretNotFoundError
from agent_vault_proxy.caching import CachingSecretsClient
from agent_vault_proxy.config import BindingSpec, Config, SecretSpec, build_backend, load_config
from agent_vault_proxy.matching import host_matches_pattern
from agent_vault_proxy.template import TemplateRenderError

_log = logging.getLogger("agent_vault_proxy.addon")


class AgentVaultProxyAddon:
    def __init__(self) -> None:
        self.config: Config | None = None
        # CachingSecretsClient wrapping whichever backend bindings.yaml selected.
        # Kept generic so future backends (1Password, Vault, etc.) plug in here.
        self.client: CachingSecretsClient | None = None
        self.audit: AuditWriter | None = None
        # Silas F4 corollary: tracks composite bindings that have already
        # logged the same-UUID warning. Logging once per binding (not per
        # request) keeps the signal high and the log volume reasonable.
        self._same_uuid_warned: set[str] = set()
        self._warned_lock = threading.Lock()

    def load(self, loader: Loader) -> None:
        loader.add_option(
            name="avp_config",
            typespec=str,
            default="/etc/agent-vault-proxy/bindings.yaml",
            help="Path to agent-vault-proxy bindings.yaml",
        )

    def configure(self, updated: set[str]) -> None:
        if "avp_config" not in updated and self.config is not None:
            return
        from mitmproxy.ctx import options

        config_path = Path(options.avp_config)
        # Silas F3: build the full new state BEFORE assigning to self.
        # Each individual attribute assignment is atomic at the Python
        # bytecode level (STORE_ATTR), so the worst a concurrent request
        # handler can see is one consistent (config, client, audit) tuple
        # mixed with one stale one (where the per-handler snapshot at the
        # top of requestheaders/http_connect captures a frozen reference
        # for the rest of that request — see _capture_state).
        new_config = load_config(config_path)
        backend, _ = build_backend(new_config)
        new_client = CachingSecretsClient(
            backend=backend,
            ttl_seconds=new_config.cache.ttl_seconds,
            jitter_seconds=new_config.cache.jitter_seconds,
            max_entries=new_config.cache.max_entries,
        )
        new_audit = AuditWriter(
            path=new_config.audit.path,
            fail_on_unwritable=new_config.audit.fail_on_unwritable,
        )
        # Reset the same-UUID warning set on reload — operator may have
        # corrected the misconfigured binding; let the warning re-fire
        # if the new config still has the issue.
        with self._warned_lock:
            self._same_uuid_warned.clear()
        # Publish all three. Reads from request handlers are captured
        # once at handler entry so a partial publish here cannot tear
        # a single in-flight request's view.
        self.config = new_config
        self.client = new_client
        self.audit = new_audit

    def _capture_state(
        self,
    ) -> tuple[Config | None, CachingSecretsClient | None, AuditWriter | None]:
        """Snapshot (config, client, audit) at handler entry. Each individual
        attribute read is atomic; the per-handler snapshot prevents using
        a new config with an old client (or vice versa) within one request."""
        return self.config, self.client, self.audit

    def running(self) -> None:
        # Mitmproxy calls this once after addons are wired up and the proxy
        # is about to accept connections.
        #
        # Order matters (Oracle C1): run the security preflight FIRST.
        # One of the checks is "audit log lacks chattr +a" — emitting the
        # proxy_restart event before that check would write into a
        # potentially mutable log we're about to warn about. If preflight
        # is in strict mode and a warning fires, it raises and aborts
        # startup before any audit emission too.
        if self.config is not None:
            from agent_vault_proxy._preflight import emit_preflight

            emit_preflight(self.config)
        # Now emit the startup record — closes G9's "restart itself
        # is audited" half (the "history preserved" half comes from chattr +a).
        if self.audit is not None:
            self.audit.emit({"type": "proxy_restart"})

    def http_connect(self, flow: http.HTTPFlow) -> None:
        config, _client, audit = self._capture_state()
        if config is None or audit is None:
            return
        target_host = flow.request.pretty_host
        if _destination_in_any_binding(config, target_host):
            flow.metadata["avp_request_id"] = str(uuid.uuid4())
            flow.metadata["avp_connect_host"] = target_host
            return
        if config.unmatched_destination_policy == "deny":
            audit.emit(
                {
                    "type": "deny",
                    "reason": "unmatched_destination",
                    "destination": {"host": target_host, "port": flow.request.port},
                }
            )
            flow.response = http.Response.make(
                403,
                b"agent-vault-proxy: destination not in any binding\n",
                {"Content-Type": "text/plain"},
            )

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        # Snapshot (config, client, audit) at handler entry — Silas F3.
        # Any subsequent configure() call publishes a new triple that this
        # request will never see.
        config, client, audit = self._capture_state()
        if config is None or client is None or audit is None:
            return
        request_id = flow.metadata.get("avp_request_id") or str(uuid.uuid4())
        flow.metadata["avp_request_id"] = request_id

        target_host = flow.request.pretty_host
        connect_host = flow.metadata.get("avp_connect_host")
        if connect_host and connect_host != target_host:
            audit.emit(
                {
                    "type": "deny",
                    "request_id": request_id,
                    "reason": "sni_host_mismatch",
                    "destination": {"connect_host": connect_host, "request_host": target_host},
                }
            )
            flow.response = http.Response.make(
                403,
                b"agent-vault-proxy: CONNECT host and request host disagree\n",
                {"Content-Type": "text/plain"},
            )
            return

        # Destination allow-list — enforced unconditionally here, not just at
        # http_connect, so plain HTTP (no CONNECT) can't be used as an open
        # relay to hosts outside the binding set.
        if config.unmatched_destination_policy == "deny" and not _destination_in_any_binding(
            config, target_host
        ):
            audit.emit(
                {
                    "type": "deny",
                    "request_id": request_id,
                    "reason": "unmatched_destination",
                    "destination": {"host": target_host, "port": flow.request.port},
                }
            )
            flow.response = http.Response.make(
                403,
                b"agent-vault-proxy: destination not in any binding\n",
                {"Content-Type": "text/plain"},
            )
            return

        match = _find_placeholder_in_headers(config, flow)
        if match is None:
            return
        secret_name, secret_spec, header_name, header_value = match

        matched_binding = _matched_binding(target_host, secret_spec)
        if matched_binding is None:
            audit.emit(
                {
                    "type": "inject_decision",
                    "request_id": request_id,
                    "decision": "denied",
                    "reason": "destination_not_in_binding",
                    "secret_name": secret_name,
                    "destination": {"host": target_host, "port": flow.request.port},
                }
            )
            return

        request_method = flow.request.method.upper()
        request_path = flow.request.path.split("?", 1)[0]
        if not matched_binding.matches_scope(request_method, request_path):
            audit.emit(
                {
                    "type": "inject_decision",
                    "request_id": request_id,
                    "decision": "denied",
                    "reason": "binding_scope_violation",
                    "secret_name": secret_name,
                    "destination": {"host": target_host, "port": flow.request.port},
                    "method": request_method,
                    "path": request_path,
                }
            )
            return

        # Branch on composite vs single-secret. config-load guarantees that
        # exactly one of the two paths applies (inject.format ⊕ inject.template).
        if secret_spec.compose is not None:
            rendered_value = self._fetch_and_render_composite(
                client=client,
                audit=audit,
                request_id=request_id,
                target_host=target_host,
                flow=flow,
                secret_name=secret_name,
                secret_spec=secret_spec,
            )
            if rendered_value is None:
                return  # response already set + audit emitted
            new_header_value = rendered_value
        else:
            assert secret_spec.inject.format is not None
            try:
                real_secret = client.get(secret_name)
            except (BackendUnavailableError, SecretNotFoundError) as e:
                audit.emit(
                    {
                        "type": "inject_decision",
                        "request_id": request_id,
                        "decision": "denied",
                        "reason": f"secret_unavailable:{type(e).__name__}",
                        "secret_name": secret_name,
                        "destination": {"host": target_host, "port": flow.request.port},
                    }
                )
                flow.response = http.Response.make(
                    503,
                    b"agent-vault-proxy: secret unavailable\n",
                    {"Content-Type": "text/plain"},
                )
                return
            # Use .replace() not .format() — Python's str.format() permits attribute
            # access via {field.__class__.…}, so a hostile or buggy bindings.yaml
            # could traverse internals of the secret string. .replace() can only
            # do a literal substitution, full stop.
            new_header_value = secret_spec.inject.format.replace("{secret}", real_secret)

        flow.request.headers[header_name] = new_header_value

        # G6 ORDERING — DO NOT REORDER. mitmproxy does not write the request
        # to the upstream socket until requestheaders() returns. The header
        # mutation above is an in-memory dict update on flow.request only;
        # no bytes leave the proxy until this function returns. audit.emit()
        # below performs a synchronous fsync (see audit.py), so by the time
        # this function returns, the inject_decision event is durable on
        # disk. Do NOT move audit.emit() to a thread/queue, do NOT defer it
        # past return, and do NOT add a `return` between the mutation and
        # the emit — any of those would break G6 invisibly.
        #
        # Hot-path audit on success — minimal, no compose: list. Per design
        # §9, the compose list appears only on flush events and failure
        # paths (the failure path emits it inside _fetch_and_render_composite).
        audit.emit(
            {
                "type": "inject_decision",
                "request_id": request_id,
                "decision": "allowed",
                "reason": "binding_matched",
                "secret_name": secret_name,
                "destination": {
                    "host": target_host,
                    "port": flow.request.port,
                    "path_prefix": flow.request.path.split("?", 1)[0][:64],
                },
            }
        )

    def _fetch_and_render_composite(
        self,
        *,
        client: CachingSecretsClient,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
        flow: http.HTTPFlow,
        secret_name: str,
        secret_spec: SecretSpec,
    ) -> str | None:
        """Composite-binding fetch + render path. Returns the rendered header
        value on success, or None after writing a 503 response + audit entry
        on failure. Failure-path audit includes the compose: list so an
        operator can correlate flush events with affected composites."""
        assert secret_spec.compose is not None
        assert secret_spec.compiled_template is not None

        try:
            values = client.composite_fetch(secret_spec.compose)
        except (BackendUnavailableError, SecretNotFoundError) as e:
            # Silas-confirmed audit shape: compose: list included on failure.
            audit.emit(
                {
                    "type": "inject_decision",
                    "request_id": request_id,
                    "decision": "denied",
                    "reason": f"composite_unavailable:{type(e).__name__}",
                    "secret_name": secret_name,
                    "compose": list(secret_spec.compose),
                    "destination": {"host": target_host, "port": flow.request.port},
                }
            )
            flow.response = http.Response.make(
                503,
                b"agent-vault-proxy: composite secret unavailable\n",
                {"Content-Type": "text/plain"},
            )
            return None

        # Silas F4 corollary: warn once per binding when two different
        # named entries resolve to equal values (likely operator typo
        # pointing two compose entries at the same BWS UUID). The values
        # themselves are NEVER logged — only the binding name.
        self._maybe_warn_same_uuid(secret_name, values)

        try:
            rendered = secret_spec.compiled_template.render(values)
        except TemplateRenderError as exc:
            # Oracle C7: audit message stays generic ("render_failed") so
            # the agent boundary can't observe compose-internal details
            # via the inject_decision event. Detailed exception text goes
            # to the proxy's own logger (root-readable on framework).
            _log.warning(
                "composite render failed for binding %s: %s",
                secret_name,
                exc,
            )
            audit.emit(
                {
                    "type": "inject_decision",
                    "request_id": request_id,
                    "decision": "denied",
                    "reason": "render_failed",
                    "secret_name": secret_name,
                    "compose": list(secret_spec.compose),
                    "destination": {"host": target_host, "port": flow.request.port},
                }
            )
            flow.response = http.Response.make(
                503,
                b"agent-vault-proxy: composite render failed\n",
                {"Content-Type": "text/plain"},
            )
            return None

        return rendered

    def _maybe_warn_same_uuid(
        self,
        secret_name: str,
        values: dict[str, str],
    ) -> None:
        """Silas F4 corollary: if two distinctly-named compose entries
        resolve to the same value, log a one-shot warning. Suggests an
        operator typo (two names pointing at one BWS UUID). Does NOT fail
        the request — there are legitimate edge cases (e.g., service
        account where username == password)."""
        if len(values) < 2:
            return
        with self._warned_lock:
            if secret_name in self._same_uuid_warned:
                return
        # O(n²) is fine for n ≤ 4 per the cap.
        names = list(values.keys())
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                if values[names[i]] == values[names[j]]:
                    with self._warned_lock:
                        self._same_uuid_warned.add(secret_name)
                    _log.warning(
                        "composite binding %s: distinct compose entries "
                        "%s and %s resolved to the same value — likely an "
                        "operator typo pointing both at one BWS secret. "
                        "Composite is degraded.",
                        secret_name,
                        names[i],
                        names[j],
                    )
                    return

    def response(self, flow: http.HTTPFlow) -> None:
        if self.audit is None or flow.response is None:
            return
        request_id = flow.metadata.get("avp_request_id")
        if request_id is None:
            return
        self.audit.emit(
            {
                "type": "upstream_response",
                "request_id": request_id,
                "status": flow.response.status_code,
            }
        )


def _destination_in_any_binding(config: Config, host: str) -> bool:
    return any(_matched_binding(host, spec) is not None for spec in config.secrets.values())


def _matched_binding(host: str, spec: SecretSpec) -> BindingSpec | None:
    for b in spec.bindings:
        if host_matches_pattern(host, b.host):
            return b
    return None


def _find_placeholder_in_headers(
    config: Config, flow: http.HTTPFlow
) -> tuple[str, SecretSpec, str, str] | None:
    for secret_name, spec in config.secrets.items():
        target_header = spec.inject.header
        value = flow.request.headers.get(target_header)
        if value and spec.placeholder in value:
            return secret_name, spec, target_header, value
    return None


addons = [AgentVaultProxyAddon()]
