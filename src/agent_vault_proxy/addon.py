from __future__ import annotations

import logging
import uuid
from pathlib import Path

from mitmproxy import http
from mitmproxy.addonmanager import Loader

from agent_vault_proxy._derived_token_cache import DerivedTokenCache
from agent_vault_proxy._healthz import healthz_response, is_healthz_request
from agent_vault_proxy.audit import (
    REASON_HOST_NOT_IN_ALLOWLIST,
    REASON_INVALID_BINDING_METADATA,
    REASON_NO_BINDING_IN_NOTES,
    AuditWriter,
)
from agent_vault_proxy.caching import CachingSecretsClient
from agent_vault_proxy.config import (
    Config,
    build_backend,
    load_config,
)
from agent_vault_proxy.handlers import (
    BodyInjectionHandler,
    CompositeResolver,
    HeaderInjectionHandler,
    NotesActivator,
)
from agent_vault_proxy.injectors.oauth2_refresh import OauthResolver
from agent_vault_proxy.policy import (
    decide,
    destination_in_any_binding,
)

_log = logging.getLogger("agent_vault_proxy.addon")


class AgentVaultProxyAddon:
    def __init__(self) -> None:
        self.config: Config | None = None
        # CachingSecretsClient wrapping whichever backend bindings.yaml selected.
        # Kept generic so future backends (1Password, Vault, etc.) plug in here.
        self.client: CachingSecretsClient | None = None
        self.audit: AuditWriter | None = None
        # BWS-notes activation state (ADR-0011). Populated in bws_notes/both
        # mode by configure(); empty/None in file mode. The request path
        # consults these to fail closed on a placeholder whose secret has no
        # binding (no spec) with the right audit reason.
        #   _placeholder_to_name: derived placeholder -> secret_name for EVERY
        #     listed BWS secret (bound, no-binding, or invalid).
        #   _no_binding_names / _invalid_names: the audit-reason split.
        self._placeholder_to_name: dict[str, str] = {}
        self._no_binding_names: set[str] = set()
        self._invalid_names: set[str] = set()
        # ADR-0024: names whose notes binding was dropped WHOLE by the
        # file-side notes_host_allowlist (no approved host remained) — the
        # pre-step attributes their placeholders as host_not_in_allowlist.
        # Partial rejections live on the header handler's
        # allowlist_rejected_hosts map instead (spec stays live).
        self._allowlist_rejected_names: set[str] = set()
        self._companion_headers: dict[str, dict[str, str]] = {}
        # Derived-token cache for the oauth2_refresh resolution step
        # (ADR-0017 §3 / §11). Sibling of ``self.client`` — vault secrets
        # and exchanged access tokens have incompatible flush/list/audit
        # semantics, so they live in separate caches. One instance per
        # addon, rebuilt on every ``configure_from_path`` so a config
        # reload starts with a cold derived-token cache.
        self._token_cache: DerivedTokenCache | None = None
        # Request-path handlers (see handlers.py). The composite resolver is
        # shared header+body so the same-UUID warning fires once per binding
        # across both paths; its warning set is reset on every reload.
        self._composite = CompositeResolver()
        self._header_handler = HeaderInjectionHandler(
            composite=self._composite,
            oauth_resolver=OauthResolver(),
        )
        self._body_handler = BodyInjectionHandler(composite=self._composite)
        self._notes_activator = NotesActivator()

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

        self.configure_from_path(options.avp_config)

    def configure_from_path(
        self,
        config_path: str | Path,
        *,
        backend_override: object | None = None,
    ) -> None:
        """Load config + (re)build the live state.

        Split out from :meth:`configure` so it can be driven directly in
        tests (and any non-mitmproxy harness) without the ctx.options shim.
        ``backend_override`` substitutes a backend instance for the one
        ``build_backend`` would construct — used by tests to inject a fake
        BWS backend; production passes None.
        """
        config_path = Path(config_path)
        # Snapshot pattern: build the full new state BEFORE assigning to
        # self. STORE_ATTR is atomic, so the worst a concurrent handler
        # sees is one fresh component mixed with a stale one — and the
        # per-handler snapshot in _capture_state freezes the tuple for
        # the rest of that request.
        new_config = load_config(config_path)
        if backend_override is not None:
            backend: object = backend_override
        else:
            backend, _ = build_backend(new_config)

        # BWS-notes activation (ADR-0011 item 3). In bws_notes/both mode we
        # resolve bindings from BWS secret notes and MERGE them into the
        # config's secrets map (notes win over file). file mode is left
        # completely untouched — no BWS listing, identical to pre-ADR-0011.
        new_placeholder_to_name: dict[str, str] = {}
        new_no_binding: set[str] = set()
        new_invalid: set[str] = set()
        new_allowlist_rejected: set[str] = set()
        new_allowlist_rejected_hosts: dict[str, set[str]] = {}
        new_companion_headers: dict[str, dict[str, str]] = {}
        if new_config.binding_source != "file":
            self._notes_activator.activate(
                new_config=new_config,
                backend=backend,
                config_path=config_path,
                out_placeholder_to_name=new_placeholder_to_name,
                out_no_binding=new_no_binding,
                out_invalid=new_invalid,
                out_companion_headers=new_companion_headers,
                out_allowlist_rejected=new_allowlist_rejected,
                out_allowlist_rejected_hosts=new_allowlist_rejected_hosts,
            )

        new_client = CachingSecretsClient(
            backend=backend,  # type: ignore[arg-type]
            ttl_seconds=new_config.cache.ttl_seconds,
            jitter_seconds=new_config.cache.jitter_seconds,
            max_entries=new_config.cache.max_entries,
        )
        new_audit = AuditWriter(
            path=new_config.audit.path,
            fail_on_unwritable=new_config.audit.fail_on_unwritable,
            # ADR-0019 §5: secret names flagged `honeytoken: true` so the
            # writer auto-emits the follow-up tripwire event. Built from the
            # merged secret set (notes activation above already ran), rebuilt
            # on every reload.
            honeytoken_names=frozenset(
                name for name, spec in new_config.secrets.items() if spec.honeytoken
            ),
        )
        # Reset the same-UUID warning set on reload — operator may have
        # corrected the misconfigured binding; let the warning re-fire
        # if the new config still has the issue.
        self._composite.reset_warnings()
        # Publish all state. Reads from request handlers are captured once at
        # handler entry so a partial publish here cannot tear a single
        # in-flight request's view. Publish the no-binding/invalid maps
        # BEFORE config so a handler that sees the new config also sees the
        # matching attribution maps (config is the last write).
        self._placeholder_to_name = new_placeholder_to_name
        self._no_binding_names = new_no_binding
        self._invalid_names = new_invalid
        self._allowlist_rejected_names = new_allowlist_rejected
        # Partial-rejection map rides on the header handler (consulted at
        # the deny site); atomic attribute swap, same publish ordering.
        self._header_handler.allowlist_rejected_hosts = new_allowlist_rejected_hosts
        self._companion_headers = new_companion_headers
        self.client = new_client
        self.audit = new_audit
        self.config = new_config
        # Fresh derived-token cache on every (re)load. Stale access
        # tokens from a prior config could otherwise outlive the
        # binding shape that minted them.
        self._token_cache = DerivedTokenCache()

    def _capture_state(
        self,
    ) -> tuple[
        Config | None,
        CachingSecretsClient | None,
        AuditWriter | None,
        dict[str, dict[str, str]],
    ]:
        """Snapshot (config, client, audit) at handler entry. Each individual
        attribute read is atomic; the per-handler snapshot prevents using
        a new config with an old client (or vice versa) within one request."""
        return self.config, self.client, self.audit, self._companion_headers

    def running(self) -> None:
        # Mitmproxy calls this once after addons are wired up and the proxy
        # is about to accept connections.
        #
        # Order matters: run the security preflight FIRST.
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
        config, _client, audit, _companion_headers = self._capture_state()
        if config is None or audit is None:
            return
        target_host = flow.request.pretty_host
        if destination_in_any_binding(config, target_host):
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
        # Three-stage pipeline at the same hook (P0.6):
        #
        # 1. Shared deny gates (SNI consistency, destination allow-list) —
        #    if they fire, flow.response is set and we abort.
        # 2. Header injection — one header per request gets substituted
        #    (or audited+denied) in :meth:`_execute_header_decision`, driven
        #    by the pure :func:`agent_vault_proxy.policy.decide` verdict.
        # 3. Body injection streaming setup — for hosts with body bindings,
        #    attach a streaming replacer to ``flow.request.stream`` so the
        #    body never buffers in memory. Chunked transfer encoding lets
        #    AVP emit modified bytes as they arrive without knowing the
        #    final body length in advance.
        #
        # Stages 2 and 3 can fire in the same request when different
        # secrets bind header + body on the same host. They never share
        # a secret in P0.6 — composite header+body injection lands with
        # MultiInjector in P0.7.
        #
        # Liveness/readiness probe (roadmap: Observability). Answered here,
        # BEFORE the destination allow-list, so the probe is not 403'd as an
        # unmatched destination; never proxied upstream and emits no audit
        # (health polling would otherwise flood the log). Ready = fully
        # configured (config + client + audit all published by configure()).
        if is_healthz_request(flow):
            flow.response = healthz_response(
                ready=(
                    self.config is not None and self.client is not None and self.audit is not None
                )
            )
            return
        #
        # Snapshot (config, client, audit) at handler entry. Any concurrent
        # configure() publishes a new triple that this request will never see.
        config, client, audit, companion_headers = self._capture_state()
        if config is None or client is None or audit is None:
            return
        request_id = flow.metadata.get("avp_request_id") or str(uuid.uuid4())
        flow.metadata["avp_request_id"] = request_id

        target_host = flow.request.pretty_host
        connect_host = flow.metadata.get("avp_connect_host")
        method = flow.request.method.upper()
        path = flow.request.path.split("?", 1)[0]

        # Pure policy verdict (ADR-0013). decide() does no I/O and no flow
        # mutation; this method EXECUTES the verdict — the fetch/render/inject
        # and the G6-ordered audit live in _execute_header_decision, unchanged.
        decision = decide(
            config=config,
            host=target_host,
            port=flow.request.port,
            method=method,
            path=path,
            connect_host=connect_host,
            header_get=flow.request.headers.get,
        )

        # Hard pre-gates (SNI consistency, destination allow-list) abort with a
        # 4xx and fire BEFORE the unbound-placeholder audit — preserving the
        # original ordering. These emit ``type: deny``.
        if decision.reason in ("sni_host_mismatch", "unmatched_destination"):
            audit.emit(
                {
                    "type": "deny",
                    "request_id": request_id,
                    "reason": decision.reason,
                    "destination": decision.extra["destination"],
                }
            )
            assert decision.response_status is not None
            assert decision.response_body is not None
            flow.response = http.Response.make(
                decision.response_status,
                decision.response_body,
                {"Content-Type": "text/plain"},
            )
            return

        # BWS-notes fail-closed gate (ADR-0011): a placeholder for a secret
        # with NO binding (or a malformed one) has no SecretSpec, so the header
        # verdict never matches it and it forwards verbatim. We AUDIT it with
        # the precise reason so the operator sees the typo/no-binding rather
        # than silence. Pre-step; no-op in file mode.
        self._audit_unbound_placeholders(
            flow=flow,
            audit=audit,
            request_id=request_id,
            target_host=target_host,
        )

        # Execute the header verdict — may set flow.response on deny.
        self._header_handler.execute(
            flow=flow,
            decision=decision,
            client=client,
            audit=audit,
            request_id=request_id,
            target_host=target_host,
            companion_headers=companion_headers,
            token_cache=self._token_cache,
        )

        # Body streaming setup. Runs alongside header injection unless the
        # header path already set a response (request being aborted).
        if flow.response is None:
            self._body_handler.setup(
                flow=flow,
                config=config,
                client=client,
                audit=audit,
                request_id=request_id,
                target_host=target_host,
            )

    def _audit_unbound_placeholders(
        self,
        *,
        flow: http.HTTPFlow,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
    ) -> None:
        """Audit any request header carrying a placeholder for a no-binding or
        invalid-binding BWS secret (ADR-0011 fail-closed reasons).

        These secrets have no SecretSpec, so the header pipeline never matches
        them — the placeholder is forwarded verbatim (fail closed, no real
        value injected). This method ONLY adds the audit record with the
        precise reason; it does NOT set flow.response (forward-unmodified is
        the documented default — an egress firewall enforces actual blocking).
        Emits at most one event per affected secret per request.

        Snapshot the attribution maps once; they are replaced atomically by
        configure(), so a single read is a consistent view. No-op in file mode
        (the maps are empty).
        """
        placeholder_to_name = self._placeholder_to_name
        if not placeholder_to_name:
            return
        no_binding = self._no_binding_names
        invalid = self._invalid_names
        allowlist_rejected = self._allowlist_rejected_names
        seen: set[str] = set()
        for value in flow.request.headers.values():
            if not value:
                continue
            for placeholder, secret_name in placeholder_to_name.items():
                if secret_name in seen:
                    continue
                if placeholder not in value:
                    continue
                if secret_name in invalid:
                    reason = REASON_INVALID_BINDING_METADATA
                elif secret_name in allowlist_rejected:
                    # ADR-0024: every host in this secret's note was outside
                    # the file-side allowlist — the binding never activated.
                    reason = REASON_HOST_NOT_IN_ALLOWLIST
                elif secret_name in no_binding:
                    reason = REASON_NO_BINDING_IN_NOTES
                else:
                    # Has a real spec — handled by the header/body pipeline.
                    continue
                seen.add(secret_name)
                audit.emit(
                    {
                        "type": "inject_decision",
                        "request_id": request_id,
                        "decision": "denied",
                        "reason": reason,
                        "secret_name": secret_name,
                        "binding_source": "bws_notes",
                        "destination": {"host": target_host, "port": flow.request.port},
                    }
                )

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


addons = [AgentVaultProxyAddon()]
