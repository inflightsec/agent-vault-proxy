from __future__ import annotations

import logging
import threading
import uuid
from pathlib import Path

from mitmproxy import http
from mitmproxy.addonmanager import Loader

from agent_vault_proxy.audit import (
    REASON_INVALID_BINDING_METADATA,
    REASON_NO_BINDING_IN_NOTES,
    AuditWriter,
)
from agent_vault_proxy.backends import (
    BackendCannotListError,
    BackendUnavailableError,
    SecretNotFoundError,
)
from agent_vault_proxy.caching import CachingSecretsClient
from agent_vault_proxy.config import (
    BodyInjector,
    Config,
    SecretSpec,
    build_backend,
    iter_leaf_injectors,
    load_config,
)
from agent_vault_proxy.injectors.body import _build_body_replacer
from agent_vault_proxy.policy import (
    Decision,
    decide,
    destination_in_any_binding,
    matched_binding,
)
from agent_vault_proxy.template import TemplateRenderError

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
        self._companion_headers: dict[str, dict[str, str]] = {}
        # Tracks composite bindings that have already logged the same-UUID
        # warning. Once per binding (not per request) — signal stays high.
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
        new_companion_headers: dict[str, dict[str, str]] = {}
        if new_config.binding_source != "file":
            self._activate_bws_notes(
                new_config=new_config,
                backend=backend,
                config_path=config_path,
                out_placeholder_to_name=new_placeholder_to_name,
                out_no_binding=new_no_binding,
                out_invalid=new_invalid,
                out_companion_headers=new_companion_headers,
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
        )
        # Reset the same-UUID warning set on reload — operator may have
        # corrected the misconfigured binding; let the warning re-fire
        # if the new config still has the issue.
        with self._warned_lock:
            self._same_uuid_warned.clear()
        # Publish all state. Reads from request handlers are captured once at
        # handler entry so a partial publish here cannot tear a single
        # in-flight request's view. Publish the no-binding/invalid maps
        # BEFORE config so a handler that sees the new config also sees the
        # matching attribution maps (config is the last write).
        self._placeholder_to_name = new_placeholder_to_name
        self._no_binding_names = new_no_binding
        self._invalid_names = new_invalid
        self._companion_headers = new_companion_headers
        self.client = new_client
        self.audit = new_audit
        self.config = new_config

    def _activate_bws_notes(
        self,
        *,
        new_config: Config,
        backend: object,
        config_path: Path,
        out_placeholder_to_name: dict[str, str],
        out_no_binding: set[str],
        out_invalid: set[str],
        out_companion_headers: dict[str, dict[str, str]],
    ) -> None:
        """Resolve BWS-notes bindings and merge them into ``new_config``.

        Mutates ``new_config.secrets`` (notes specs win over file specs for
        the same name) and rebuilds the host index. Populates the three
        ``out_*`` collections so the request path can attribute and fail
        closed on no-binding / invalid placeholders.

        Collision / config errors remain hard failures. Salt-path/salt-file
        failures and backends that cannot list secrets degrade to file-only
        (`both`) or no bindings (`bws_notes`) so the daemon keeps serving
        without guessing or using insecure state.
        """
        from agent_vault_proxy.placeholders import (
            load_or_create_install_salt,
            resolve_install_salt_path,
        )
        from agent_vault_proxy.runtime_bindings import resolve_runtime_bindings

        try:
            salt_path = resolve_install_salt_path(new_config.install_salt_path)
            install_salt = load_or_create_install_salt(salt_path)
        except (OSError, RuntimeError, ValueError) as e:
            self._degrade_bws_notes_activation(
                new_config=new_config,
                reason=(
                    f"cannot use install salt at {new_config.install_salt_path or '<default>'}: "
                    f"{type(e).__name__}: {e}"
                ),
            )
            return

        try:
            resolved = resolve_runtime_bindings(
                backend=backend,
                binding_source=new_config.binding_source,
                install_salt=install_salt,
                file_config=new_config if new_config.binding_source == "both" else None,
            )
        except BackendCannotListError as e:
            self._degrade_bws_notes_activation(
                new_config=new_config,
                reason=f"backend cannot list secrets: {type(e).__name__}: {e}",
            )
            return

        file_specs = dict(new_config.secrets)

        # Merge resolved specs over the file-loaded secrets. The resolver has
        # ALREADY applied notes-over-file precedence within its own sources;
        # here we additionally let any resolved spec replace the matching
        # file entry in the live config (so the request path's single
        # config.secrets iteration sees the effective binding).
        if new_config.binding_source == "both":
            merged: dict[str, SecretSpec] = {
                name: spec for name, spec in file_specs.items() if name not in resolved.invalid
            }
        else:
            merged = {}
        for name, (spec, _source, companion) in resolved.specs.items():
            merged[name] = spec
            if companion:
                out_companion_headers[name] = dict(companion)
        new_config.secrets = merged
        # Re-assert the placeholder invariants over the MERGED set. config-load
        # validated only the file secrets; in `both` mode a derived placeholder
        # could in principle collide with / be a substring of a file one, which
        # would make the addon's `in` matching ambiguous. Fail closed at
        # configure() before serving rather than risk routing the wrong secret.
        from agent_vault_proxy.config import validate_placeholder_invariants

        validate_placeholder_invariants({name: spec.placeholder for name, spec in merged.items()})
        # Rebuild the host-keyed indices for the merged secret set — the
        # request path's destination matching reads these indices.
        new_config.rebuild_host_index()

        out_placeholder_to_name.update(resolved.placeholder_to_name)
        for name in resolved.invalid:
            file_spec = file_specs.get(name)
            if file_spec is not None:
                out_placeholder_to_name[file_spec.placeholder] = name
        out_no_binding.update(resolved.no_binding)
        out_invalid.update(resolved.invalid)

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
        #    body never buffers in memory. Mirrors superfly-tokenizer's
        #    ``InjectBodyProcessor`` (``processor.go:275-310``), which
        #    streams via ``icholy/replace.Chain`` with chunked transfer.
        #
        # Stages 2 and 3 can fire in the same request when different
        # secrets bind header + body on the same host. They never share
        # a secret in P0.6 — composite header+body injection lands with
        # MultiInjector in P0.7.
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
        self._execute_header_decision(
            flow=flow,
            decision=decision,
            client=client,
            audit=audit,
            request_id=request_id,
            target_host=target_host,
            companion_headers=companion_headers,
        )

        # Body streaming setup. Runs alongside header injection unless the
        # header path already set a response (request being aborted).
        if flow.response is None:
            self._setup_body_injection_streaming(
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

    def _execute_header_decision(  # noqa: C901
        self,
        *,
        flow: http.HTTPFlow,
        decision: Decision,
        client: CachingSecretsClient,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
        companion_headers: dict[str, dict[str, str]],
    ) -> None:
        """Execute the header verdict from :func:`decide`.

        decide() chose the branch (pure); this method performs the side
        effects: audit emission, secret fetch/render, header mutation. The
        allowed path keeps the G6 audit-before-write ordering verbatim — do
        not reorder. ``return`` ends the header path only; the caller runs
        body streaming unless this set ``flow.response``.
        """
        if decision.decision == "forward_unmodified":
            return

        if decision.reason == "ambiguous_placeholder_match":
            audit.emit(
                {
                    "type": "inject_decision",
                    "request_id": request_id,
                    "decision": "denied",
                    "reason": "ambiguous_placeholder_match",
                    "matched_secret_names": decision.extra["matched_secret_names"],
                    "destination": {"host": target_host, "port": flow.request.port},
                }
            )
            flow.response = http.Response.make(
                400,
                b"agent-vault-proxy: ambiguous placeholder match\n",
                {"Content-Type": "text/plain"},
            )
            return

        if decision.reason == "destination_not_in_binding":
            audit.emit(
                {
                    "type": "inject_decision",
                    "request_id": request_id,
                    "decision": "denied",
                    "reason": "destination_not_in_binding",
                    "secret_name": decision.secret_name,
                    "destination": {"host": target_host, "port": flow.request.port},
                }
            )
            return

        if decision.reason == "binding_scope_violation":
            audit.emit(
                {
                    "type": "inject_decision",
                    "request_id": request_id,
                    "decision": "denied",
                    "reason": "binding_scope_violation",
                    "secret_name": decision.secret_name,
                    "destination": {"host": target_host, "port": flow.request.port},
                    "method": decision.extra["method"],
                    "path": decision.extra["path"],
                }
            )
            return

        # Allowed — execute with the handles decide() resolved.
        secret_name = decision.secret_name
        secret_spec = decision.secret_spec
        header_injector = decision.header_injector
        header_name = decision.header_name
        assert secret_name is not None
        assert secret_spec is not None
        assert header_name is not None

        # Branch on composite vs single-secret. config-load guarantees that
        # exactly one of the two paths applies (inject.format XOR inject.template).
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
            assert header_injector is not None
            assert header_injector.format is not None
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
            except Exception as e:  # noqa: BLE001
                # G6 fail-closed: any uncaught backend exception MUST NOT result
                # in the placeholder being forwarded verbatim. Without this the
                # exception bubbles to mitmproxy, which logs it and forwards the
                # unmodified request — silently leaking the placeholder. Audit
                # reason is distinct from secret_unavailable: so operators can
                # grep the "unexpected backend bug" class separately.
                _log.exception(
                    "unexpected backend exception fetching %s: %s",
                    secret_name,
                    type(e).__name__,
                )
                audit.emit(
                    {
                        "type": "inject_decision",
                        "request_id": request_id,
                        "decision": "denied",
                        "reason": f"secret_fetch_error:{type(e).__name__}",
                        "secret_name": secret_name,
                        "destination": {"host": target_host, "port": flow.request.port},
                    }
                )
                flow.response = http.Response.make(
                    503,
                    b"agent-vault-proxy: secret fetch failed\n",
                    {"Content-Type": "text/plain"},
                )
                return
            # HeaderInjector.render_value() owns the substitution rule (named
            # form {<SECRET_NAME>} replaced with the resolved bytes via
            # .replace(), not .format() — no attribute-access traversal).
            new_header_value = header_injector.render_value(
                real_secret=real_secret,
                secret_name=secret_name,
            )

        flow.request.headers[header_name] = new_header_value
        # Companion headers (e.g. anthropic-version) are DEFAULTS, not
        # overrides: set them only when the client didn't already send one.
        for companion_name, companion_value in companion_headers.get(secret_name, {}).items():
            if companion_name not in flow.request.headers:
                flow.request.headers[companion_name] = companion_value

        # G6 ORDERING — DO NOT REORDER. mitmproxy does not write the request to
        # the upstream socket until requestheaders() returns. The header
        # mutation above is an in-memory update on flow.request only; no bytes
        # leave the proxy until this function returns. audit.emit() below does a
        # synchronous fsync (see audit.py), so the inject_decision event is
        # durable before any upstream write. Do NOT move audit.emit() to a
        # thread/queue, do NOT defer it past return, and do NOT add a return
        # between the mutation and the emit — any of those breaks G6 invisibly.
        audit.emit(
            {
                "type": "inject_decision",
                "request_id": request_id,
                "decision": "allowed",
                "reason": "binding_matched",
                "secret_name": secret_name,
                # ADR-0011 item 6: binding source ("file" | "bws_notes").
                "binding_source": secret_spec.binding_source,
                "destination": {
                    "host": target_host,
                    "port": flow.request.port,
                    "path_prefix": flow.request.path.split("?", 1)[0][:64],
                },
            }
        )

    def _degrade_bws_notes_activation(self, *, new_config: Config, reason: str) -> None:
        """Fall back from notes activation without serving guessed state.

        An unusable salt is a security failure, not something we should work
        around by continuing to derive placeholders from it. Degrading to
        file-only (`both`) or no bindings (`bws_notes`) keeps startup alive
        while staying fail closed for notes-derived bindings.
        """
        degraded_to = "file bindings only" if new_config.binding_source == "both" else "no bindings"
        _log.warning(
            "BWS-notes activation degraded in %s mode: %s; serving %s",
            new_config.binding_source,
            reason,
            degraded_to,
        )
        if new_config.binding_source == "bws_notes":
            new_config.secrets = {}
        new_config.rebuild_host_index()

    def _setup_body_injection_streaming(  # noqa: C901
        self,
        *,
        flow: http.HTTPFlow,
        config: Config,
        client: CachingSecretsClient,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
    ) -> None:
        """Body-injection setup — P0.6 of the v0.5.0 injector port.

        For each body-injector secret bound to ``target_host``, attach a
        streaming replacer to ``flow.request.stream`` so the body is
        rewritten chunk-by-chunk without ever buffering in proxy memory.
        Mirrors superfly-tokenizer's ``InjectBodyProcessor``
        (``processor.go:275-310``): a Transformer-style chain that
        emits modified bytes as the body arrives, with chunked transfer
        encoding ensuring the upstream sees the new framing.

        Three control-flow shapes here:

        1. **No body candidates for this host** — return without touching
           ``flow.request.stream`` (mitmproxy default: stream=False,
           body buffered for header path, no streaming overhead).
        2. **Candidates exist but all filtered out by ``content_type``** —
           pass through without modification but in streaming mode
           (constant memory regardless of body size).
        3. **At least one candidate eligible** — attach the replacer
           closure built by :func:`_build_body_replacer`. The closure
           lazy-fetches secrets on first placeholder match and uses the
           same fail-closed audit shape as the header path.
        """
        candidates: list[tuple[str, SecretSpec, BodyInjector]] = []
        for secret_name, spec in config.secrets_for_host(target_host):
            for child in iter_leaf_injectors(spec.inject):
                if not isinstance(child, BodyInjector):
                    continue
                # Per-binding scope check (method/path) — the placeholder may
                # appear in any body, but the binding gates whether THIS
                # request is in scope. Same semantics as the header path.
                binding = matched_binding(target_host, spec)
                if binding is None:
                    continue
                request_method = flow.request.method.upper()
                request_path = flow.request.path.split("?", 1)[0]
                if not binding.matches_scope(request_method, request_path):
                    # Audit a deny so operators see scope violations on body
                    # injectors too. The request still proceeds with the
                    # placeholder verbatim (forward-unmodified default); the
                    # caller (e.g. an egress firewall) is responsible for
                    # actually blocking traffic if that's the policy.
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
                    continue
                candidates.append((secret_name, spec, child))

        if not candidates:
            return

        # Content-Type gate: filter candidates whose declared content_type
        # doesn't match the request's. Content-Type may include parameters
        # (``application/json; charset=utf-8``) — strip them and casefold
        # before comparing. Spec values were normalised at config load.
        raw_ct = flow.request.headers.get("Content-Type", "") or ""
        actual_ct = raw_ct.split(";", 1)[0].strip().lower()
        eligible: list[tuple[str, SecretSpec, BodyInjector]] = []
        for secret_name, spec, inject in candidates:
            if inject.content_type is not None and inject.content_type != actual_ct:
                continue
            eligible.append((secret_name, spec, inject))

        if not eligible:
            # Candidates existed but were all filtered out by Content-Type.
            # Stream the body through unchanged (constant-memory passthrough)
            # rather than buffering. No audit event — content_type is a
            # filter, not a deny gate.
            flow.request.stream = True
            return

        # Composite resolver closure: captures the addon instance so the
        # body replacer can invoke ``_fetch_and_render_composite`` (which
        # owns the per-binding same-UUID warning state) without holding a
        # direct addon reference. Returns the rendered composite value on
        # success, or None after the resolver has already set ``flow.response
        # = 503`` and emitted the failure audit.
        def _composite_resolver(secret_name: str, secret_spec: SecretSpec) -> str | None:
            return self._fetch_and_render_composite(
                client=client,
                audit=audit,
                request_id=request_id,
                target_host=target_host,
                flow=flow,
                secret_name=secret_name,
                secret_spec=secret_spec,
            )

        replacer = _build_body_replacer(
            eligible=eligible,
            client=client,
            audit=audit,
            request_id=request_id,
            target_host=target_host,
            flow=flow,
            composite_resolver=_composite_resolver,
        )
        flow.request.stream = replacer
        # Chunked transfer encoding — superfly's pattern. The replacement
        # length is not knowable until the body is fully streamed (each
        # placeholder occurrence changes the byte count by
        # len(rendered) - len(placeholder)), so we cannot preserve the
        # original Content-Length. Drop it and let HTTP/1.1's chunked
        # framing handle the unknown-length body.
        flow.request.headers.pop("Content-Length", None)
        flow.request.headers["Transfer-Encoding"] = "chunked"

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
            # Failure audit shape: include compose: list so operators can
            # correlate flush events with affected composites.
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
        except Exception as e:  # noqa: BLE001
            # G6 fail-closed mirror of the single-secret path: any uncaught
            # backend exception during composite fetch must result in a 503,
            # not a forwarded placeholder.
            _log.exception(
                "unexpected backend exception fetching composite %s: %s",
                secret_name,
                type(e).__name__,
            )
            audit.emit(
                {
                    "type": "inject_decision",
                    "request_id": request_id,
                    "decision": "denied",
                    "reason": f"composite_fetch_error:{type(e).__name__}",
                    "secret_name": secret_name,
                    "compose": list(secret_spec.compose),
                    "destination": {"host": target_host, "port": flow.request.port},
                }
            )
            flow.response = http.Response.make(
                503,
                b"agent-vault-proxy: composite secret fetch failed\n",
                {"Content-Type": "text/plain"},
            )
            return None

        # Warn once per binding when two compose entries resolve to equal
        # values (likely operator typo pointing both at the same BWS UUID).
        # Values themselves are NEVER logged — only the binding name.
        self._maybe_warn_same_uuid(secret_name, values)

        try:
            rendered = secret_spec.compiled_template.render(values)
        except TemplateRenderError as exc:
            # Audit reason stays generic ("render_failed") so the agent
            # boundary can't infer compose-internal details.
            #
            # Default WARNING line carries only the EXCEPTION CLASS NAME —
            # not the exception message. Template helpers (e.g. ``b64decode``,
            # ``totp``) raise exceptions whose ``str()`` legitimately includes
            # operator-provided fragments (a base32 input that fails to decode,
            # a Unicode position from ``encode("ascii")``). Those fragments can
            # be substrings or shape-leaks of the secret value the template
            # was given. Stderr is root-readable but commonly shipped to log
            # aggregators, so we keep secrets out of it by default. The full
            # message is available at DEBUG when an operator opts in.
            _log.warning(
                "composite render failed for binding %s: %s",
                secret_name,
                type(exc).__name__,
            )
            if _log.isEnabledFor(logging.DEBUG):
                _log.debug(
                    "composite render failure detail for binding %s: %s",
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
        """One-shot warning if two compose entries resolve to the same
        value. Suggests an operator typo (two names pointing at one BWS
        UUID); does NOT fail — legitimate edge cases exist (e.g. service
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


addons = [AgentVaultProxyAddon()]
