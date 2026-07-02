"""Request-path handlers split out of :class:`AgentVaultProxyAddon`.

The addon owns the mitmproxy lifecycle and per-request state snapshot; these
handlers own the execution of each verdict. They receive the per-request
snapshot (client, audit, request_id, target_host, flow) as call arguments so
the addon's tearing-prevention capture model is preserved verbatim.

Logging uses the ``agent_vault_proxy.addon`` channel so operator log filters
and caplog assertions keyed on that name keep working after the split.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from mitmproxy import http

from agent_vault_proxy._fail_closed import emit_denial_and_503
from agent_vault_proxy.audit import AuditWriter
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
    iter_leaf_injectors,
)
from agent_vault_proxy.injectors.body import _build_body_replacer
from agent_vault_proxy.injectors.oauth2_refresh import OauthResolver
from agent_vault_proxy.policy import matched_binding
from agent_vault_proxy.template import TemplateRenderError

if TYPE_CHECKING:
    from agent_vault_proxy._derived_token_cache import DerivedTokenCache
    from agent_vault_proxy.policy import Decision

_log = logging.getLogger("agent_vault_proxy.addon")


class CompositeResolver:
    """Composite-binding fetch + render, with per-binding same-UUID warnings.

    Owns the once-per-binding warning state; :meth:`reset_warnings` is called
    on every config reload so a corrected binding can re-warn.
    """

    def __init__(self) -> None:
        import threading

        self._same_uuid_warned: set[str] = set()
        self._warned_lock = threading.Lock()

    def reset_warnings(self) -> None:
        with self._warned_lock:
            self._same_uuid_warned.clear()

    def fetch_and_render(
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
            emit_denial_and_503(
                audit=audit,
                flow=flow,
                request_id=request_id,
                reason=f"composite_unavailable:{type(e).__name__}",
                secret_name=secret_name,
                message=b"agent-vault-proxy: composite secret unavailable\n",
                target_host=target_host,
                extra={"compose": list(secret_spec.compose)},
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
            emit_denial_and_503(
                audit=audit,
                flow=flow,
                request_id=request_id,
                reason=f"composite_fetch_error:{type(e).__name__}",
                secret_name=secret_name,
                message=b"agent-vault-proxy: composite secret fetch failed\n",
                target_host=target_host,
                extra={"compose": list(secret_spec.compose)},
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
            emit_denial_and_503(
                audit=audit,
                flow=flow,
                request_id=request_id,
                reason="render_failed",
                secret_name=secret_name,
                message=b"agent-vault-proxy: composite render failed\n",
                target_host=target_host,
                extra={"compose": list(secret_spec.compose)},
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


class HeaderInjectionHandler:
    """Executes the header verdict from :func:`agent_vault_proxy.policy.decide`."""

    def __init__(self, *, composite: CompositeResolver, oauth_resolver: OauthResolver) -> None:
        self._composite = composite
        self._oauth_resolver = oauth_resolver

    def execute(
        self,
        *,
        flow: http.HTTPFlow,
        decision: Decision,
        client: CachingSecretsClient,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
        companion_headers: dict[str, dict[str, str]],
        token_cache: DerivedTokenCache | None,
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

        if self._audit_deny(
            flow=flow,
            decision=decision,
            audit=audit,
            request_id=request_id,
            target_host=target_host,
        ):
            return

        # Allowed — execute with the handles decide() resolved.
        secret_name = decision.secret_name
        secret_spec = decision.secret_spec
        header_injector = decision.header_injector
        header_name = decision.header_name
        assert secret_name is not None
        assert secret_spec is not None
        assert header_name is not None

        # OAuth2 refresh-token grant: divert through the token-exchange
        # branch. ADR-0017 §11 — resolution slots in between deny gates
        # (handled above) and header injection. The resolver sets
        # ``flow.response`` on any deny path and otherwise injects the
        # resolved access token via the standard header mutation +
        # audit-before-bytes-leave ordering.
        if decision.oauth2_injector is not None:
            assert token_cache is not None
            self._oauth_resolver.resolve(
                flow=flow,
                decision=decision,
                client=client,
                audit=audit,
                request_id=request_id,
                target_host=target_host,
                companion_headers=companion_headers,
                token_cache=token_cache,
            )
            return

        new_header_value = self._resolve_header_value(
            flow=flow,
            client=client,
            audit=audit,
            request_id=request_id,
            target_host=target_host,
            secret_name=secret_name,
            secret_spec=secret_spec,
            header_injector=header_injector,
        )
        if new_header_value is None:
            return  # response already set + audit emitted

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

    def _audit_deny(
        self,
        *,
        flow: http.HTTPFlow,
        decision: Decision,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
    ) -> bool:
        """Emit the deny audit for a non-allowed header verdict. Returns True if
        the verdict was a deny (caller must stop); False if it is the allowed
        path. Only ambiguous_placeholder_match sets a response (400); the
        other two forward the placeholder verbatim after auditing."""
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
            return True

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
            return True

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
            return True

        return False

    def _resolve_header_value(
        self,
        *,
        flow: http.HTTPFlow,
        client: CachingSecretsClient,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
        secret_name: str,
        secret_spec: SecretSpec,
        header_injector: object,
    ) -> str | None:
        """Resolve the header value for an allowed verdict. Returns the rendered
        value, or None after a fail-closed 503 + audit. Branches on composite
        vs single-secret — config-load guarantees exactly one applies
        (inject.format XOR inject.template)."""
        if secret_spec.compose is not None:
            return self._composite.fetch_and_render(
                client=client,
                audit=audit,
                request_id=request_id,
                target_host=target_host,
                flow=flow,
                secret_name=secret_name,
                secret_spec=secret_spec,
            )

        from agent_vault_proxy.config import HeaderInjector

        assert isinstance(header_injector, HeaderInjector)
        assert header_injector.format is not None
        try:
            real_secret = client.get(secret_name)
        except (BackendUnavailableError, SecretNotFoundError) as e:
            emit_denial_and_503(
                audit=audit,
                flow=flow,
                request_id=request_id,
                reason=f"secret_unavailable:{type(e).__name__}",
                secret_name=secret_name,
                message=b"agent-vault-proxy: secret unavailable\n",
                target_host=target_host,
            )
            return None
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
            emit_denial_and_503(
                audit=audit,
                flow=flow,
                request_id=request_id,
                reason=f"secret_fetch_error:{type(e).__name__}",
                secret_name=secret_name,
                message=b"agent-vault-proxy: secret fetch failed\n",
                target_host=target_host,
            )
            return None
        # HeaderInjector.render_value() owns the substitution rule (named
        # form {<SECRET_NAME>} replaced with the resolved bytes via
        # .replace(), not .format() — no attribute-access traversal).
        return header_injector.render_value(
            real_secret=real_secret,
            secret_name=secret_name,
        )


class BodyInjectionHandler:
    """Attaches a streaming body replacer for hosts with body bindings."""

    def __init__(self, *, composite: CompositeResolver) -> None:
        self._composite = composite

    def setup(
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
        A Transformer-style chain emits modified bytes as the body
        arrives, with chunked transfer encoding ensuring the upstream
        sees the new framing.

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
        candidates = self._collect_candidates(
            flow=flow,
            config=config,
            audit=audit,
            request_id=request_id,
            target_host=target_host,
        )
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

        # Composite resolver closure: delegates to the shared CompositeResolver
        # (which owns the per-binding same-UUID warning state). Returns the
        # rendered composite value on success, or None after the resolver has
        # already set ``flow.response = 503`` and emitted the failure audit.
        def _composite_resolver(secret_name: str, secret_spec: SecretSpec) -> str | None:
            return self._composite.fetch_and_render(
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
        # Chunked transfer encoding. The replacement length is not
        # knowable until the body is fully streamed (each placeholder
        # occurrence changes the byte count by
        # len(rendered) - len(placeholder)), so we cannot preserve the
        # original Content-Length. Drop it and let HTTP/1.1's chunked
        # framing handle the unknown-length body.
        flow.request.headers.pop("Content-Length", None)
        flow.request.headers["Transfer-Encoding"] = "chunked"

    def _collect_candidates(
        self,
        *,
        flow: http.HTTPFlow,
        config: Config,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
    ) -> list[tuple[str, SecretSpec, BodyInjector]]:
        """Collect in-scope body-injector candidates for this host. Emits a
        scope-violation deny audit (forward-unmodified default) for any body
        binding whose method/path scope excludes this request."""
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
        return candidates


class BwsNotesActivator:
    """Resolves BWS-notes bindings and merges them into a fresh Config at load.

    Config-build helper only — no request-path state. Degrades to file-only
    (`both`) or no bindings (`bws_notes`) when the install salt or backend
    listing is unusable, rather than serving guessed state.
    """

    def activate(
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
            self.degrade(
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
            self.degrade(
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

    def degrade(self, *, new_config: Config, reason: str) -> None:
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
