"""OAuth 2.0 client-credentials grant injector (RFC 6749 §4.4).

Exchanges a vault-held client id + secret for a short-lived access token at the
configured token endpoint, caches it per-binding, and injects it as a bearer
credential. The machine-to-machine sibling of ``oauth2_refresh`` — same exchange
transport, TTL cache and audit shape, minus the refresh token and its rotation /
write-back. Resolves at ``requestheaders`` (no request body needed).
"""

from __future__ import annotations

import base64
import json
import logging
import time
from typing import TYPE_CHECKING
from urllib.parse import urlencode, urlparse

from mitmproxy import http

from agent_vault_proxy._derived_token_cache import KeyInputs
from agent_vault_proxy.backends import BackendUnavailableError, SecretNotFoundError
from agent_vault_proxy.config import Oauth2ClientCredentialsInjector
from agent_vault_proxy.injectors._token_transport import TokenResult, post

if TYPE_CHECKING:
    from agent_vault_proxy._derived_token_cache import DerivedTokenCache
    from agent_vault_proxy.audit import AuditWriter
    from agent_vault_proxy.caching import CachingSecretsClient
    from agent_vault_proxy.policy import Decision

_log = logging.getLogger("agent_vault_proxy.injectors.oauth2_client_credentials")


class _ExchangeFailedError(Exception):
    def __init__(self, result: TokenResult) -> None:
        self.result = result


def exchange(
    spec: Oauth2ClientCredentialsInjector, client_id: str, client_secret: str
) -> TokenResult:
    """POST the client-credentials grant to the token endpoint (RFC 6749 §4.4)."""
    body_params: dict[str, str] = {"grant_type": "client_credentials"}
    if spec.scopes is not None:
        body_params["scope"] = spec.scopes
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if spec.client_auth_method == "basic":
        creds = f"{client_id}:{client_secret}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(creds).decode("ascii")
    else:
        body_params["client_id"] = client_id
        body_params["client_secret"] = client_secret
    return post(
        url=str(spec.token_url),
        data=urlencode(body_params).encode("utf-8"),
        headers=headers,
        on_success=lambda body: _parse_success(body, spec),
    )


def _parse_success(body_bytes: bytes, spec: Oauth2ClientCredentialsInjector) -> TokenResult:
    try:
        payload = json.loads(body_bytes)
    except (ValueError, json.JSONDecodeError):
        return TokenResult(outcome="response_parse_failed")
    if not isinstance(payload, dict) or "access_token" not in payload:
        return TokenResult(outcome="response_parse_failed")
    token_type = payload.get("token_type")
    if token_type is not None and (
        not isinstance(token_type, str) or token_type.lower() != "bearer"
    ):
        return TokenResult(outcome="unsupported_token_type")
    access_token = str(payload["access_token"])
    now = time.time()
    expires_in = payload.get("expires_in")
    if isinstance(expires_in, int) and expires_in > 0:
        ttl = max(0, min(expires_in - spec.cache_ttl_safety_seconds, spec.cache_ttl_max_seconds))
        return TokenResult(outcome="success", token=access_token, expires_at=now + ttl)
    return TokenResult(
        outcome="success", token=access_token, expires_at=now + spec.cache_ttl_max_seconds
    )


class Oauth2CcResolver:
    """Executes a client-credentials verdict at requestheaders: fetch id+secret,
    cache-or-exchange, inject the access token. Fail-closed with 503 + audit."""

    def resolve(
        self,
        *,
        flow: http.HTTPFlow,
        decision: Decision,
        client: CachingSecretsClient,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
        companion_headers: dict[str, dict[str, str]],
        token_cache: DerivedTokenCache,
    ) -> None:
        injector = decision.oauth2_cc_injector
        secret_name = decision.secret_name
        secret_spec = decision.secret_spec
        header_name = decision.header_name
        assert injector is not None
        assert secret_name is not None
        assert secret_spec is not None
        assert header_name is not None

        try:
            client_id_value = client.get(injector.client_id_secret)
            client_secret_value = client.get(injector.client_secret_secret)
        except (BackendUnavailableError, SecretNotFoundError) as e:
            self._deny_secret(
                flow, audit, request_id, secret_name, target_host, e, "secret_unavailable"
            )
            return
        except Exception as e:  # noqa: BLE001
            _log.exception("cc secret fetch failed for %s: %s", secret_name, type(e).__name__)
            self._deny_secret(
                flow, audit, request_id, secret_name, target_host, e, "secret_fetch_error"
            )
            return

        # client_secret is folded into the cache key (repurposed refresh slot) so
        # a rotated secret invalidates the cached token (Oracle C4 invariant).
        cache_inputs = KeyInputs(
            binding_name=secret_name,
            token_url=str(injector.token_url),
            scopes=injector.scopes,
            client_id_value=client_id_value,
            refresh_token_value=client_secret_value,
        )
        cached = token_cache.get(cache_inputs)
        if cached is not None:
            self._inject(
                flow,
                audit,
                request_id,
                target_host,
                secret_name,
                secret_spec,
                injector,
                header_name,
                cached,
                companion_headers,
            )
            return

        holder: list[TokenResult] = []

        def _fetch() -> tuple[str, float]:
            result = exchange(injector, client_id_value, client_secret_value)
            holder.append(result)
            if result.outcome != "success":
                raise _ExchangeFailedError(result)
            assert result.token is not None
            assert result.expires_at is not None
            return result.token, result.expires_at

        try:
            token = token_cache.dedup_or_fetch(cache_inputs, _fetch)
        except _ExchangeFailedError as exc:
            result = exc.result
        else:
            if holder:  # only the leader that actually exchanged emits the audit
                self._emit_token_exchange(audit, request_id, secret_name, injector, holder[0])
            self._inject(
                flow,
                audit,
                request_id,
                target_host,
                secret_name,
                secret_spec,
                injector,
                header_name,
                token,
                companion_headers,
            )
            return

        self._emit_token_exchange(audit, request_id, secret_name, injector, result)
        audit.emit(
            {
                "type": "inject_decision",
                "request_id": request_id,
                "decision": "denied",
                "reason": f"token_exchange_failed:{result.outcome}",
                "secret_name": secret_name,
                "destination": {"host": target_host, "port": flow.request.port},
            }
        )
        flow.response = http.Response.make(
            503,
            b"agent-vault-proxy: oauth2 client-credentials exchange failed\n",
            {"Content-Type": "text/plain"},
        )

    def _inject(
        self,
        flow: http.HTTPFlow,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
        secret_name: str,
        secret_spec: object,
        injector: Oauth2ClientCredentialsInjector,
        header_name: str,
        access_token: str,
        companion_headers: dict[str, dict[str, str]],
    ) -> None:
        flow.request.headers[header_name] = injector.render_value(access_token=access_token)
        for companion_name, companion_value in companion_headers.get(secret_name, {}).items():
            if companion_name not in flow.request.headers:
                flow.request.headers[companion_name] = companion_value
        audit.emit(
            {
                "type": "inject_decision",
                "request_id": request_id,
                "decision": "allowed",
                "reason": "binding_matched",
                "secret_name": secret_name,
                "binding_source": secret_spec.binding_source,  # type: ignore[attr-defined]
                "destination": {
                    "host": target_host,
                    "port": flow.request.port,
                    "path_prefix": flow.request.path.split("?", 1)[0][:64],
                },
            }
        )

    def _emit_token_exchange(
        self,
        audit: AuditWriter,
        request_id: str,
        secret_name: str,
        injector: Oauth2ClientCredentialsInjector,
        result: TokenResult,
    ) -> None:
        event: dict[str, object] = {
            "type": "token_exchange",
            "request_id": request_id,
            "binding_name": secret_name,
            "token_url_host": urlparse(str(injector.token_url)).hostname,
            "outcome": result.outcome,
        }
        if result.outcome == "success" and result.expires_at is not None:
            event["cache_ttl_effective_seconds"] = int(result.expires_at - time.time())
        if result.error_description is not None:
            event["error_description"] = result.error_description
        audit.emit(event)

    def _deny_secret(
        self,
        flow: http.HTTPFlow,
        audit: AuditWriter,
        request_id: str,
        secret_name: str,
        target_host: str,
        err: Exception,
        reason_prefix: str,
    ) -> None:
        audit.emit(
            {
                "type": "inject_decision",
                "request_id": request_id,
                "decision": "denied",
                "reason": f"{reason_prefix}:{type(err).__name__}",
                "secret_name": secret_name,
                "destination": {"host": target_host, "port": flow.request.port},
            }
        )
        flow.response = http.Response.make(
            503,
            b"agent-vault-proxy: oauth2 client-credentials secret unavailable\n",
            {"Content-Type": "text/plain"},
        )
