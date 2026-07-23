"""GitHub App installation access-token injector.

Mints an App JWT (RS256) from the App's PEM private key, exchanges it at GitHub's
``/app/installations/{id}/access_tokens`` endpoint for a short-lived installation
token, caches it, and injects it (default ``Authorization: token {token}``).
Reuses the JWT signer (:mod:`agent_vault_proxy.injectors.jwt_bearer`) and the
shared token transport. Resolves at ``requestheaders`` (no request body needed).
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from mitmproxy import http

from agent_vault_proxy._derived_token_cache import KeyInputs
from agent_vault_proxy.backends import BackendUnavailableError, SecretNotFoundError
from agent_vault_proxy.config import GithubAppInjector
from agent_vault_proxy.injectors._token_transport import TokenResult, post
from agent_vault_proxy.injectors.jwt_bearer import encode as jwt_encode

if TYPE_CHECKING:
    from agent_vault_proxy._derived_token_cache import DerivedTokenCache
    from agent_vault_proxy.audit import AuditWriter
    from agent_vault_proxy.caching import CachingSecretsClient
    from agent_vault_proxy.policy import Decision

_log = logging.getLogger("agent_vault_proxy.injectors.github_app")

# GitHub App JWT: exp ≤ 10 min from iat; iat backdated 60s for clock skew.
_APP_JWT_IAT_SKEW_SECONDS = 60
_APP_JWT_TTL_SECONDS = 480
# Installation tokens last ~1h; fall back conservatively if expires_at is absent.
_INSTALLATION_TOKEN_FALLBACK_SECONDS = 3300


class _ExchangeFailedError(Exception):
    def __init__(self, result: TokenResult) -> None:
        self.result = result


def _installations_url(injector: GithubAppInjector) -> str:
    return f"{injector.api_base_url}/app/installations/{injector.installation_id}/access_tokens"


def mint_app_jwt(app_id: str, private_key_pem: str) -> str:
    """Mint the RS256 App JWT GitHub requires to authenticate as the App."""
    now = int(time.time())
    return jwt_encode(
        payload={
            "iss": app_id,
            "iat": now - _APP_JWT_IAT_SKEW_SECONDS,
            "exp": now + _APP_JWT_TTL_SECONDS,
        },
        key=private_key_pem,
        algorithm="RS256",
    )


def exchange(injector: GithubAppInjector, private_key_pem: str) -> TokenResult:
    """Mint the App JWT, then POST for an installation access token."""
    try:
        app_jwt = mint_app_jwt(injector.app_id, private_key_pem)
    except Exception as e:  # noqa: BLE001  (malformed / non-RSA private key)
        _log.exception("github_app JWT mint failed: %s", type(e).__name__)
        return TokenResult(outcome=f"app_jwt_error:{type(e).__name__}")
    return post(
        url=_installations_url(injector),
        data=b"",
        headers={
            "Authorization": f"Bearer {app_jwt}",
            "Accept": "application/vnd.github+json",
        },
        on_success=lambda body: _parse_token(body, injector),
    )


def _parse_token(body_bytes: bytes, injector: GithubAppInjector) -> TokenResult:
    try:
        payload = json.loads(body_bytes)
    except (ValueError, json.JSONDecodeError):
        return TokenResult(outcome="response_parse_failed")
    if not isinstance(payload, dict) or "token" not in payload:
        return TokenResult(outcome="response_parse_failed")
    token = str(payload["token"])
    now = time.time()
    expires_at_raw = payload.get("expires_at")
    exp_unix: float | None = None
    if isinstance(expires_at_raw, str):
        try:
            exp_unix = datetime.fromisoformat(expires_at_raw.replace("Z", "+00:00")).timestamp()
        except ValueError:
            exp_unix = None
    if exp_unix is not None:
        ttl = max(0.0, exp_unix - now - injector.cache_ttl_safety_seconds)
        return TokenResult(outcome="success", token=token, expires_at=now + ttl)
    return TokenResult(
        outcome="success", token=token, expires_at=now + _INSTALLATION_TOKEN_FALLBACK_SECONDS
    )


class GithubAppResolver:
    """Executes a github_app verdict at requestheaders: fetch the private key,
    cache-or-mint the installation token, inject it. Fail-closed with 503."""

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
        injector = decision.github_app_injector
        secret_name = decision.secret_name
        secret_spec = decision.secret_spec
        header_name = decision.header_name
        assert injector is not None
        assert secret_name is not None
        assert secret_spec is not None
        assert header_name is not None

        try:
            private_key = client.get(injector.private_key_secret)
        except (BackendUnavailableError, SecretNotFoundError) as e:
            self._deny_secret(
                flow, audit, request_id, secret_name, target_host, e, "secret_unavailable"
            )
            return
        except Exception as e:  # noqa: BLE001
            _log.exception("github_app key fetch failed for %s: %s", secret_name, type(e).__name__)
            self._deny_secret(
                flow, audit, request_id, secret_name, target_host, e, "secret_fetch_error"
            )
            return

        # Cache key spans app id, installation id (in the URL) and the private
        # key (hashed) so any rotation invalidates the cached installation token.
        cache_inputs = KeyInputs(
            binding_name=secret_name,
            token_url=_installations_url(injector),
            scopes=None,
            client_id_value=f"{injector.app_id}:{injector.installation_id}",
            refresh_token_value=hashlib.sha256(private_key.encode("utf-8")).hexdigest(),
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
            result = exchange(injector, private_key)
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
            if holder:
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
            b"agent-vault-proxy: github app token exchange failed\n",
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
        injector: GithubAppInjector,
        header_name: str,
        token: str,
        companion_headers: dict[str, dict[str, str]],
    ) -> None:
        flow.request.headers[header_name] = injector.render_value(token=token)
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
        injector: GithubAppInjector,
        result: TokenResult,
    ) -> None:
        event: dict[str, object] = {
            "type": "token_exchange",
            "request_id": request_id,
            "binding_name": secret_name,
            "token_url_host": urlparse(_installations_url(injector)).hostname,
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
            b"agent-vault-proxy: github app private key unavailable\n",
            {"Content-Type": "text/plain"},
        )
