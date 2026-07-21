"""Shared HTTP egress for the token-minting injectors — oauth2_client_credentials
and github_app — which POST to a provider to obtain a short-lived credential.

SSRF-guarded, no-redirect (a 3xx from a token endpoint is a misconfig / SSRF
pivot), one retry on 5xx / transport error. ``transport_open`` is the single
egress seam the e2e tests patch. The pre-existing ``oauth2_refresh`` injector
keeps its own equivalent transport (not refactored — it is verified as-is).
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agent_vault_proxy._ssrf_guard import SsrfBlockedError, check_url_not_internal

_log = logging.getLogger("agent_vault_proxy.injectors._token_transport")
_RETRY_BACKOFF_SECONDS = 1.0
_USER_AGENT = "agent-vault-proxy/token-exchange"


@dataclass(frozen=True)
class TokenResult:
    """One token-minting attempt. ``outcome`` is the audit vocabulary label;
    ``token`` + ``expires_at`` are set only on ``success``. No secret material
    other than the freshly minted ``token`` (which the resolver injects, never
    audits)."""

    outcome: str
    token: str | None = None
    expires_at: float | None = None
    error_description: str | None = None


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse every 3xx from a token endpoint — following it (even with a
    post-hoc check) means the redirected host was already contacted."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: ARG002
        return None


def transport_open(req: urllib.request.Request, timeout: float) -> Any:
    """Single egress seam — tests patch THIS name. Fresh no-redirect opener per
    call (no global opener state). Scheme is https by config validation; the URL
    is SSRF-re-checked in :func:`post` immediately before the call."""
    opener = urllib.request.build_opener(_NoRedirectHandler)
    return opener.open(req, timeout=timeout)  # noqa: S310  # nosec


def _safe_read(err: urllib.error.HTTPError) -> bytes:
    try:
        return err.read()
    except Exception:  # noqa: BLE001
        return b""


def _http_error(status: int, body: bytes) -> TokenResult:
    description: str | None = None
    try:
        payload = json.loads(body)
        if isinstance(payload, dict):
            raw = payload.get("error_description") or payload.get("error") or payload.get("message")
            description = str(raw) if raw is not None else None
    except (ValueError, json.JSONDecodeError):
        description = None
    if 300 <= status < 400:
        return TokenResult(outcome=f"token_endpoint_status:{status}", error_description=description)
    return TokenResult(outcome=f"token_endpoint_error:{status}", error_description=description)


def post(
    *,
    url: str,
    data: bytes,
    headers: dict[str, str],
    on_success: Callable[[bytes], TokenResult],
    timeout: float = 10.0,
) -> TokenResult:
    """SSRF-checked POST with one retry on 5xx / transport error. On HTTP 200,
    ``on_success(body)`` parses the provider response; on any error a categorised
    :class:`TokenResult` is returned. Never raises (barring programmer error)."""
    try:
        check_url_not_internal(url)
    except SsrfBlockedError as e:
        _log.warning("token endpoint SSRF-blocked at runtime: %s", e)
        return TokenResult(outcome="ssrf_blocked")

    all_headers = {"User-Agent": _USER_AGENT, "Accept": "application/json", **headers}
    req = urllib.request.Request(url, data=data, headers=all_headers, method="POST")  # noqa: S310
    for attempt in (0, 1):
        try:
            with transport_open(req, timeout=timeout) as resp:
                return on_success(resp.read())
        except urllib.error.HTTPError as e:
            status = e.code
            body = _safe_read(e)
            if 300 <= status < 500:
                return _http_error(status, body)
            if attempt == 0:  # 5xx — retry once
                time.sleep(_RETRY_BACKOFF_SECONDS)
                continue
            return _http_error(status, body)
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt == 0:
                time.sleep(_RETRY_BACKOFF_SECONDS)
                continue
            _log.info("token endpoint unreachable: %s", e)
            return TokenResult(outcome="token_endpoint_unreachable")
    return TokenResult(outcome="token_endpoint_unreachable")
