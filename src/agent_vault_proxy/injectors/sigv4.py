"""AWS Signature Version 4 request signing.

Pure, dependency-free implementation of the AWS SigV4 signing process
(``AWS4-HMAC-SHA256``): canonical request -> string to sign -> derived signing
key -> signature -> ``Authorization`` header. Written from the published AWS
SigV4 specification; verified against the AWS SigV4 test-suite ``get-vanilla``
vector in tests.

The signing function is pure (the request timestamp is passed in, not read from
a clock) so it is deterministic and testable against fixed vectors. The addon
handler stamps the real ``X-Amz-Date`` from the request clock and calls it.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, quote, urlsplit

from mitmproxy import http

from agent_vault_proxy.backends import BackendUnavailableError, SecretNotFoundError

if TYPE_CHECKING:
    from agent_vault_proxy.audit import AuditWriter
    from agent_vault_proxy.caching import CachingSecretsClient
    from agent_vault_proxy.policy import Decision

_log = logging.getLogger("agent_vault_proxy.injectors.sigv4")

_ALGORITHM = "AWS4-HMAC-SHA256"

# The empty-string SHA-256, the payload hash for a body-less request.
EMPTY_PAYLOAD_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@dataclass(frozen=True)
class Sigv4Result:
    """Headers the signer produces. The handler sets each on the outbound
    request. ``security_token`` is present only for temporary (STS) credentials."""

    authorization: str
    amz_date: str
    content_sha256: str
    security_token: str | None


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _uri_encode(value: str, *, encode_slash: bool) -> str:
    # AWS: leave RFC 3986 unreserved (A-Za-z0-9-_.~) as-is; percent-encode
    # everything else with UPPERCASE hex. `quote` already uppercases and leaves
    # the unreserved set; `safe` decides whether '/' is preserved.
    safe = "" if encode_slash else "/"
    return quote(value, safe=safe)


def _canonical_uri(path: str) -> str:
    # A proxy signs the path as the service will receive it. Empty path -> "/".
    # Segments are URI-encoded but the separators are not.
    if not path:
        return "/"
    return _uri_encode(path, encode_slash=False)


def _canonical_query(query: str) -> str:
    if not query:
        return ""
    # Sort by encoded key then encoded value; each name/value URI-encoded.
    pairs = [
        (_uri_encode(k, encode_slash=True), _uri_encode(v, encode_slash=True))
        for k, v in parse_qsl(query, keep_blank_values=True)
    ]
    pairs.sort()
    return "&".join(f"{k}={v}" for k, v in pairs)


def _canonical_headers(
    signed: dict[str, str],
) -> tuple[str, str]:
    # signed: already-lowercased header name -> value. Trim + collapse internal
    # whitespace runs, sort by name. Returns (canonical_headers_block,
    # signed_headers_list).
    names = sorted(signed)
    block = "".join(f"{n}:{_trim(signed[n])}\n" for n in names)
    return block, ";".join(names)


def _trim(value: str) -> str:
    # Strip leading/trailing whitespace and collapse sequential spaces to one
    # (AWS canonicalization for non-quoted header values).
    return " ".join(value.split())


def _derive_signing_key(secret_access_key: str, date: str, region: str, service: str) -> bytes:
    k_date = _hmac(("AWS4" + secret_access_key).encode("utf-8"), date)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


def sign(
    *,
    method: str,
    url: str,
    body: bytes,
    access_key_id: str,
    secret_access_key: str,
    region: str,
    service: str,
    amz_date: str,
    session_token: str | None = None,
) -> Sigv4Result:
    """Sign a request per AWS SigV4. ``amz_date`` is the ``YYYYMMDDTHHMMSSZ``
    request timestamp (passed in so the function stays pure). Signs the minimal
    required header set — ``host`` + ``x-amz-date`` (+ ``x-amz-security-token``
    for temporary credentials) — which is what a broker controls and is
    sufficient for the service to verify. Returns the header values to set."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.port is not None and not _is_default_port(parts.scheme, parts.port):
        host = f"{host}:{parts.port}"
    date = amz_date[:8]  # YYYYMMDD

    payload_hash = EMPTY_PAYLOAD_HASH if not body else _sha256_hex(body)

    signed_headers: dict[str, str] = {"host": host, "x-amz-date": amz_date}
    if session_token is not None:
        signed_headers["x-amz-security-token"] = session_token
    canonical_headers, signed_header_list = _canonical_headers(signed_headers)

    canonical_request = "\n".join(
        [
            method.upper(),
            _canonical_uri(parts.path),
            _canonical_query(parts.query),
            canonical_headers,
            signed_header_list,
            payload_hash,
        ]
    )

    credential_scope = f"{date}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            _ALGORITHM,
            amz_date,
            credential_scope,
            _sha256_hex(canonical_request.encode("utf-8")),
        ]
    )

    signing_key = _derive_signing_key(secret_access_key, date, region, service)
    signature = _hmac(signing_key, string_to_sign).hex()

    authorization = (
        f"{_ALGORITHM} "
        f"Credential={access_key_id}/{credential_scope}, "
        f"SignedHeaders={signed_header_list}, "
        f"Signature={signature}"
    )
    return Sigv4Result(
        authorization=authorization,
        amz_date=amz_date,
        content_sha256=payload_hash,
        security_token=session_token,
    )


def _is_default_port(scheme: str, port: int) -> bool:
    return (scheme == "https" and port == 443) or (scheme == "http" and port == 80)


class Sigv4Resolver:
    """Signs a ``sigv4``-bound request and applies the AWS auth headers.

    Runs in the addon ``request`` hook (NOT ``requestheaders``) because SigV4
    hashes the full request body, which is only buffered by then. Mirrors
    ``OauthResolver``'s fetch -> compute -> inject -> audit shape, minus the
    network exchange and derived-token cache (signing is local + deterministic).
    Fail-closed: a credential-fetch failure denies with 503 and audits, exactly
    like the header/oauth paths.
    """

    def sign_and_apply(
        self,
        *,
        flow: http.HTTPFlow,
        decision: Decision,
        client: CachingSecretsClient,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
    ) -> None:
        injector = decision.sigv4_injector
        secret_name = decision.secret_name
        secret_spec = decision.secret_spec
        header_name = decision.header_name
        assert injector is not None
        assert secret_name is not None
        assert secret_spec is not None
        assert header_name is not None

        try:
            access_key_id = client.get(injector.access_key_id_secret)
            secret_access_key = client.get(injector.secret_access_key_secret)
            session_token = (
                client.get(injector.session_token_secret)
                if injector.session_token_secret is not None
                else None
            )
        except (BackendUnavailableError, SecretNotFoundError) as e:
            self._deny(
                flow,
                audit,
                request_id,
                secret_name,
                target_host,
                f"secret_unavailable:{type(e).__name__}",
            )
            return
        except Exception as e:  # noqa: BLE001
            _log.exception(
                "unexpected backend exception fetching sigv4 credentials for %s: %s",
                secret_name,
                type(e).__name__,
            )
            self._deny(
                flow,
                audit,
                request_id,
                secret_name,
                target_host,
                f"secret_fetch_error:{type(e).__name__}",
            )
            return

        amz_date = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        # Hash the RAW bytes that go on the wire (what the service receives and
        # hashes), not the content-decoded view — SigV4 signs the payload as
        # sent. AVP does not mutate a sigv4 request's body, so raw_content is
        # forwarded verbatim.
        result = sign(
            method=flow.request.method,
            url=flow.request.url,
            body=flow.request.raw_content or b"",
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            region=injector.region,
            service=injector.service,
            amz_date=amz_date,
            session_token=session_token,
        )

        # Mutate in place. No bytes leave the proxy until this hook returns, so
        # the G6 audit-before-write ordering holds with the emit below.
        flow.request.headers[header_name] = result.authorization
        flow.request.headers["x-amz-date"] = result.amz_date
        if result.security_token is not None:
            flow.request.headers["x-amz-security-token"] = result.security_token

        audit.emit(
            {
                "type": "inject_decision",
                "request_id": request_id,
                "decision": "allowed",
                "reason": "binding_matched",
                "secret_name": secret_name,
                "binding_source": secret_spec.binding_source,
                "destination": {
                    "host": target_host,
                    "port": flow.request.port,
                    "path_prefix": flow.request.path.split("?", 1)[0][:64],
                },
            }
        )

    @staticmethod
    def _deny(
        flow: http.HTTPFlow,
        audit: AuditWriter,
        request_id: str,
        secret_name: str,
        target_host: str,
        reason: str,
    ) -> None:
        audit.emit(
            {
                "type": "inject_decision",
                "request_id": request_id,
                "decision": "denied",
                "reason": reason,
                "secret_name": secret_name,
                "destination": {"host": target_host, "port": flow.request.port},
            }
        )
        flow.response = http.Response.make(
            503,
            b"agent-vault-proxy: sigv4 credential unavailable\n",
            {"Content-Type": "text/plain"},
        )
