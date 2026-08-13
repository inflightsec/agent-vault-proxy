"""Liveness/readiness probe for orchestrators (roadmap: Observability).

A request to the reserved sentinel host + ``/healthz`` is answered by the
addon directly and never proxied upstream. The ``.invalid`` TLD (RFC 6761
§2) can never resolve, so it can never collide with a real binding
destination — a probe to this host is unambiguously a health check, not
proxied traffic. Plain HTTP only (liveness probes don't tunnel); an HTTPS
CONNECT to the sentinel is treated as any other unmatched destination.

The response body is static — it never reads, renders, or emits a secret.
"""

from __future__ import annotations

import json

from mitmproxy import http

# Reserved probe target. Gated on BOTH host and path so a real proxied
# request to some-bound-host/healthz is never intercepted.
HEALTHZ_HOST = "healthz.agent-vault-proxy.invalid"
HEALTHZ_PATH = "/healthz"


def is_healthz_request(flow: http.HTTPFlow) -> bool:
    """True iff this flow is the reserved liveness probe (exact host + path)."""
    path = flow.request.path.split("?", 1)[0]
    return path == HEALTHZ_PATH and flow.request.pretty_host == HEALTHZ_HOST


def healthz_response(*, ready: bool) -> http.Response:
    """Synthesize the probe response.

    ``ready`` (config, backend client, and audit writer all initialized) →
    ``200 {"status": "ok"}``. Otherwise — mitmproxy is up but kow has not
    finished loading a config — ``503 {"status": "starting"}`` so an
    orchestrator holds traffic until the proxy can actually broker.

    The body carries NO version or build identifier: an orchestrator only
    needs the status code, and a version string on an unauthenticated
    endpoint is gratuitous fingerprint/CVE-matching surface. Read the
    version on the host via ``avp --version``, never over the wire.
    """
    status = "ok" if ready else "starting"
    code = 200 if ready else 503
    body = json.dumps({"status": status}) + "\n"
    return http.Response.make(
        code,
        body.encode(),
        {"Content-Type": "application/json"},
    )
