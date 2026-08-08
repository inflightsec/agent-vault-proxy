"""Liveness/readiness probe (`/healthz`) — roadmap: Observability.

The probe is intercepted in ``requestheaders`` on a reserved sentinel host so
orchestrators get a real "AVP is configured and brokering" signal, not just the
TCP-port-open signal the Docker healthcheck had before. These tests pin: the
ready/starting split, that no secret path or audit is touched, and that real
proxied traffic to a ``/healthz`` path on a *bound* host is never hijacked.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mitmproxy.test import tflow

from kow._healthz import HEALTHZ_HOST, HEALTHZ_PATH

from .test_addon import PLACEHOLDER, REAL_SECRET, _build_addon, _read_audit


def _probe(host: str = HEALTHZ_HOST, path: str = HEALTHZ_PATH) -> Any:
    flow = tflow.tflow()
    flow.request.host = host
    flow.request.port = 80
    flow.request.scheme = "http"
    flow.request.method = "GET"
    flow.request.path = path
    return flow


def test_healthz_ready_returns_200(tmp_path: Path) -> None:
    addon, audit_path = _build_addon(tmp_path)
    flow = _probe()
    addon.requestheaders(flow)

    assert flow.response is not None
    assert flow.response.status_code == 200
    assert flow.response.headers["Content-Type"] == "application/json"
    payload = json.loads(flow.response.get_text())
    # No version/build identifier on the wire — anti-fingerprinting (see
    # healthz_response docstring). Status code + status field only.
    assert payload == {"status": "ok"}
    # Health probes must never touch the audit log — polling would flood it.
    assert _read_audit(audit_path) == []


def test_healthz_before_config_returns_503_starting(tmp_path: Path) -> None:
    addon, _ = _build_addon(tmp_path)
    # Simulate mitmproxy up but AVP not yet configured.
    addon.config = None
    flow = _probe()
    addon.requestheaders(flow)

    assert flow.response is not None
    assert flow.response.status_code == 503
    assert json.loads(flow.response.get_text())["status"] == "starting"


def test_healthz_fires_before_destination_allowlist(tmp_path: Path) -> None:
    """The sentinel host is in no binding; without early interception the
    deny-unmatched gate would 403 it. Ready probe must win with 200."""
    addon, _ = _build_addon(tmp_path)
    flow = _probe()
    # No http_connect() — mirrors a plain-HTTP probe straight to the port.
    addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 200


def test_healthz_path_on_bound_host_is_not_hijacked(tmp_path: Path) -> None:
    """A real proxied request to /healthz on a BOUND host must inject normally,
    not be swallowed by the probe (gate is host AND path)."""
    addon, _ = _build_addon(tmp_path)
    flow = _probe(host="api.anthropic.com", path="/healthz")
    flow.request.port = 443
    flow.request.scheme = "https"
    flow.request.headers["Authorization"] = f"Bearer {PLACEHOLDER}"
    addon.http_connect(flow)
    addon.requestheaders(flow)
    # Not intercepted as health: the placeholder got substituted for real.
    assert flow.request.headers["Authorization"] == f"Bearer {REAL_SECRET}"


def test_healthz_wrong_path_on_sentinel_host_not_intercepted(tmp_path: Path) -> None:
    """Sentinel host but a non-/healthz path is not a probe; it falls through
    to the allow-list and is denied (sentinel host is in no binding)."""
    addon, _ = _build_addon(tmp_path)
    flow = _probe(path="/metrics")
    addon.requestheaders(flow)
    assert flow.response is not None
    assert flow.response.status_code == 403
