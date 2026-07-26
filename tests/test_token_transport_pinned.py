"""Pinned HTTPS transport tests for ADR-0035."""

from __future__ import annotations

import socket
import ssl
import urllib.request
from dataclasses import dataclass
from email.message import Message
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import ClassVar

import pytest

from agent_vault_proxy.injectors._token_transport import (
    _TLS_CONTEXT,
    TokenResult,
    _PinnedHTTPSConnection,
    post,
    transport_open,
)
from tests._tls_helpers import run_loopback_tls_http_server


@dataclass(frozen=True)
class _ConnectionPlan:
    status: int = 200
    body: bytes = b"{}"
    reason: str = "OK"
    request_error: OSError | None = None


class _FakeHTTPResponse:
    def __init__(
        self,
        *,
        status: int,
        body: bytes,
        reason: str,
        headers: Message | None = None,
    ) -> None:
        self.status = status
        self.reason = reason
        self.headers = headers or Message()
        self._body = body
        self.closed = False

    def read(self) -> bytes:
        return self._body

    def close(self) -> None:
        self.closed = True


class RecordingPinnedHTTPSConnection:
    plans: ClassVar[dict[str, list[_ConnectionPlan]]] = {}
    constructed: ClassVar[list[tuple[int, str, str, int]]] = []
    requested: ClassVar[list[str]] = []

    def __init__(
        self,
        family: int,
        ip: str,
        host: str,
        port: int,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        del timeout, context
        self._ip = ip
        self._plan = self.plans.get(ip, [_ConnectionPlan()]).pop(0)
        self.constructed.append((family, ip, host, port))

    @classmethod
    def reset(cls) -> None:
        cls.plans = {}
        cls.constructed = []
        cls.requested = []

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        del method, url, body, headers
        self.requested.append(self._ip)
        if self._plan.request_error is not None:
            raise self._plan.request_error

    def getresponse(self) -> _FakeHTTPResponse:
        return _FakeHTTPResponse(
            status=self._plan.status,
            body=self._plan.body,
            reason=self._plan.reason,
        )

    def close(self) -> None:
        return


def test_rebinding_prevented_dials_only_vetted_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    RecordingPinnedHTTPSConnection.reset()
    calls = {"count": 0}

    def resolve(url: str) -> list[tuple[int, str]]:
        calls["count"] += 1
        assert url == "https://api.example.com/token"
        return [(socket.AF_INET, "93.184.216.34")]

    RecordingPinnedHTTPSConnection.plans = {
        "93.184.216.34": [_ConnectionPlan(status=200, body=b"{}")],
    }
    monkeypatch.setattr("agent_vault_proxy.injectors._token_transport.resolve_and_vet", resolve)
    monkeypatch.setattr(
        "agent_vault_proxy.injectors._token_transport._PinnedHTTPSConnection",
        RecordingPinnedHTTPSConnection,
    )

    req = urllib.request.Request("https://api.example.com/token", data=b"x", method="POST")
    with transport_open(req, 10.0) as resp:
        assert resp.read() == b"{}"

    assert RecordingPinnedHTTPSConnection.constructed == [
        (socket.AF_INET, "93.184.216.34", "api.example.com", 443),
    ]
    assert calls["count"] == 1


def test_sequential_failover_second_vetted_ip_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    RecordingPinnedHTTPSConnection.reset()
    monkeypatch.setattr(
        "agent_vault_proxy.injectors._token_transport.resolve_and_vet",
        lambda url: [(socket.AF_INET, "93.184.216.34"), (socket.AF_INET, "93.184.216.35")],
    )
    monkeypatch.setattr(
        "agent_vault_proxy.injectors._token_transport._PinnedHTTPSConnection",
        RecordingPinnedHTTPSConnection,
    )
    RecordingPinnedHTTPSConnection.plans = {
        "93.184.216.34": [_ConnectionPlan(request_error=OSError("dial failed"))],
        "93.184.216.35": [_ConnectionPlan(status=200, body=b"second")],
    }

    req = urllib.request.Request("https://api.example.com/token", data=b"x", method="POST")
    with transport_open(req, 10.0) as resp:
        assert resp.read() == b"second"

    assert RecordingPinnedHTTPSConnection.constructed == [
        (socket.AF_INET, "93.184.216.34", "api.example.com", 443),
        (socket.AF_INET, "93.184.216.35", "api.example.com", 443),
    ]
    assert RecordingPinnedHTTPSConnection.requested == ["93.184.216.34", "93.184.216.35"]


def test_retry_revets_fresh_on_5xx(monkeypatch: pytest.MonkeyPatch) -> None:
    RecordingPinnedHTTPSConnection.reset()
    calls = {"count": 0}

    def resolve(url: str) -> list[tuple[int, str]]:
        calls["count"] += 1
        assert url == "https://api.example.com/token"
        return [(socket.AF_INET, "93.184.216.34")]

    def success(body: bytes) -> TokenResult:
        assert body == b"ok"
        return TokenResult(outcome="success")

    RecordingPinnedHTTPSConnection.plans = {
        "93.184.216.34": [
            _ConnectionPlan(status=502, body=b'{"error":"bad gateway"}', reason="Bad Gateway"),
            _ConnectionPlan(status=200, body=b"ok"),
        ],
    }
    monkeypatch.setattr(
        "agent_vault_proxy._ssrf_guard.socket.getaddrinfo",
        lambda host, *a, **kw: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 0))
        ],
    )
    monkeypatch.setattr("agent_vault_proxy.injectors._token_transport.resolve_and_vet", resolve)
    monkeypatch.setattr(
        "agent_vault_proxy.injectors._token_transport._PinnedHTTPSConnection",
        RecordingPinnedHTTPSConnection,
    )
    monkeypatch.setattr(
        "agent_vault_proxy.injectors._token_transport.time.sleep",
        lambda seconds: None,
    )

    result = post(
        url="https://api.example.com/token",
        data=b"x",
        headers={},
        on_success=success,
        timeout=10.0,
    )

    assert result.outcome == "success"
    assert calls["count"] == 2


def test_pinned_connection_keeps_hostname_and_context_verifies() -> None:
    conn = _PinnedHTTPSConnection(
        socket.AF_INET,
        "93.184.216.34",
        "api.example.com",
        443,
        timeout=5.0,
        context=_TLS_CONTEXT,
    )

    assert conn.host == "api.example.com"
    assert _TLS_CONTEXT.check_hostname is True
    assert _TLS_CONTEXT.verify_mode == ssl.CERT_REQUIRED


def test_real_handshake_verifies_cert_against_hostname_not_ip(
    tmp_path: Path,
) -> None:
    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args: object) -> None:
            return

    with run_loopback_tls_http_server(tmp_path, _Handler) as server:
        conn = _PinnedHTTPSConnection(
            socket.AF_INET,
            "127.0.0.1",
            "pinned.test",
            server.port,
            timeout=5.0,
            context=server.client_context,
        )
        conn.request("GET", "/")
        resp = conn.getresponse()
        assert resp.status == 200
        assert resp.read() == b"ok"
        conn.close()

        bad_conn = _PinnedHTTPSConnection(
            socket.AF_INET,
            "127.0.0.1",
            "127.0.0.1",
            server.port,
            timeout=5.0,
            context=server.client_context,
        )
        with pytest.raises(ssl.SSLCertVerificationError):
            bad_conn.request("GET", "/")
        bad_conn.close()
