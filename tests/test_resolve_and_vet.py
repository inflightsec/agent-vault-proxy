"""ADR-0035: ``resolve_and_vet`` — resolve once, return the vetted addresses.

Unit tests for the sibling of ``check_url_not_internal`` that RETURNS the
vetted address set (so the transport connects to a member of exactly this
set — no check→connect re-resolution). Hermetic: ``socket.getaddrinfo`` is
monkeypatched; no real DNS.
"""

from __future__ import annotations

import socket

import pytest

from kow._ssrf_guard import SsrfBlockedError, resolve_and_vet

_PUBLIC = "93.184.216.34"  # example.com — a real public address
_IMDS = "169.254.169.254"  # AWS instance-metadata (link-local, blocked)


def _rec(family: int, ip: str, socktype: int = socket.SOCK_STREAM) -> tuple:
    """One getaddrinfo 5-tuple ``(family, socktype, proto, canonname, sockaddr)``."""
    return (family, socktype, 6, "", (ip, 0))


def test_returns_deduped_addresses_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    # getaddrinfo yields one record per socktype — the (family, ip) dedupe
    # collapses the STREAM/DGRAM duplicate, order preserved.
    recs = [
        _rec(socket.AF_INET, _PUBLIC, socket.SOCK_STREAM),
        _rec(socket.AF_INET, _PUBLIC, socket.SOCK_DGRAM),
        _rec(socket.AF_INET, "8.8.8.8", socket.SOCK_STREAM),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: recs)
    assert resolve_and_vet("https://api.example.com/token") == [
        (socket.AF_INET, _PUBLIC),
        (socket.AF_INET, "8.8.8.8"),
    ]


def test_blocks_when_any_resolved_address_is_internal(monkeypatch: pytest.MonkeyPatch) -> None:
    # Rebinding defense: one public + one IMDS record ⇒ block the whole set.
    recs = [_rec(socket.AF_INET, _PUBLIC), _rec(socket.AF_INET, _IMDS)]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: recs)
    with pytest.raises(SsrfBlockedError, match="link-local"):
        resolve_and_vet("https://api.example.com/token")


def test_ip_literal_short_circuits_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*a: object, **k: object) -> None:
        raise AssertionError("getaddrinfo must not be called for an IP literal")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    assert resolve_and_vet(f"https://{_PUBLIC}/token") == [(socket.AF_INET, _PUBLIC)]


def test_blocked_ip_literal_raises_without_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*a: object, **k: object) -> None:
        raise AssertionError("getaddrinfo must not be called for an IP literal")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    with pytest.raises(SsrfBlockedError, match="link-local"):
        resolve_and_vet(f"https://{_IMDS}/token")


def test_fail_closed_on_dns_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(*a: object, **k: object) -> None:
        raise socket.gaierror("name resolution failed")

    monkeypatch.setattr(socket, "getaddrinfo", _raise)
    with pytest.raises(SsrfBlockedError, match="Failing closed"):
        resolve_and_vet("https://api.example.com/token")


def test_fail_closed_on_empty_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [])
    with pytest.raises(SsrfBlockedError, match="failing closed"):
        resolve_and_vet("https://api.example.com/token")


def test_fail_closed_on_malformed_sockaddr(monkeypatch: pytest.MonkeyPatch) -> None:
    # A non-str host at sockaddr[0] never happens for AF_INET/AF_INET6, but the
    # guard fails CLOSED rather than assert (assertions strip under python -O).
    bad = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (12345, 0))]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: bad)
    with pytest.raises(SsrfBlockedError, match="failing closed"):
        resolve_and_vet("https://api.example.com/token")
