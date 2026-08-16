"""Shared OAuth2 test helpers (ADR-0017 test-fixture consolidation)."""

from __future__ import annotations

import json
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from mitmproxy.test import tflow

from kow.backends import (
    BackendUnavailableError,
    FetchContext,
    SecretNotFoundError,
)
from kow.secret import Secret

PLACEHOLDER = "google-oauth-PLACEHOLDER-01HXY1234567890ABCD"


def apply_public_ssrf_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve non-loopback hostnames to a public IP; pass-through loopback
    + IP literals so in-process mock servers stay reachable.

    ``kow._ssrf_guard.socket`` IS the global ``socket`` —
    monkeypatching here changes name resolution for ALL code in the
    process, including ``http.client.HTTPConnection``'s
    ``create_connection``. A naive "everything → public IP" stub silently
    misroutes loopback test traffic; pass-through fixes it.
    """
    real_getaddrinfo = socket.getaddrinfo

    def stub(host: str, *a: object, **kw: object) -> list[tuple]:
        if host in ("127.0.0.1", "::1", "localhost"):
            return real_getaddrinfo(host, *a, **kw)  # type: ignore[arg-type]
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 0)),
        ]

    monkeypatch.setattr("kow._ssrf_guard.socket.getaddrinfo", stub)


@pytest.fixture
def public_ssrf_dns(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    apply_public_ssrf_stub(monkeypatch)
    yield


class FakeBackend:
    def __init__(self, values: dict[str, str]) -> None:
        self._values = dict(values)
        self.fetches: list[str] = []
        self.updates: list[tuple[str, str]] = []

    @property
    def values(self) -> dict[str, str]:
        return self._values

    @property
    def update_count(self) -> int:
        return len(self.updates)

    def fetch(self, name: str, ctx: FetchContext | None = None) -> Secret:
        self.fetches.append(name)
        if name not in self._values:
            raise SecretNotFoundError(f"missing secret {name!r}")
        return Secret(self._values[name])

    def update(
        self,
        name: str,
        value: str,
        ctx: FetchContext | None = None,
        *,
        expected_current_value: str | None = None,
    ) -> None:
        # Mirror BitwardenBackend's value-precondition semantics (ADR-0017
        # hardening series) so conflict paths are testable against the fake.
        if expected_current_value is not None and self._values.get(name) != expected_current_value:
            from kow.backends import BackendWriteConflictError

            raise BackendWriteConflictError(
                f"secret {name!r} changed since read; refusing to overwrite"
            )
        self.updates.append((name, value))
        self._values[name] = value


class ReadOnlyBackend:
    # Deliberately NOT inheriting from FakeBackend: backends.update_secret
    # dispatches via getattr(type(backend), "update", None), and inheritance
    # would expose the parent's update and break the read-only semantic.
    def __init__(self, values: dict[str, str]) -> None:
        self._values = dict(values)
        self.fetches: list[str] = []

    def fetch(self, name: str, ctx: FetchContext | None = None) -> Secret:
        self.fetches.append(name)
        if name not in self._values:
            raise SecretNotFoundError(f"missing secret {name!r}")
        return Secret(self._values[name])


class FailingBackend:
    def __init__(self, error: Exception | None = None) -> None:
        self._error = error or BackendUnavailableError("vault down")

    def fetch(self, name: str, ctx: FetchContext | None = None) -> Secret:
        raise self._error


class UpdateFailsBackend(FakeBackend):
    def __init__(
        self,
        values: dict[str, str],
        error: Exception | None = None,
    ) -> None:
        super().__init__(values)
        self._update_error = error or BackendUnavailableError("vault down for update")

    def update(
        self,
        name: str,
        value: str,
        ctx: FetchContext | None = None,
        *,
        expected_current_value: str | None = None,
    ) -> None:
        raise self._update_error


class FakeResp:
    # Redirects are refused at the opener itself (_NoRedirectHandler in
    # oauth2_refresh) — there is no post-call geturl() check any more, so
    # fakes never need to model the redirect path; a redirect in tests is
    # simulated by the patched transport raising HTTPError(code=3xx).
    def __init__(
        self,
        body: bytes,
        status: int = 200,
        geturl_value: str | None = None,
    ) -> None:
        self._body = body
        self.status = status
        self._geturl_value = geturl_value

    def read(self) -> bytes:
        return self._body

    def geturl(self) -> str | None:
        return self._geturl_value

    def __enter__(self) -> FakeResp:
        return self

    def __exit__(self, *_a: object) -> None:
        return None


def read_audit(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def make_request(
    host: str,
    headers: dict[str, str],
    *,
    method: str = "GET",
    path: str = "/oauth2/v1/userinfo",
    port: int = 443,
    scheme: str = "https",
) -> Any:
    flow = tflow.tflow()
    flow.request.host = host
    flow.request.port = port
    flow.request.scheme = scheme
    flow.request.method = method
    flow.request.path = path
    for k, v in headers.items():
        flow.request.headers[k] = v
    return flow


def ok_body(access_token: str = "at-FRESH", expires_in: int = 3600) -> bytes:
    return json.dumps({"access_token": access_token, "expires_in": expires_in}).encode()


def rotation_body(
    access_token: str = "at-FRESH",
    refresh_token: str = "rtok-ROTATED",
    expires_in: int = 3600,
) -> bytes:
    return json.dumps(
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": expires_in,
        }
    ).encode()


def oauth_yaml(
    audit_path: Path,
    *,
    token_url: str = "https://oauth2.example.com/token",
    write_back: bool | None = None,
    methods: str = "",
    full: bool = False,
) -> str:
    """Standard oauth2_refresh binding YAML. ``full=True`` adds
    binding_source/cache/policy blocks; ``write_back=None`` omits the knob."""
    wb = (
        ""
        if write_back is None
        else f"      refresh_token_write_back: {'true' if write_back else 'false'}\n"
    )  # noqa: E501
    head = "version: 1\n" + ("binding_source: file\n" if full else "")
    m = f"        methods: {methods}\n" if methods else ""
    extra = (
        "cache:\n  ttl_seconds: 300\n  jitter_seconds: 0\n  max_entries: 100\n"
        "unmatched_destination_policy: deny\n"
        if full
        else ""
    )
    return (
        f"\n{head}secrets:\n  GOOGLE_OAUTH:\n"
        f'    placeholder: "{PLACEHOLDER}"\n    inject:\n'
        f"      type: oauth2_refresh\n      token_url: {token_url}\n"
        f"      client_auth_method: body_post\n"
        f"      client_id_secret: GOOGLE_OAUTH_CLIENT_ID\n"
        f"      client_secret_secret: GOOGLE_OAUTH_CLIENT_SECRET\n"
        f"      refresh_token_secret: GOOGLE_OAUTH_REFRESH_TOKEN\n"
        f"{wb}    bindings:\n      - host: www.googleapis.com\n{m}"
        f"audit:\n  path: {audit_path}\n  fail_on_unwritable: true\n{extra}"
    )


def build_oauth_addon(
    tmp_path: Path,
    *,
    backend: object | None = None,
    write_back: bool | None = None,
) -> tuple[Any, Path, Any]:
    """Hand-build a ``GOOGLE_OAUTH`` oauth2_refresh addon; write_back=None
    omits the slice-7 knob (slice-6 tests predate it)."""
    from kow._derived_token_cache import DerivedTokenCache
    from kow.addon import AgentVaultProxyAddon
    from kow.audit import AuditWriter
    from kow.caching import CachingSecretsClient
    from kow.config import load_config

    audit_path = tmp_path / "audit.jsonl"
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(oauth_yaml(audit_path, write_back=write_back))

    if backend is None:
        backend = FakeBackend(
            {
                "GOOGLE_OAUTH_CLIENT_ID": "cid-real",
                "GOOGLE_OAUTH_CLIENT_SECRET": "csec-real",
                "GOOGLE_OAUTH_REFRESH_TOKEN": "rtok-real",
            }
        )
    client = CachingSecretsClient(
        backend,  # type: ignore[arg-type]
        ttl_seconds=300,
        jitter_seconds=0,
        max_entries=100,
    )
    addon = AgentVaultProxyAddon()
    addon.config = load_config(config_path)
    addon.audit = AuditWriter(str(audit_path))
    addon.client = client
    addon._token_cache = DerivedTokenCache()
    return addon, audit_path, client


__all__ = [
    "PLACEHOLDER",
    "FailingBackend",
    "FakeBackend",
    "FakeResp",
    "ReadOnlyBackend",
    "UpdateFailsBackend",
    "apply_public_ssrf_stub",
    "build_oauth_addon",
    "make_request",
    "oauth_yaml",
    "ok_body",
    "public_ssrf_dns",
    "read_audit",
    "rotation_body",
]
