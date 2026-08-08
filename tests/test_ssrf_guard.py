"""SSRF guard tests (ADR-0017 slice 2).

The guard is shared between config-load (every binding's ``token_url``
is checked at startup) and the runtime token-exchange step (DNS
re-check before each outbound POST — DNS rebinding defense). This
file pins both surfaces.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator

import pytest

from kow._ssrf_guard import SsrfBlockedError, check_url_not_internal

# ---------------------------------------------------------------------------
# Direct-IP blocklist — each address range gets its own pin so a regression
# in one range can't hide behind the others
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/token",
        "https://127.5.5.5/token",
    ],
)
def test_loopback_v4_blocked(url: str) -> None:
    with pytest.raises(SsrfBlockedError, match=r"loopback|127"):
        check_url_not_internal(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://10.0.0.1/token",
        "https://10.255.255.254/token",
        "https://172.16.0.1/token",
        "https://172.31.255.254/token",
        "https://192.168.1.1/token",
        "https://192.168.99.99/token",
    ],
)
def test_rfc1918_blocked(url: str) -> None:
    with pytest.raises(SsrfBlockedError, match=r"private|rfc1918"):
        check_url_not_internal(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://169.254.169.254/latest/meta-data/",  # AWS IMDS v4
        "https://169.254.0.1/token",
        "https://169.254.255.254/token",
    ],
)
def test_link_local_v4_blocked(url: str) -> None:
    with pytest.raises(SsrfBlockedError, match=r"link-local|169\.254|imds"):
        check_url_not_internal(url)


def test_cgnat_blocked() -> None:
    with pytest.raises(SsrfBlockedError, match=r"cgnat|100\.64"):
        check_url_not_internal("https://100.64.0.1/token")


def test_zero_address_blocked() -> None:
    with pytest.raises(SsrfBlockedError, match=r"reserved|0\.0\.0\.0"):
        check_url_not_internal("https://0.0.0.0/token")


def test_ipv6_loopback_blocked() -> None:
    with pytest.raises(SsrfBlockedError, match=r"loopback|::1"):
        check_url_not_internal("https://[::1]/token")


def test_ipv6_link_local_blocked() -> None:
    with pytest.raises(SsrfBlockedError, match=r"link-local|fe80"):
        check_url_not_internal("https://[fe80::1]/token")


def test_ipv6_unique_local_blocked() -> None:
    with pytest.raises(SsrfBlockedError, match=r"unique-local|ula|fc00|fd"):
        check_url_not_internal("https://[fd00::1]/token")


def test_aws_imds_v6_blocked() -> None:
    """AWS IMDSv2 over IPv6 lives at ``fd00:ec2::254``. The /7 ULA block
    catches it, this test just nails the exact address as a regression
    pin — if the broader ULA check ever loosens, this still fires."""
    with pytest.raises(SsrfBlockedError):
        check_url_not_internal("https://[fd00:ec2::254]/latest/meta-data/")


# ---------------------------------------------------------------------------
# Public addresses — must NOT block
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://8.8.8.8/token",
        "https://1.1.1.1/token",
        "https://[2606:4700:4700::1111]/token",  # Cloudflare DNS over v6
    ],
)
def test_public_ip_passes(url: str) -> None:
    # Direct-IP URL with a public address: must pass without raising.
    check_url_not_internal(url)


# ---------------------------------------------------------------------------
# Hostname resolution — monkeypatched getaddrinfo so the test is hermetic
# ---------------------------------------------------------------------------


def _stub_getaddrinfo(ips: list[str]) -> object:
    """Build a getaddrinfo stub returning the given IPs.

    Each IP becomes one record in the (family, type, proto, canonname,
    sockaddr) shape the stdlib produces, which is all the guard reads."""

    def stub(
        host: str,
        port: object,
        family: int = 0,
        type_: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[int, int, int, str, tuple]]:
        out: list[tuple[int, int, int, str, tuple]] = []
        for ip in ips:
            if ":" in ip:
                fam = socket.AF_INET6
                sockaddr: tuple = (ip, 0, 0, 0)
            else:
                fam = socket.AF_INET
                sockaddr = (ip, 0)
            out.append((fam, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr))
        return out

    return stub


@pytest.fixture
def patched_getaddrinfo(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Per-test getaddrinfo monkeypatch via ``_stub_getaddrinfo``. The
    test sets the resolver under the ``current_ips`` attribute attached
    to this fixture's module-level state."""
    yield


def test_hostname_resolving_to_public_ip_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "kow._ssrf_guard.socket.getaddrinfo",
        _stub_getaddrinfo(["93.184.216.34"]),  # example.com's known IP
    )
    check_url_not_internal("https://example.com/token")


def test_hostname_resolving_to_loopback_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """DNS rebinding defense: a public-looking hostname that resolves to
    127.0.0.1 must be blocked."""
    monkeypatch.setattr(
        "kow._ssrf_guard.socket.getaddrinfo",
        _stub_getaddrinfo(["127.0.0.1"]),
    )
    with pytest.raises(SsrfBlockedError, match=r"loopback"):
        check_url_not_internal("https://innocent.example.com/token")


def test_hostname_resolving_to_mixed_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pseudo-public DNS returning BOTH public and private addresses. An
    attacker controlling the resolver picks the private one at connect
    time; the guard must block on ANY private hit, not just all-private."""
    monkeypatch.setattr(
        "kow._ssrf_guard.socket.getaddrinfo",
        _stub_getaddrinfo(["8.8.8.8", "10.0.0.1"]),
    )
    with pytest.raises(SsrfBlockedError, match=r"private|rfc1918"):
        check_url_not_internal("https://malicious.example.com/token")


def test_dns_resolution_failure_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    """No DNS answer at all = deny. Failing closed beats failing open;
    the operator can re-run config-load once DNS is up."""

    def boom(*_args: object, **_kw: object) -> list:
        raise socket.gaierror("name resolution failed")

    monkeypatch.setattr("kow._ssrf_guard.socket.getaddrinfo", boom)
    with pytest.raises(SsrfBlockedError, match=r"resolution|gaierror"):
        check_url_not_internal("https://nowhere.example.com/token")


# ---------------------------------------------------------------------------
# Integration with Oauth2RefreshInjector — config-load wiring
# ---------------------------------------------------------------------------

_FOO_PH = "foo_PLACEHOLDER_01HXY1234567890"


def _wrap_oauth(token_url: str) -> dict:
    return {
        "version": 1,
        "secrets": {
            "FOO": {
                "placeholder": _FOO_PH,
                "inject": {
                    "type": "oauth2_refresh",
                    "token_url": token_url,
                    "client_auth_method": "body_post",
                    "client_id_secret": "C_ID",
                    "client_secret_secret": "C_SEC",
                    "refresh_token_secret": "R_TOK",
                },
                "bindings": [{"host": "api.example.com"}],
            }
        },
        "audit": {"path": "/tmp/x.jsonl"},
    }


def test_oauth_token_url_loopback_blocked_at_config_load() -> None:
    """The injector's config-load validator MUST run the SSRF guard.
    Loopback token_url is the canonical operator paste-error case."""
    from pydantic import ValidationError

    from kow.config import Config

    with pytest.raises(ValidationError, match=r"loopback|ssrf"):
        Config.model_validate(_wrap_oauth("https://127.0.0.1/token"))


def test_oauth_token_url_imds_blocked_at_config_load() -> None:
    """The single highest-impact SSRF target: cloud metadata. Pinned
    separately so a regression that loosens the link-local check alone
    surfaces with this exact name."""
    from pydantic import ValidationError

    from kow.config import Config

    with pytest.raises(ValidationError, match=r"link-local|169\.254|imds|ssrf"):
        Config.model_validate(_wrap_oauth("https://169.254.169.254/token"))


def test_oauth_provider_preset_skips_ssrf_check_for_known_urls() -> None:
    """The bundled preset URLs are vetted at PR review. Re-checking
    them at every config-load is pointless work AND it requires the
    operator's host to have live DNS at startup. Provider-preset path
    skips the runtime DNS check; the request-time check (slice 5) still
    runs before every exchange."""
    from kow.config import Config

    Config.model_validate(
        {
            "version": 1,
            "secrets": {
                "FOO": {
                    "placeholder": _FOO_PH,
                    "inject": {
                        "type": "oauth2_refresh",
                        "provider": "google",
                        "client_id_secret": "C_ID",
                        "client_secret_secret": "C_SEC",
                        "refresh_token_secret": "R_TOK",
                    },
                    "bindings": [{"host": "www.googleapis.com"}],
                },
            },
            "audit": {"path": "/tmp/x.jsonl"},
        }
    )


# ---------------------------------------------------------------------------
# IP-literal short-circuit — the block verdict must PROPAGATE, never be
# swallowed by the "not an IP literal" parse guard (SsrfBlockedError IS-A
# ValueError; ADR-0017 hardening series closure).


def test_blocked_ip_literal_short_circuits_without_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A blocked IP literal must raise straight from the short-circuit.
    DNS must not be consulted at all — the old combined try/except sent
    the (already-blocked) literal down the getaddrinfo path."""

    def dns_must_not_be_called(*_args: object, **_kw: object) -> list:
        raise AssertionError("getaddrinfo consulted for an IP-literal URL")

    monkeypatch.setattr("kow._ssrf_guard.socket.getaddrinfo", dns_must_not_be_called)
    with pytest.raises(SsrfBlockedError, match=r"169\.254\.169\.254"):
        check_url_not_internal("https://169.254.169.254/latest/meta-data/")


def test_public_ip_literal_short_circuits_without_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A public IP literal passes via the short-circuit alone."""

    def dns_must_not_be_called(*_args: object, **_kw: object) -> list:
        raise AssertionError("getaddrinfo consulted for an IP-literal URL")

    monkeypatch.setattr("kow._ssrf_guard.socket.getaddrinfo", dns_must_not_be_called)
    check_url_not_internal("https://8.8.8.8/token")  # must not raise
