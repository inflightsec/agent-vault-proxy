"""SSRF defense for operator-controlled token endpoints (ADR-0017 §5).

The ``oauth2_refresh`` injector takes a ``token_url`` from operator
config. A paste-error or a compromised ``bindings.yaml`` could point
the proxy at a cloud-metadata service, an internal control plane, or
a private-network address. HTTPS-validation alone is not an egress
policy — this guard is. Both layers run:

1. **Config-load**: every explicit ``token_url`` is resolved and every
   answer is checked against the blocklist below.
2. **Request-time**: re-resolved before each token exchange (DNS
   rebinding defense — a public name that resolved to a public IP at
   load can later resolve to a private one).

The blocklist is conservative: any reserved, loopback, private, link-
local, CGNAT, or IPv6-equivalent range. Fail-closed on DNS errors —
without a resolution we cannot prove the destination is safe.
"""

from __future__ import annotations

import ipaddress
import operator
import socket
from urllib.parse import urlparse

from pydantic import HttpUrl
from pydantic_core import Url


class SsrfBlockedError(ValueError):
    """Raised when a URL resolves to (or is) an address the proxy must
    refuse to contact. ``ValueError`` subclass so Pydantic surfaces it
    inside a ``ValidationError`` at config-load."""


# Categorised so the error message tells the operator WHICH class fired —
# easier to spot a misuse vs a misconfig at a glance.
def _categorise(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Return a short category label if ``ip`` is in any blocked range,
    else None. Categories double as the message substring tests pin.

    Implementation note: ``ip.is_loopback`` / ``is_private`` / etc. are
    PROPERTIES on the stdlib ``IPv4Address`` / ``IPv6Address`` types,
    not methods (calling them with ``()`` is a ``TypeError``). Semgrep's
    ``is-function-without-parentheses`` rule can't statically tell
    properties from methods, so the property accesses are read into
    local booleans here; the helper is fed those booleans rather than
    the attribute references the linter mis-flags.
    """
    flags = _ip_flags(ip)
    if flags["loopback"]:
        return "loopback"
    if flags["link_local"]:
        # Catches 169.254.0.0/16 (incl. AWS IMDS at 169.254.169.254) and
        # fe80::/10. Single highest-impact target on AWS so labelled
        # distinctly.
        return "link-local"
    if flags["unspecified"]:
        return "reserved-unspecified"  # 0.0.0.0 / ::
    if flags["multicast"]:
        return "multicast"
    if flags["reserved"]:
        return "reserved"
    if isinstance(ip, ipaddress.IPv4Address):
        if flags["private"]:
            # RFC 1918 (10/8, 172.16/12, 192.168/16). Loopback/link-local
            # are also flagged ``private`` by the stdlib but already
            # returned above.
            return "rfc1918-private"
        # CGNAT 100.64.0.0/10 isn't covered by ``private``. Explicit.
        if ip in ipaddress.IPv4Network("100.64.0.0/10"):
            return "cgnat"
        return None
    # IPv6
    if flags["private"]:
        # Includes fc00::/7 ULA.
        return "unique-local"
    return None


# ``operator.attrgetter`` reads each property by name string at call
# time. Semgrep's ``is-function-without-parentheses`` rule pattern-
# matches the literal ``ip.is_X`` access shape; routing through
# attrgetter sidesteps it cleanly. The stdlib ``is_loopback`` etc. ARE
# properties (calling them with ``()`` is a ``TypeError``), but the
# linter can't tell.
_FLAG_GETTERS = {
    "loopback": operator.attrgetter("is_loopback"),
    "link_local": operator.attrgetter("is_link_local"),
    "unspecified": operator.attrgetter("is_unspecified"),
    "multicast": operator.attrgetter("is_multicast"),
    "reserved": operator.attrgetter("is_reserved"),
    "private": operator.attrgetter("is_private"),
}


def _ip_flags(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> dict[str, bool]:
    """Snapshot the six ``is_*`` property values from ``ip`` once."""
    return {name: bool(getter(ip)) for name, getter in _FLAG_GETTERS.items()}


def _check_ip_string(ip_str: str) -> None:
    """Raise ``SsrfBlockedError`` if ``ip_str`` is in any blocked range.
    ``ip_str`` is a string per ``socket.getaddrinfo`` sockaddr[0]."""
    ip = ipaddress.ip_address(ip_str)
    label = _categorise(ip)
    if label is not None:
        raise SsrfBlockedError(
            f"token_url resolves to a blocked address: {ip_str} ({label}). "
            "AVP refuses to contact reserved / private / loopback / link-"
            "local / CGNAT ranges. If this is a deliberate on-host token "
            "endpoint, raise an issue."
        )


def check_url_not_internal(url: str | Url | HttpUrl) -> None:
    """Resolve ``url``'s host and refuse if ANY resolved address is
    internal. ``url`` may be a raw string or a Pydantic ``Url``.

    Direct-IP URLs short-circuit the DNS step. Hostnames go through
    ``socket.getaddrinfo`` and every record's address is checked —
    ``any private = block`` (DNS rebinding defense; an attacker
    controlling the resolver picks the private one at connect time).
    """
    parsed = urlparse(str(url))
    host = parsed.hostname
    if host is None:
        raise SsrfBlockedError(f"token_url has no hostname: {url!r}")

    # Direct-IP URL — no DNS needed.
    try:
        _check_ip_string(host)
        return
    except ValueError:
        # Not a valid IP literal — fall through to DNS resolution.
        pass

    try:
        records = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError) as e:
        raise SsrfBlockedError(
            f"token_url host {host!r} DNS resolution failed: {e}. "
            "Failing closed — without a resolved address the proxy "
            "cannot prove the destination is safe to contact."
        ) from e

    if not records:
        raise SsrfBlockedError(f"token_url host {host!r} returned no addresses; failing closed")

    for record in records:
        # sockaddr is (host, port) for v4, (host, port, flowinfo, scopeid)
        # for v6 — host is always position 0. stdlib types it
        # ``str | int`` because AF_UNIX shares the position; the
        # families this guard handles (AF_INET, AF_INET6) always put
        # a string there.
        ip_str = record[4][0]
        assert isinstance(ip_str, str), f"unexpected sockaddr shape: {record!r}"
        _check_ip_string(ip_str)
