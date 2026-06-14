"""Property-based tests for the authorization-decision core (``matching.py``).

The host/path matchers ARE the authorization decision: a secret is injected
into an outbound request only when the request's host and path match the
secret's binding. A wildcard bug here = a credential injected at the wrong
host or path = the catastrophic failure mode. These functions are pure and
total, so property testing gives near-exhaustive coverage of the glob
semantics for the cost of stating the invariants.

The example-based cases live in ``test_matching.py``; this file asserts the
*universal* properties behind them. Generated text is restricted to a safe
URL/DNS alphabet (no ``/``, no ``*``, no newline) wherever a structural claim
depends on segment boundaries; the totality properties use arbitrary text.

Known scope boundary (deliberate, not a gap): ``*`` compiles to ``[^/]*`` and
``**`` to ``.*``; ``[^/]`` matches a newline but regex ``.`` does not, so the
"``**`` is at least as permissive as ``*``" property below would fail on a raw
newline in the path. mitmproxy strips/normalises the request line before the
addon sees it, so a bare newline never reaches these functions; the safe
alphabet encodes that precondition rather than papering over a real bug.
"""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from agent_vault_proxy.matching import host_matches_pattern, path_glob_matches

# A single DNS label: letters/digits/hyphen, no dot, no wildcard. Non-empty.
dns_labels = st.text(alphabet="abcdeFGHIJ0129-", min_size=1, max_size=8)
# A path segment: anything URL-ish except the slash and the glob star, so the
# segment can never silently introduce a boundary the matcher would honour.
path_segments = st.text(alphabet="abcdeFGHIJ0129-_.", min_size=1, max_size=8)
# Arbitrary text for totality/no-throw properties (broad, but no newlines so
# the structural reasoning above stays valid where it is reused).
safe_text = st.text(alphabet=st.characters(blacklist_characters="\n\r"), max_size=40)
# Host-shaped ASCII text for the case-insensitivity property. Scoped to ASCII
# on purpose: ``str.lower()`` is not round-trip-safe under full Unicode
# (e.g. ``"µ".upper() == "Μ"`` whose ``.lower()`` is a *different* codepoint),
# but real hostnames are ASCII/IDNA (punycode ``xn--``), so the case-folding
# guarantee only needs to hold over ASCII. Hypothesis found this edge on the
# first run — kept here as the documented reason for the narrower alphabet.
ascii_host_text = st.text(alphabet="abcdeFGHIJ0129.-*", max_size=20)


# --------------------------------------------------------------------------
# host_matches_pattern
# --------------------------------------------------------------------------


@given(host=safe_text)
def test_host_reflexive(host: str) -> None:
    """Any host matches itself used as an exact binding. A secret bound to
    exactly the host it is destined for must always be allowed through."""
    assert host_matches_pattern(host, host)


@given(host=ascii_host_text, pattern=ascii_host_text)
def test_host_case_insensitive(host: str, pattern: str) -> None:
    """DNS is case-insensitive: the decision must not change when either the
    request host or the binding pattern is upper/lower-cased. A mismatch here
    is an operator footgun (binding silently never fires, or fires too wide)."""
    baseline = host_matches_pattern(host, pattern)
    assert host_matches_pattern(host.upper(), pattern) == baseline
    assert host_matches_pattern(host, pattern.upper()) == baseline
    assert host_matches_pattern(host.lower(), pattern.lower()) == baseline


@given(label=dns_labels, base=dns_labels)
def test_wildcard_matches_exactly_one_label(label: str, base: str) -> None:
    """``*.base`` matches exactly one non-empty label in front of ``base``."""
    base_domain = f"{base}.example"
    assert host_matches_pattern(f"{label}.{base_domain}", f"*.{base_domain}")


@given(left=dns_labels, right=dns_labels, base=dns_labels)
def test_wildcard_rejects_multi_label(left: str, right: str, base: str) -> None:
    """``*.base`` must NOT match a multi-label prefix: ``*.claude.com`` allows
    ``api.claude.com`` but never ``a.b.claude.com``. Otherwise a single-label
    binding silently authorises arbitrarily deep subdomains."""
    base_domain = f"{base}.example"
    assert not host_matches_pattern(f"{left}.{right}.{base_domain}", f"*.{base_domain}")


@given(base=dns_labels)
def test_wildcard_rejects_apex(base: str) -> None:
    """``*.base`` must NOT match the bare apex ``base`` — a wildcard requires
    at least one label. Otherwise scoping to subdomains leaks the apex too."""
    base_domain = f"{base}.example"
    assert not host_matches_pattern(base_domain, f"*.{base_domain}")


@given(left=dns_labels, right=dns_labels, base=dns_labels)
def test_no_substring_or_superdomain_without_wildcard(left: str, right: str, base: str) -> None:
    """A non-wildcard binding matches ONLY its exact host (case-folded): never
    a different sibling, never a superdomain. No substring/suffix matching."""
    base_domain = f"{base}.example"
    # A different sibling label is rejected.
    if left.lower() != right.lower():
        assert not host_matches_pattern(f"{left}.{base_domain}", f"{right}.{base_domain}")
    # The parent domain never matches a more-specific exact binding.
    assert not host_matches_pattern(base_domain, f"{left}.{base_domain}")


@given(host=safe_text, pattern=safe_text)
def test_host_total(host: str, pattern: str) -> None:
    """Never raises; always returns a bool, for any input pair."""
    assert isinstance(host_matches_pattern(host, pattern), bool)


# --------------------------------------------------------------------------
# path_glob_matches  (note arg order: (pattern, path))
# --------------------------------------------------------------------------


@given(head=path_segments, seg=path_segments)
def test_single_star_matches_one_segment(head: str, seg: str) -> None:
    """``/head/*`` matches exactly one trailing segment."""
    assert path_glob_matches(f"/{head}/*", f"/{head}/{seg}")


@given(head=path_segments, a=path_segments, b=path_segments)
def test_single_star_rejects_extra_segment(head: str, a: str, b: str) -> None:
    """THE critical anti-footgun, generalised: ``/head/*`` must NOT match a
    nested path ``/head/a/b``. An operator scoping to ``/repos/*`` must not
    silently authorise ``/repos/owner/name/contents/secret``."""
    assert not path_glob_matches(f"/{head}/*", f"/{head}/{a}/{b}")


@given(head=path_segments)
def test_single_star_matches_empty_segment(head: str) -> None:
    """``/head/*`` matches a zero-length trailing segment (``/head/``)."""
    assert path_glob_matches(f"/{head}/*", f"/{head}/")


@given(head=path_segments, tail=st.lists(path_segments, max_size=5))
def test_double_star_crosses_slashes(head: str, tail: list[str]) -> None:
    """``/head/**`` matches any number of trailing segments, including zero."""
    path = f"/{head}/" + "/".join(tail)
    assert path_glob_matches(f"/{head}/**", path)


@given(head=path_segments, tail=st.lists(path_segments, min_size=1, max_size=4))
def test_double_star_at_least_as_permissive_as_single(head: str, tail: list[str]) -> None:
    """Metamorphic: whenever ``/head/*`` matches a path, ``/head/**`` matches
    it too. ``**`` is the strict superset of ``*`` (safe alphabet; see the
    newline scope boundary in the module docstring)."""
    path = f"/{head}/" + "/".join(tail)
    if path_glob_matches(f"/{head}/*", path):
        assert path_glob_matches(f"/{head}/**", path)


@given(literal=path_segments)
def test_literal_pattern_matches_only_itself(literal: str) -> None:
    """A pattern with no glob char matches exactly its own string and nothing
    longer. Regex metacharacters in the segment (e.g. ``.``) are escaped, so
    ``/a.b`` does not match ``/axb``."""
    pat = f"/{literal}"
    assert path_glob_matches(pat, pat)
    assert not path_glob_matches(pat, pat + "x")


@given(pattern=safe_text, path=safe_text)
def test_path_total(pattern: str, path: str) -> None:
    """Never raises; always returns a bool, for any input pair."""
    assert isinstance(path_glob_matches(pattern, path), bool)
