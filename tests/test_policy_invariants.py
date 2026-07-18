"""Property-based safety invariants for the pure ``decide()`` policy core.

``test_policy_decide.py`` proves the addon and ``decide()`` agree on the policy
fixtures; ``test_matching_properties.py`` proves the host/path matchers. This
file proves ``decide()`` itself is safe over arbitrary generated (config,
request) pairs, by differential testing against an INDEPENDENT oracle
(:func:`_oracle`) — a plain-Python restatement of the six-step policy from
architecture.md §7, using only the matchers (the trusted, separately
property-tested primitives). A regression that drifts ``decide()`` from the spec
is caught even if it drifts the matcher with it.

Invariant → property mapping (the goal's seven, mapped to what ``decide()``
actually guarantees — AVP's real model, not an idealised one):

  1 NO UNAUTHORIZED SECRET / 2 DESTINATION CONFINEMENT — the oracle property:
    ``allowed`` only for a secret with a binding whose host matches the request
    host and whose scope permits it; no header-placeholder match ⇒ no injection.
  3 EGRESS ALLOWLIST — AVP has NO ``allowed_hosts`` field; the egress allowlist
    IS the per-binding host set, so this is invariants 1+2 (oracle host match +
    unmatched-destination deny), not a separate concept.
  4 INJECTION LOCATION — ``decide()`` is the header path only: it never returns
    ``allowed`` for a body-only secret (asserted below); header↔body cross-site
    confinement on the body path is guarded by test_confinement_and_audit_completeness.
  5 AUDIT COMPLETENESS — ``decide()`` is pure and emits NOTHING; the "exactly one
    audit per injection" invariant is enforced at the addon layer and guarded by
    test_confinement_and_audit_completeness. Here we assert every ``allowed``
    Decision carries the fields the addon needs to emit exactly one event.
  6 PURITY — same inputs ⇒ identical Decision (asserted below).
  7 BINDING_SOURCE SAFETY — resolver-layer; the ``both``-mode merge never drops a
    file-only binding (asserted below via BindingsResolver, generalising the
    fixed "both drops file-only" regression).
"""

from __future__ import annotations

import os
import tempfile
from functools import cache
from pathlib import Path
from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from agent_vault_proxy.bindings_resolver import BindingsResolver
from agent_vault_proxy.config import (
    Config,
    HeaderInjector,
    Oauth2RefreshInjector,
    iter_leaf_injectors,
    load_config,
)
from agent_vault_proxy.matching import host_matches_pattern
from agent_vault_proxy.policy import Decision, decide

# Two placeholders known to co-exist in one config (they load together in
# test_addon.py, so the substring-overlap validator accepts the pair).
PLACEHOLDERS = {
    "ALPHA": "sk-ant-PLACEHOLDER-01HXY1234567890ABCDEFGH",
    "BETA": "sk-PLACEHOLDER-01HXY1234567890ABCDEFGHIJ",
}
SECRET_NAMES = ["ALPHA", "BETA"]
HEADER_NAMES = ["Authorization", "X-Api-Key"]
BINDING_HOSTS = ["api.alpha.com", "api.beta.com", "*.alpha.com"]
METHODS_OPTS: list[list[str] | None] = [None, ["GET"], ["POST"], ["GET", "POST"]]
PATHS_OPTS: list[list[str] | None] = [None, ["/v1/**"], ["/v1/*"], ["/only"]]
REQUEST_HOSTS = [
    "api.alpha.com",
    "api.beta.com",
    "svc.alpha.com",  # matches *.alpha.com
    "alpha.com",  # apex — must NOT match *.alpha.com
    "evil.example.com",  # unbound
]
REQUEST_METHODS = ["GET", "POST"]
REQUEST_PATHS = ["/", "/v1/x", "/v1/a/b", "/only", "/other"]

_TMP = tempfile.mkdtemp(prefix="avp-policy-invariants.")

Secret = tuple[str, str, str, list[tuple[str, list[str] | None, list[str] | None]]]
Scenario = tuple[list[Secret], str, str, str, str, str | None, dict[str, str]]


def _yaml(secrets: list[Secret], policy: str) -> str:
    out = ["version: 1", "allow_wildcard_hosts: true", "secrets:"]
    for name, kind, header, bindings in secrets:
        out.append(f"  {name}:")
        out.append(f'    placeholder: "{PLACEHOLDERS[name]}"')
        out.append("    inject:")
        if kind == "header":
            out.append(f'      header: "{header}"')
            out.append(f'      format: "Bearer {{{name}}}"')
        else:
            out.append("      type: body")
            out.append(f'      format: "{{{name}}}"')
        out.append("    bindings:")
        for host, methods, paths in bindings:
            out.append(f'      - host: "{host}"')
            if methods is not None:
                out.append(f"        methods: {methods}")
            if paths is not None:
                out.append(f"        paths: {paths}")
    out.append(f"unmatched_destination_policy: {policy}")
    out.append("audit:")
    out.append(f"  path: {_TMP}/audit.jsonl")
    out.append("  fail_on_unwritable: false")
    return "\n".join(out) + "\n"


@cache
def _load(yaml_text: str) -> Config:
    fd, path = tempfile.mkstemp(dir=_TMP, suffix=".yaml")
    os.close(fd)
    Path(path).write_text(yaml_text)
    return load_config(Path(path))


def _headers(secrets: list[Secret], placements: dict[str, str]) -> dict[str, str]:
    hdrs: dict[str, str] = {}
    for name, kind, header, _bindings in secrets:
        placement = placements[name]
        if placement == "absent":
            continue
        target = header.lower() if kind == "header" else "x-body"
        slot = target if placement == "target" else "x-unrelated"
        hdrs[slot] = (hdrs.get(slot, "") + " " + PLACEHOLDERS[name]).strip()
    return hdrs


def _header_matches(config: Config, headers: dict[str, str]) -> list[tuple[str, Any]]:
    """Every (secret_name, spec) whose placeholder appears in its target header —
    header/oauth2 leaves only (the body path is separate). Mirrors
    policy.find_header_placeholder_matches."""
    matches: list[tuple[str, Any]] = []
    for name, spec in config.secrets.items():
        for leaf in iter_leaf_injectors(spec.inject):
            if isinstance(leaf, HeaderInjector | Oauth2RefreshInjector):
                value = headers.get(leaf.header.lower())
                if value and spec.placeholder in value:
                    matches.append((name, spec))
    return matches


def _oracle(
    config: Config,
    host: str,
    method: str,
    path: str,
    connect: str | None,
    headers: dict[str, str],
) -> tuple[str, str | None, str | None]:
    """Independent restatement of decide()'s six-step spec. Returns the audited
    triple (decision, reason, secret_name)."""
    if connect is not None and connect != host:
        return ("denied", "sni_host_mismatch", None)
    if config.unmatched_destination_policy == "deny" and not config.secrets_for_host(host):
        return ("denied", "unmatched_destination", None)
    matches = _header_matches(config, headers)
    if not matches:
        return ("forward_unmodified", None, None)
    if len(matches) > 1:
        return ("denied", "ambiguous_placeholder_match", None)
    name, spec = matches[0]
    binding = next((b for b in spec.bindings if host_matches_pattern(host, b.host)), None)
    if binding is None:
        return ("denied", "destination_not_in_binding", name)
    if not binding.matches_scope(method, path):
        return ("denied", "binding_scope_violation", name)
    return ("allowed", "binding_matched", name)


@st.composite
def _scenarios(draw: st.DrawFn) -> Scenario:
    secrets: list[Secret] = []
    for name in SECRET_NAMES:
        kind = draw(st.sampled_from(["header", "body"]))
        header = draw(st.sampled_from(HEADER_NAMES))
        bindings = draw(
            st.lists(
                st.tuples(
                    st.sampled_from(BINDING_HOSTS),
                    st.sampled_from(METHODS_OPTS),
                    st.sampled_from(PATHS_OPTS),
                ),
                min_size=1,
                max_size=2,
                unique_by=lambda b: b[0],
            )
        )
        secrets.append((name, kind, header, bindings))
    policy = draw(st.sampled_from(["deny", "forward_unmodified"]))
    host = draw(st.sampled_from(REQUEST_HOSTS))
    method = draw(st.sampled_from(REQUEST_METHODS))
    path = draw(st.sampled_from(REQUEST_PATHS))
    connect = draw(st.sampled_from([None, "SAME", "api.beta.com"]))
    connect = host if connect == "SAME" else connect
    placements = {
        name: draw(st.sampled_from(["target", "wrong", "absent"])) for name, *_ in secrets
    }
    return secrets, policy, host, method, path, connect, placements


def _decide(
    config: Config, host: str, method: str, path: str, connect: str | None, headers: dict[str, str]
) -> Decision:
    return decide(
        config=config,
        host=host,
        port=443,
        method=method,
        path=path,
        connect_host=connect,
        header_get=lambda n: headers.get(n.lower()),
    )


def _audited(d: Decision) -> tuple[Any, ...]:
    return (d.decision, d.reason, d.secret_name, d.response_status, d.header_name)


@settings(max_examples=250, deadline=None)
@given(sc=_scenarios())
def test_decide_matches_independent_oracle(sc: Scenario) -> None:
    """Invariants 1+2 (+ SNI/G3, unmatched-destination, scope, ambiguity):
    decide()'s audited verdict equals the independent policy oracle for any
    generated (config, request)."""
    secrets, policy, host, method, path, connect, placements = sc
    config = _load(_yaml(secrets, policy))
    headers = _headers(secrets, placements)
    d = _decide(config, host, method, path, connect, headers)
    assert (d.decision, d.reason, d.secret_name) == _oracle(
        config, host, method, path, connect, headers
    )


@settings(max_examples=250, deadline=None)
@given(sc=_scenarios())
def test_allowed_is_header_injection_only(sc: Scenario) -> None:
    """Invariant 4 + audit-readiness for 5: an ``allowed`` verdict is always a
    single header-side injection bound to this destination, carrying the fields
    the addon needs to emit exactly one audit — never a body injector."""
    secrets, policy, host, method, path, connect, placements = sc
    config = _load(_yaml(secrets, policy))
    headers = _headers(secrets, placements)
    d = _decide(config, host, method, path, connect, headers)
    if d.decision != "allowed":
        return
    assert d.header_name is not None
    assert d.secret_spec is not None
    assert d.matched_binding is not None
    assert (d.header_injector is not None) != (d.oauth2_injector is not None)
    assert host_matches_pattern(host, d.matched_binding.host)
    assert d.matched_binding.matches_scope(method, path)
    assert d.reason == "binding_matched" and d.secret_name is not None


@settings(max_examples=150, deadline=None)
@given(sc=_scenarios())
def test_decide_is_pure(sc: Scenario) -> None:
    """Invariant 6: identical inputs ⇒ identical audited Decision (no hidden state)."""
    secrets, policy, host, method, path, connect, placements = sc
    config = _load(_yaml(secrets, policy))
    headers = _headers(secrets, placements)
    assert _audited(_decide(config, host, method, path, connect, headers)) == _audited(
        _decide(config, host, method, path, connect, headers)
    )


class _StubSource:
    """Minimal BindingsSource: a name→ResolvedSpec map plus an ``invalid`` dict.
    Exercises BindingsResolver.resolve()'s merge — where the fixed "both drops
    file-only" bug lived — without the full notes/file machinery."""

    def __init__(self, mapping: dict[str, Any], invalid: dict[str, str] | None = None) -> None:
        self._mapping = mapping
        self.invalid = invalid or {}

    def resolve(self) -> dict[str, Any]:
        return dict(self._mapping)


_RES_NAMES = ["S1", "S2", "S3", "S4"]


@settings(max_examples=200, deadline=None)
@given(
    file_names=st.lists(st.sampled_from(_RES_NAMES), unique=True),
    notes_names=st.lists(st.sampled_from(_RES_NAMES), unique=True),
    invalid_names=st.lists(st.sampled_from(_RES_NAMES), unique=True),
)
def test_both_mode_never_drops_a_file_only_binding(
    file_names: list[str], notes_names: list[str], invalid_names: list[str]
) -> None:
    """Invariant 7: with sources ordered [notes, file] (``both`` mode), a
    file-only binding (name absent from notes) is NEVER dropped; a valid note
    wins over file; an invalid note excludes the same-name file binding."""
    invalid = set(invalid_names)
    valid_notes = set(notes_names) - invalid
    notes = _StubSource(
        {n: (n, "bws_notes", {}) for n in valid_notes},
        invalid=dict.fromkeys(invalid, "bad"),
    )
    file_src = _StubSource({n: (n, "file", {}) for n in file_names})
    merged = BindingsResolver(sources=[notes, file_src]).resolve()
    for n in file_names:
        if n in invalid:
            assert n not in merged
        elif n in valid_notes:
            assert merged[n][1] == "bws_notes"
        else:
            assert n in merged and merged[n][1] == "file"
    for n in valid_notes:
        assert n in merged
