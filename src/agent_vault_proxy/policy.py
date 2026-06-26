"""Pure policy core — ADR-0013's ``decide()`` single source of truth.

``decide()`` answers *whether* a request gets a credential and *which* one,
with no I/O and no flow mutation. It returns a :class:`Decision` the addon
then EXECUTES (fetch the secret, render, mutate the header, fsync the audit
under the G6 ordering). Splitting the verdict from the execution is what
makes the decision logic unit-testable against the policy fixtures without
a live backend or the mitmproxy transport.

What stays OUT of here (because it is I/O or ordering-sensitive, not policy):
  * secret fetch + render (and the ``secret_unavailable`` / ``secret_fetch_error``
    / ``composite_*`` denials that only a failed fetch can produce);
  * ``audit.emit`` and its synchronous fsync (G6);
  * the BWS-notes no-binding/invalid attribution audit (an addon pre-step).

The verdict ``forward_unmodified`` means "no inject_decision event from the
header path" — the placeholder is forwarded verbatim (G5 enforcement by
omission).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from agent_vault_proxy.config import (
    BindingSpec,
    Config,
    HeaderInjector,
    SecretSpec,
    iter_leaf_injectors,
)
from agent_vault_proxy.matching import host_matches_pattern

Verdict = Literal["allowed", "denied", "forward_unmodified"]


@dataclass(frozen=True)
class Decision:
    """The verdict for one request's header path.

    ``decision``/``reason``/``secret_name`` are the audited triple (the
    policy fixtures assert exactly these). ``response_status`` is the HTTP
    status the addon should synthesise on a hard deny (403/400); ``None``
    means "do not set a response" — for ``allowed`` and for the
    forward-verbatim denials (``destination_not_in_binding`` /
    ``binding_scope_violation``, which preserve G5 by omission).

    The remaining fields are EXECUTION handles, populated only for
    ``allowed``: the addon uses them to fetch + render + inject. ``extra``
    carries branch-specific audit fields (e.g. ``matched_secret_names`` for
    ambiguity, ``method``/``path`` for a scope violation).
    """

    decision: Verdict
    reason: str | None = None
    secret_name: str | None = None
    response_status: int | None = None
    response_body: bytes | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    # Execution handles (allowed only):
    secret_spec: SecretSpec | None = None
    header_injector: HeaderInjector | None = None
    header_name: str | None = None
    matched_binding: BindingSpec | None = None


# --- relocated pure matching helpers (were private in addon.py) -------------


def destination_in_any_binding(config: Config, host: str) -> bool:
    """True if any secret has a binding whose host matches ``host``.

    Uses the config-load host index rather than a per-request linear scan.
    """
    return bool(config.secrets_for_host(host))


def matched_binding(host: str, spec: SecretSpec) -> BindingSpec | None:
    """The first of ``spec``'s bindings whose host pattern matches ``host``."""
    for b in spec.bindings:
        if host_matches_pattern(host, b.host):
            return b
    return None


def find_header_placeholder_matches(
    config: Config, header_get: Callable[[str], str | None]
) -> list[tuple[str, SecretSpec, HeaderInjector, str, str]]:
    """Every ``(secret_name, spec, header_injector, header_name, value)`` where
    the secret's placeholder appears inside its configured target header.

    Multiple matches => the request is ambiguous (the caller refuses to
    guess). Only ``HeaderInjector`` leaves are considered; body leaves are
    handled by the streaming body path. ``header_get`` is the request's
    header accessor (case-insensitive, mitmproxy semantics) so this stays
    free of the flow object.
    """
    matches: list[tuple[str, SecretSpec, HeaderInjector, str, str]] = []
    for secret_name, spec in config.secrets.items():
        for child in iter_leaf_injectors(spec.inject):
            if not isinstance(child, HeaderInjector):
                continue
            value = header_get(child.header)
            if value and spec.placeholder in value:
                matches.append((secret_name, spec, child, child.header, value))
    return matches


# --- the decision -----------------------------------------------------------

_FORWARD = Decision(decision="forward_unmodified")


def decide(
    *,
    config: Config,
    host: str,
    port: int,
    method: str,
    path: str,
    connect_host: str | None,
    header_get: Callable[[str], str | None],
) -> Decision:
    """Compute the header-path verdict for one request. Pure.

    ``method`` should be upper-cased and ``path`` query-stripped by the
    caller (mirrors what the addon already extracts). ``header_get`` looks
    up a request header by name. The order of checks mirrors ``addon``'s
    ``requestheaders`` -> ``_run_header_injection_pipeline`` exactly:
    SNI consistency, destination allow-list, placeholder match, ambiguity,
    destination binding, scope, then allow.
    """
    # 1. SNI/Host consistency (G3): a CONNECT to one host then an inner
    #    request claiming another is a TLS-proxy laundering attempt.
    if connect_host and connect_host != host:
        return Decision(
            decision="denied",
            reason="sni_host_mismatch",
            response_status=403,
            response_body=b"agent-vault-proxy: CONNECT host and request host disagree\n",
            extra={"destination": {"connect_host": connect_host, "request_host": host}},
        )

    # 2. Destination allow-list — enforced here (not only at CONNECT) so plain
    #    HTTP can't relay to hosts outside the binding set.
    if config.unmatched_destination_policy == "deny" and not destination_in_any_binding(
        config, host
    ):
        return Decision(
            decision="denied",
            reason="unmatched_destination",
            response_status=403,
            response_body=b"agent-vault-proxy: destination not in any binding\n",
            extra={"destination": {"host": host, "port": port}},
        )

    # 3. Placeholder match in the configured target header(s).
    matches = find_header_placeholder_matches(config, header_get)
    if not matches:
        return _FORWARD
    if len(matches) > 1:
        # Two distinct configured placeholders in the request headers. Config
        # load forbids substring overlap, but an adversarial/accidental request
        # can still embed two — refuse to guess which secret to inject.
        return Decision(
            decision="denied",
            reason="ambiguous_placeholder_match",
            response_status=400,
            response_body=b"agent-vault-proxy: ambiguous placeholder match\n",
            extra={"matched_secret_names": sorted({m[0] for m in matches})},
        )
    secret_name, secret_spec, header_injector, header_name, _value = matches[0]

    # 4. The matched secret must be bound to this destination (else G5: forward
    #    the placeholder verbatim, audit the omission, no response).
    binding = matched_binding(host, secret_spec)
    if binding is None:
        return Decision(
            decision="denied",
            reason="destination_not_in_binding",
            secret_name=secret_name,
        )

    # 5. The binding's method/path scope must permit this request (else G5).
    if not binding.matches_scope(method, path):
        return Decision(
            decision="denied",
            reason="binding_scope_violation",
            secret_name=secret_name,
            extra={"method": method, "path": path},
        )

    # 6. Allowed. The addon fetches + renders + injects (and only then can an
    #    I/O failure produce secret_unavailable / secret_fetch_error / the
    #    composite_* denials — those are execution-layer, not policy).
    return Decision(
        decision="allowed",
        reason="binding_matched",
        secret_name=secret_name,
        secret_spec=secret_spec,
        header_injector=header_injector,
        header_name=header_name,
        matched_binding=binding,
    )
