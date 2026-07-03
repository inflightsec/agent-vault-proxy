"""Streaming body-injection executor (factored out of ``addon.py``).

One ``_BodyReplacer`` instance per request rewrites placeholders in the
request body chunk-by-chunk in constant memory, fail-closed on backend
errors. The addon builds one via :func:`_build_body_replacer` and assigns
it to ``flow.request.stream``; this module owns no policy decisions — the
addon decides *whether* a body injector is eligible (scope/content-type)
before handing the eligible set here.

G6 ordering note: the per-secret ``allowed`` audit fires inside
``_apply_replacements`` on the FIRST match for each secret, BEFORE the
substituted bytes are returned to mitmproxy — the same audit-before-action
invariant the header path enforces. Do not reorder.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from mitmproxy import http

from agent_vault_proxy._fail_closed import emit_denial_and_503
from agent_vault_proxy.audit import AuditWriter
from agent_vault_proxy.backends import (
    BackendUnavailableError,
    SecretNotFoundError,
)
from agent_vault_proxy.caching import CachingSecretsClient
from agent_vault_proxy.config import BodyInjector, SecretSpec

_log = logging.getLogger("agent_vault_proxy.injectors.body")


def _build_body_replacer(
    *,
    eligible: list[tuple[str, SecretSpec, BodyInjector]],
    client: CachingSecretsClient,
    audit: AuditWriter,
    request_id: str,
    target_host: str,
    flow: http.HTTPFlow,
    composite_resolver: Callable[[str, SecretSpec], str | None],
) -> _BodyReplacer:
    """Build the per-flow streaming replacement callable.

    Returns an instance of :class:`_BodyReplacer` — a callable
    mitmproxy invokes with each body chunk. The instance holds the
    overlap buffer (handling placeholder spans across chunk
    boundaries — Critical for correctness, see ``test_body_injector
    _placeholder_spans_chunk_boundary``) and the resolved-replacement
    cache (lazy-fetch on first match, fail-closed on backend errors).

    Encapsulated as a class rather than a closure so the state is
    inspectable from tests and the type checker can see the
    ``__call__`` signature mitmproxy expects.
    """
    # Encode placeholders once. Sort by length DESC so that if any
    # placeholder were ever a prefix of another (config-load validators
    # already reject substring overlaps, but defensive: a 24-char
    # placeholder cannot be a prefix of a 24-char placeholder, but a
    # future shorter placeholder type might), the longer match wins.
    targets: list[tuple[bytes, str, SecretSpec, BodyInjector]] = [
        (spec.placeholder.encode("utf-8"), name, spec, inject) for name, spec, inject in eligible
    ]
    targets.sort(key=lambda t: len(t[0]), reverse=True)
    return _BodyReplacer(
        targets=targets,
        client=client,
        audit=audit,
        request_id=request_id,
        target_host=target_host,
        flow=flow,
        composite_resolver=composite_resolver,
    )


class _BodyReplacer:
    """Streaming body-injection callable. One instance per request.

    Mitmproxy calls ``self(chunk)`` repeatedly as body bytes arrive.
    The final call passes ``b""`` to signal end-of-stream, which is
    the cue to flush any held overlap buffer.

    Invariants:

    * **Constant memory** — the overlap buffer holds at most
      ``max(len(placeholder) for placeholder in targets) - 1`` bytes
      between calls, regardless of total body size.
    * **Boundary-correct** — placeholders split across chunk
      boundaries are detected by holding back the trailing
      ``(max_placeholder_len - 1)`` bytes from each emission and
      prepending them to the next chunk.
    * **Fail-closed on backend errors** — if secret fetch fails, sets
      ``flow.response = 503``, emits a denied audit event, and the
      remaining chunks are swallowed (the upstream connection will be
      aborted by mitmproxy when it sees ``flow.response`` set).
    * **Lazy fetch** — secrets are fetched only when their placeholder
      actually appears in a chunk. A request with no matches incurs
      zero backend calls.
    """

    def __init__(
        self,
        *,
        targets: list[tuple[bytes, str, SecretSpec, BodyInjector]],
        client: CachingSecretsClient,
        audit: AuditWriter,
        request_id: str,
        target_host: str,
        flow: http.HTTPFlow,
        composite_resolver: Callable[[str, SecretSpec], str | None],
    ) -> None:
        self._targets = targets
        self._client = client
        self._audit = audit
        self._request_id = request_id
        self._target_host = target_host
        self._flow = flow
        # Composite render path for body bindings with ``compose:`` set.
        # Returns the rendered value on success, or None when the resolver
        # has already set ``flow.response = 503`` + emitted a failure audit
        # (composite_unavailable / composite_fetch_error / render_failed).
        self._composite_resolver = composite_resolver
        # Running buffer holding (a) bytes not yet emitted because they
        # might be the start of an incomplete placeholder, and (b)
        # incoming chunks before processing. Constant-bounded at
        # ``max(max_needle_len - 1, residual_after_replacement)`` after
        # each call.
        self._buffer = bytearray()
        self._max_needle_len = max(len(t[0]) for t in targets)
        self._rendered_cache: dict[str, bytes] = {}
        self._matched_names: set[str] = set()
        self._fetch_failed = False

    def __call__(self, chunk: bytes) -> bytes:
        if self._fetch_failed:
            # A previous chunk already triggered fail-closed; eat
            # remaining bytes so we don't forward partial unprocessed
            # body to the upstream.
            return b""
        if not chunk:
            # End-of-stream — process whatever remains in the buffer
            # and flush it (any placeholder still split here was never
            # going to be completed by a future chunk). Per-secret
            # allowed-audit fires inside ``_apply_replacements`` on
            # FIRST match for each secret, BEFORE the substituted bytes
            # return to mitmproxy — matches the header path's G6
            # ordering invariant (audit before action).
            tail = bytes(self._buffer)
            self._buffer.clear()
            return self._apply_replacements(tail)

        self._buffer.extend(chunk)
        # Streaming-replace algorithm (boundary-correct):
        # 1. Scan the FULL buffer for complete placeholder matches and
        #    replace them in place — bytes.replace handles all complete
        #    occurrences in one C-level pass.
        # 2. Hold back the trailing ``max_needle_len - 1`` bytes from
        #    emission — those COULD be the start of a placeholder that
        #    continues into the next chunk. Anything earlier is either
        #    already-replaced or proven-not-a-match.
        keep = self._max_needle_len - 1
        if len(self._buffer) < self._max_needle_len:
            # Buffer too short for any complete match; hold and wait
            # for more bytes.
            return b""
        processed = self._apply_replacements(bytes(self._buffer))
        if self._fetch_failed:
            self._buffer.clear()
            return b""
        # The buffer is now the post-replacement bytes. Emit all but
        # the trailing ``keep`` bytes; those stay for the next chunk.
        self._buffer.clear()
        if len(processed) <= keep:
            # Replacement shrank the buffer below the safe-emit
            # threshold; hold everything for the next chunk.
            self._buffer.extend(processed)
            return b""
        emit_len = len(processed) - keep
        self._buffer.extend(processed[emit_len:])
        return processed[:emit_len]

    def _apply_replacements(self, buf: bytes) -> bytes:  # noqa: C901
        """Two-phase commit: fetch ALL needed secrets first, then audit +
        replace as a single atomic step. The split matters when a buffer
        contains placeholders for multiple secrets — without it, a
        partial-failure path would emit ``allowed`` audits for secrets
        whose substituted bytes never actually reach mitmproxy (because
        the fail-closed return ``b""`` from a later iteration eats the
        whole buffer). Phase 1 fails-closed without touching audit
        state; phase 2 commits both.
        """
        if not buf:
            return b""
        # Phase 1 — resolve every placeholder match's substitute. On any
        # backend error: fail-closed denial, return b"" without emitting
        # an allowed audit for any prior placeholder in this buffer.
        pending: list[tuple[bytes, str, SecretSpec]] = []
        for placeholder, name, spec, inject in self._targets:
            if placeholder not in buf:
                continue
            if name not in self._rendered_cache:
                if spec.compose is not None:
                    # Composite path: delegate to the addon's
                    # ``_fetch_and_render_composite`` (via the resolver
                    # closure). The resolver owns ALL failure-path bookkeeping
                    # — on None return it has already set ``flow.response =
                    # 503`` and emitted ``composite_unavailable`` /
                    # ``composite_fetch_error`` / ``render_failed`` to audit
                    # with the ``compose:`` list, matching the header path's
                    # failure shape. We fail-closed locally (drop buffer,
                    # signal end-of-stream) without emitting a second audit.
                    #
                    # ``_fetch_and_render_composite`` catches BackendUnavailableError,
                    # SecretNotFoundError, Exception (composite_fetch_error)
                    # and TemplateRenderError. Anything else — e.g. a closure
                    # capture bug, a RecursionError or MemoryError during
                    # render — would otherwise propagate up through
                    # mitmproxy's streaming machinery without ``flow.response``
                    # being set, leaving placeholder bytes uncleared. G6
                    # fail-closed requires us to catch here and 503.
                    try:
                        rendered = self._composite_resolver(name, spec)
                    except Exception as e:  # noqa: BLE001
                        _log.exception(
                            "unexpected exception in body composite resolver for %s: %s",
                            name,
                            type(e).__name__,
                        )
                        self._emit_fail_closed_denial(
                            secret_name=name,
                            reason=f"composite_render_unexpected_error:{type(e).__name__}",
                            message=b"agent-vault-proxy: composite render failed unexpectedly\n",
                        )
                        return b""
                    if rendered is None:
                        self._fetch_failed = True
                        self._buffer.clear()
                        return b""
                    # Resolver contract (review Council seat 1): a non-None
                    # return means the resolver did NOT touch ``flow.response``.
                    # If a future refactor of ``_fetch_and_render_composite``
                    # ever returns a string AND sets a 503, we would happily
                    # substitute into a body whose response is already torn —
                    # racier and harder to detect than a clean failure. Lock
                    # the contract here.
                    assert self._flow.response is None, (
                        "composite_resolver returned a rendered value but already "
                        "set flow.response; resolver contract violated"
                    )
                    self._rendered_cache[name] = rendered.encode("utf-8")
                else:
                    try:
                        real_secret = self._client.get(name)
                    except (BackendUnavailableError, SecretNotFoundError) as e:
                        self._emit_fail_closed_denial(
                            secret_name=name,
                            reason=f"secret_unavailable:{type(e).__name__}",
                            message=b"agent-vault-proxy: secret unavailable\n",
                        )
                        return b""
                    except Exception as e:  # noqa: BLE001
                        # G6 fail-closed mirror of header path's catch-all.
                        _log.exception(
                            "unexpected backend exception fetching body-injection secret %s: %s",
                            name,
                            type(e).__name__,
                        )
                        self._emit_fail_closed_denial(
                            secret_name=name,
                            reason=f"secret_fetch_error:{type(e).__name__}",
                            message=b"agent-vault-proxy: secret fetch failed\n",
                        )
                        return b""
                    self._rendered_cache[name] = inject.render_value(
                        real_secret=real_secret,
                        secret_name=name,
                    ).encode("utf-8")
            pending.append((placeholder, name, spec))
        # Phase 2 — every fetch succeeded; emit per-secret allowed audits
        # (one per first occurrence per request) BEFORE returning the
        # bytes with real secrets, then perform the in-place replacements.
        # This matches the header path's G6 ordering invariant (audit
        # before action) AND preserves audit-history consistency: the
        # request's audit reflects exactly the substitutions the upstream
        # will see.
        out = buf
        for placeholder, name, spec in pending:
            if name not in self._matched_names:
                self._matched_names.add(name)
                self._audit.emit(
                    {
                        "type": "inject_decision",
                        "request_id": self._request_id,
                        "decision": "allowed",
                        "reason": "body_binding_matched",
                        "secret_name": name,
                        "binding_source": spec.binding_source,
                        "destination": {
                            "host": self._target_host,
                            "port": self._flow.request.port,
                            "path_prefix": self._flow.request.path.split("?", 1)[0][:64],
                        },
                    }
                )
            out = out.replace(placeholder, self._rendered_cache[name])
        return out

    def _emit_fail_closed_denial(self, *, secret_name: str, reason: str, message: bytes) -> None:
        self._fetch_failed = True
        # Drop held bytes — request is aborting; the buffer would otherwise
        # pin memory until the replacer is GC'd.
        self._buffer.clear()
        emit_denial_and_503(
            audit=self._audit,
            flow=self._flow,
            request_id=self._request_id,
            reason=reason,
            secret_name=secret_name,
            message=message,
            target_host=self._target_host,
        )
