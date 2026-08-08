"""Tests for P0.6 BodyInjector — streaming body substitution.

The contract these tests pin:

* Each placeholder occurrence in the request body bytes is replaced
  in place via ``flow.request.stream = _BodyReplacer(...)``.
* The replacer is boundary-correct — placeholders split across chunk
  boundaries by mitmproxy's chunking still get detected.
* Backend fetch failures cause a 503 + audit denial, body bytes
  forwarded after the failure are eaten.
* Header injection and body injection can coexist on the same host
  for different secrets in the same request.
* ``Content-Type`` is an optional filter — mismatch causes a
  passthrough stream (no audit, request forwarded unmodified).
* ``Content-Length`` is dropped and ``Transfer-Encoding: chunked``
  added when body injection is set up — the post-replacement length
  is not knowable until the stream finishes.

See ``avp-p06-body-injector-design.md`` for the design rationale.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from mitmproxy.test import tflow

from kow.addon import AgentVaultProxyAddon
from kow.audit import AuditWriter
from kow.backends import BackendUnavailableError, FetchContext
from kow.caching import CachingSecretsClient
from kow.config import load_config
from kow.injectors.body import _BodyReplacer

BODY_PLACEHOLDER = "tok_PLACEHOLDER_01HXY1234567890ABC"  # 35 chars
BODY_REAL = "tok-real-XYZ"
HEADER_PLACEHOLDER = "sk-PLACEHOLDER-01HXY1234567890ABCDEFGHIJ"
HEADER_REAL = "sk-real-ABC"


class _FakeBackend:
    """In-memory backend keyed by name. Configurable per-name failure."""

    def __init__(
        self,
        *,
        per_name: dict[str, str] | None = None,
        fail_names: set[str] | None = None,
    ) -> None:
        self._per_name = per_name or {}
        self._fail_names = fail_names or set()

    def fetch(self, name: str, ctx: FetchContext | None = None) -> str:
        if name in self._fail_names:
            raise BackendUnavailableError(f"simulated outage for {name}")
        return self._per_name[name]


def _make_client(
    *, per_name: dict[str, str], fail_names: set[str] | None = None
) -> CachingSecretsClient:
    return CachingSecretsClient(
        _FakeBackend(per_name=per_name, fail_names=fail_names),
        ttl_seconds=300,
        jitter_seconds=0,
        max_entries=100,
    )


def _build_addon(tmp_path: Path, config_yaml: str) -> tuple[AgentVaultProxyAddon, Path]:
    audit_path = tmp_path / "audit.jsonl"
    # Use sentinel replace instead of str.format() because the YAML
    # strings contain literal ``{NAME}`` placeholders for the secret
    # name, which would collide with ``str.format`` syntax.
    config_yaml = config_yaml.replace("__AUDIT_PATH__", str(audit_path))
    config_path = tmp_path / "bindings.yaml"
    config_path.write_text(config_yaml)
    addon = AgentVaultProxyAddon()
    addon.config = load_config(config_path)
    addon.audit = AuditWriter(str(audit_path))
    return addon, audit_path


def _read_audit(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def _make_request(
    host: str,
    *,
    method: str = "POST",
    path: str = "/v1/webhook",
    headers: dict[str, str] | None = None,
) -> Any:
    flow = tflow.tflow()
    flow.request.host = host
    flow.request.port = 443
    flow.request.scheme = "https"
    flow.request.method = method
    flow.request.path = path
    if headers:
        for k, v in headers.items():
            flow.request.headers[k] = v
    return flow


_BODY_ONLY_CONFIG = f"""
version: 1

secrets:
  WEBHOOK_TOKEN:
    placeholder: "{BODY_PLACEHOLDER}"
    inject:
      type: body
      format: "{{WEBHOOK_TOKEN}}"
    bindings:
      - host: "hooks.example.com"
        methods: [POST]

unmatched_destination_policy: forward_unmodified

audit:
  path: __AUDIT_PATH__
  fail_on_unwritable: true
"""


def _stream_through(replacer: Any, chunks: list[bytes]) -> bytes:
    """Drive a _BodyReplacer instance through a chunk sequence, returning
    the concatenated output. The final empty chunk signals end-of-stream
    (mitmproxy's convention)."""
    out = bytearray()
    for chunk in chunks:
        out.extend(replacer(chunk))
    out.extend(replacer(b""))
    return bytes(out)


def test_body_injector_basic_single_chunk(tmp_path: Path) -> None:
    """Placeholder fully contained in one chunk, single occurrence."""
    addon, audit_path = _build_addon(tmp_path, _BODY_ONLY_CONFIG)
    addon.client = _make_client(per_name={"WEBHOOK_TOKEN": BODY_REAL})

    flow = _make_request("hooks.example.com")
    addon.requestheaders(flow)

    assert callable(flow.request.stream), "expected streaming replacer attached"
    assert "Content-Length" not in flow.request.headers
    assert flow.request.headers["Transfer-Encoding"] == "chunked"

    body_in = json.dumps({"token": BODY_PLACEHOLDER, "msg": "hi"}).encode()
    body_out = _stream_through(flow.request.stream, [body_in])
    assert BODY_PLACEHOLDER.encode() not in body_out
    assert BODY_REAL.encode() in body_out
    parsed = json.loads(body_out)
    assert parsed["token"] == BODY_REAL
    assert parsed["msg"] == "hi"

    events = _read_audit(audit_path)
    allowed = [e for e in events if e.get("decision") == "allowed"]
    assert len(allowed) == 1
    assert allowed[0]["reason"] == "body_binding_matched"
    assert allowed[0]["secret_name"] == "WEBHOOK_TOKEN"


def test_body_injector_placeholder_spans_chunk_boundary(tmp_path: Path) -> None:
    """The load-bearing streaming-correctness test: a placeholder split
    arbitrarily across two (or more) chunks must still be detected and
    substituted. This is the case where a naive per-chunk ``replace()``
    would miss the match."""
    addon, _ = _build_addon(tmp_path, _BODY_ONLY_CONFIG)
    addon.client = _make_client(per_name={"WEBHOOK_TOKEN": BODY_REAL})
    flow = _make_request("hooks.example.com")
    addon.requestheaders(flow)

    body = f'{{"token":"{BODY_PLACEHOLDER}","msg":"hi"}}'.encode()
    # Cut every plausible boundary across the placeholder, including
    # 1-byte chunks (worst case for the overlap buffer).
    placeholder_start = body.index(BODY_PLACEHOLDER.encode())
    placeholder_end = placeholder_start + len(BODY_PLACEHOLDER)
    for split in range(placeholder_start + 1, placeholder_end):
        flow2 = _make_request("hooks.example.com")
        addon.requestheaders(flow2)
        out = _stream_through(flow2.request.stream, [body[:split], body[split:]])
        assert BODY_PLACEHOLDER.encode() not in out, (
            f"placeholder leaked when split at byte {split}"
        )
        assert BODY_REAL.encode() in out, f"replacement missing when split at byte {split}"

    # One-byte chunks — the worst-case overlap stress.
    flow3 = _make_request("hooks.example.com")
    addon.requestheaders(flow3)
    out = _stream_through(flow3.request.stream, [bytes([b]) for b in body])
    assert BODY_PLACEHOLDER.encode() not in out
    assert BODY_REAL.encode() in out


def test_body_injector_multiple_occurrences(tmp_path: Path) -> None:
    """Same placeholder appears N times in a body — all get replaced."""
    addon, _ = _build_addon(tmp_path, _BODY_ONLY_CONFIG)
    addon.client = _make_client(per_name={"WEBHOOK_TOKEN": BODY_REAL})
    flow = _make_request("hooks.example.com")
    addon.requestheaders(flow)

    body = (
        f'{{"a":"{BODY_PLACEHOLDER}","b":"{BODY_PLACEHOLDER}","c":"{BODY_PLACEHOLDER}"}}'
    ).encode()
    out = _stream_through(flow.request.stream, [body])
    assert BODY_PLACEHOLDER.encode() not in out
    assert out.count(BODY_REAL.encode()) == 3


def test_body_injector_no_placeholder_passes_through(tmp_path: Path) -> None:
    """Body without the placeholder forwards bit-identical."""
    addon, audit_path = _build_addon(tmp_path, _BODY_ONLY_CONFIG)
    addon.client = _make_client(per_name={"WEBHOOK_TOKEN": BODY_REAL})
    flow = _make_request("hooks.example.com")
    addon.requestheaders(flow)

    body = b'{"hello": "world", "n": 42}'
    out = _stream_through(flow.request.stream, [body])
    assert out == body

    events = _read_audit(audit_path)
    allowed = [e for e in events if e.get("decision") == "allowed"]
    assert allowed == [], "no placeholder match should produce no allowed event"


def test_body_injector_secret_unavailable_fails_503(tmp_path: Path) -> None:
    """Backend down ⇒ 503 + audit denial; remaining chunks eaten."""
    addon, audit_path = _build_addon(tmp_path, _BODY_ONLY_CONFIG)
    addon.client = _make_client(per_name={"WEBHOOK_TOKEN": BODY_REAL}, fail_names={"WEBHOOK_TOKEN"})
    flow = _make_request("hooks.example.com")
    addon.requestheaders(flow)

    body = f'{{"token":"{BODY_PLACEHOLDER}"}}'.encode()
    out = _stream_through(flow.request.stream, [body])
    # Body MUST NOT be forwarded after fail-closed kicks in.
    assert out == b""
    assert flow.response is not None
    assert flow.response.status_code == 503

    events = _read_audit(audit_path)
    denied = [e for e in events if e.get("decision") == "denied"]
    assert len(denied) == 1
    assert denied[0]["reason"].startswith("secret_unavailable:")
    assert denied[0]["secret_name"] == "WEBHOOK_TOKEN"


def test_body_injector_chunked_encoding_set(tmp_path: Path) -> None:
    """Content-Length removed; Transfer-Encoding: chunked added."""
    addon, _ = _build_addon(tmp_path, _BODY_ONLY_CONFIG)
    addon.client = _make_client(per_name={"WEBHOOK_TOKEN": BODY_REAL})
    flow = _make_request("hooks.example.com", headers={"Content-Length": "100"})
    addon.requestheaders(flow)

    assert "Content-Length" not in flow.request.headers
    assert flow.request.headers["Transfer-Encoding"] == "chunked"


_CONTENT_TYPE_CONFIG = f"""
version: 1

secrets:
  WEBHOOK_TOKEN:
    placeholder: "{BODY_PLACEHOLDER}"
    inject:
      type: body
      content_type: "application/json"
      format: "{{WEBHOOK_TOKEN}}"
    bindings:
      - host: "hooks.example.com"
        methods: [POST]

unmatched_destination_policy: forward_unmodified

audit:
  path: __AUDIT_PATH__
  fail_on_unwritable: true
"""


def test_body_injector_content_type_match(tmp_path: Path) -> None:
    """Content-Type matches ⇒ substitution fires."""
    addon, _ = _build_addon(tmp_path, _CONTENT_TYPE_CONFIG)
    addon.client = _make_client(per_name={"WEBHOOK_TOKEN": BODY_REAL})
    flow = _make_request(
        "hooks.example.com",
        headers={"Content-Type": "application/json; charset=utf-8"},
    )
    addon.requestheaders(flow)

    out = _stream_through(flow.request.stream, [f'{{"t":"{BODY_PLACEHOLDER}"}}'.encode()])
    assert BODY_REAL.encode() in out
    assert BODY_PLACEHOLDER.encode() not in out


def test_body_injector_content_type_mismatch_passthrough(tmp_path: Path) -> None:
    """Content-Type mismatch ⇒ stream=True passthrough, body unchanged."""
    addon, audit_path = _build_addon(tmp_path, _CONTENT_TYPE_CONFIG)
    addon.client = _make_client(per_name={"WEBHOOK_TOKEN": BODY_REAL})
    flow = _make_request(
        "hooks.example.com",
        headers={"Content-Type": "application/octet-stream"},
    )
    addon.requestheaders(flow)
    # Passthrough is signalled via stream=True (no replacer); the body
    # contains a placeholder but won't be touched.
    assert flow.request.stream is True
    # No chunked-encoding flip on passthrough — the original framing is
    # preserved bit-for-bit.
    assert "Transfer-Encoding" not in flow.request.headers
    events = _read_audit(audit_path)
    # No deny audit for content-type filter — it's a filter, not a gate.
    denied = [e for e in events if e.get("decision") == "denied"]
    assert denied == []


_HEADER_AND_BODY_CONFIG = f"""
version: 1

secrets:
  AUTH_HEADER:
    placeholder: "{HEADER_PLACEHOLDER}"
    inject:
      type: header
      header: "Authorization"
      format: "Bearer {{AUTH_HEADER}}"
    bindings:
      - host: "hooks.example.com"
  WEBHOOK_TOKEN:
    placeholder: "{BODY_PLACEHOLDER}"
    inject:
      type: body
      format: "{{WEBHOOK_TOKEN}}"
    bindings:
      - host: "hooks.example.com"
        methods: [POST]

unmatched_destination_policy: forward_unmodified

audit:
  path: __AUDIT_PATH__
  fail_on_unwritable: true
"""


def test_body_injector_coexists_with_header_injector(tmp_path: Path) -> None:
    """Different secrets bound header + body on the same host both fire."""
    addon, audit_path = _build_addon(tmp_path, _HEADER_AND_BODY_CONFIG)
    addon.client = _make_client(per_name={"AUTH_HEADER": HEADER_REAL, "WEBHOOK_TOKEN": BODY_REAL})
    flow = _make_request(
        "hooks.example.com",
        headers={"Authorization": f"Bearer {HEADER_PLACEHOLDER}"},
    )
    addon.requestheaders(flow)

    # Header substitution happened.
    assert flow.request.headers["Authorization"] == f"Bearer {HEADER_REAL}"
    # Body streaming wired up.
    assert callable(flow.request.stream)
    body_out = _stream_through(flow.request.stream, [f'{{"t":"{BODY_PLACEHOLDER}"}}'.encode()])
    assert BODY_REAL.encode() in body_out

    events = _read_audit(audit_path)
    allowed = [e for e in events if e.get("decision") == "allowed"]
    # Two allowed events: one from header path, one from body path.
    reasons = {e["reason"] for e in allowed}
    assert "binding_matched" in reasons  # header
    assert "body_binding_matched" in reasons  # body


def test_body_injector_method_scope_violation_audits_and_skips(tmp_path: Path) -> None:
    """A body binding scoped to POST should NOT fire on GET; emits a
    scope_violation audit but doesn't deny the request (forward-unmodified)."""
    addon, audit_path = _build_addon(tmp_path, _BODY_ONLY_CONFIG)
    addon.client = _make_client(per_name={"WEBHOOK_TOKEN": BODY_REAL})
    flow = _make_request("hooks.example.com", method="GET")
    addon.requestheaders(flow)

    # No streaming setup because the only candidate was scope-rejected.
    assert flow.request.stream is False or flow.request.stream is None
    events = _read_audit(audit_path)
    scope_violations = [
        e
        for e in events
        if e.get("reason") == "binding_scope_violation" and e.get("secret_name") == "WEBHOOK_TOKEN"
    ]
    assert len(scope_violations) == 1


def test_body_injector_unbound_host_does_not_set_stream(tmp_path: Path) -> None:
    """A host without any body binding doesn't get the streaming setup."""
    addon, _ = _build_addon(tmp_path, _BODY_ONLY_CONFIG)
    addon.client = _make_client(per_name={"WEBHOOK_TOKEN": BODY_REAL})
    # forward_unmodified policy + unbound host — no streaming.
    flow = _make_request("other.example.com")
    addon.requestheaders(flow)
    assert flow.request.stream is False or flow.request.stream is None
    assert "Transfer-Encoding" not in flow.request.headers


def test_body_replacer_constant_memory_on_large_body(tmp_path: Path) -> None:
    """Streaming guarantee: the overlap buffer never grows beyond
    ``max_needle_len - 1`` bytes regardless of body size. This is a
    structural test — we feed many small chunks and observe the
    instance's internal buffer never exceeds the bound."""
    addon, _ = _build_addon(tmp_path, _BODY_ONLY_CONFIG)
    addon.client = _make_client(per_name={"WEBHOOK_TOKEN": BODY_REAL})
    flow = _make_request("hooks.example.com")
    addon.requestheaders(flow)

    replacer = flow.request.stream
    assert isinstance(replacer, _BodyReplacer)
    keep = replacer._max_needle_len - 1

    # 1 MB of random body, fed as 1 KB chunks. Verify the residual buffer
    # never exceeds ``keep`` bytes after a successful emit. (During a
    # processing call the buffer transiently holds ``overlap + chunk``,
    # but post-emit it returns to ≤ keep bytes.)
    import os

    chunk_size = 1024
    total_chunks = 1024  # 1 MB
    max_buf_seen = 0
    for _ in range(total_chunks):
        chunk = os.urandom(chunk_size)
        _ = replacer(chunk)
        max_buf_seen = max(max_buf_seen, len(replacer._buffer))
    # Final flush
    _ = replacer(b"")
    assert max_buf_seen <= keep, (
        f"residual buffer exceeded bound: saw {max_buf_seen} bytes, max allowed {keep}"
    )


def test_body_injector_format_with_prefix(tmp_path: Path) -> None:
    """``format: 'sha256:{NAME}'`` should produce ``sha256:<real>`` in the
    body, not just the raw secret."""
    yaml = f"""
version: 1
secrets:
  WEBHOOK_TOKEN:
    placeholder: "{BODY_PLACEHOLDER}"
    inject:
      type: body
      format: "sha256:{{WEBHOOK_TOKEN}}"
    bindings:
      - host: "hooks.example.com"
        methods: [POST]
unmatched_destination_policy: forward_unmodified
audit:
  path: __AUDIT_PATH__
  fail_on_unwritable: true
"""
    addon, _ = _build_addon(tmp_path, yaml)
    addon.client = _make_client(per_name={"WEBHOOK_TOKEN": BODY_REAL})
    flow = _make_request("hooks.example.com")
    addon.requestheaders(flow)
    out = _stream_through(flow.request.stream, [f'{{"x":"{BODY_PLACEHOLDER}"}}'.encode()])
    assert b'"x":"sha256:tok-real-XYZ"' in out


def test_body_injector_lazy_fetch_no_call_when_placeholder_absent(tmp_path: Path) -> None:
    """If the request body never contains the placeholder, the backend
    is never called. Important for hosts where body binding is configured
    but most traffic doesn't trigger it."""
    addon, _ = _build_addon(tmp_path, _BODY_ONLY_CONFIG)

    call_log: list[str] = []

    class _RecordingBackend:
        def fetch(self, name: str, ctx: FetchContext | None = None) -> str:
            call_log.append(name)
            return BODY_REAL

    addon.client = CachingSecretsClient(
        _RecordingBackend(), ttl_seconds=300, jitter_seconds=0, max_entries=100
    )
    flow = _make_request("hooks.example.com")
    addon.requestheaders(flow)

    _ = _stream_through(flow.request.stream, [b'{"no_placeholder_here": "value"}'])
    assert call_log == [], (
        "backend was called even though the placeholder was absent — lazy-fetch invariant violated"
    )


def test_body_injector_two_phase_commit_no_orphan_audits_on_partial_fail(
    tmp_path: Path,
) -> None:
    """Adversarial-review finding: when a buffer contains placeholders
    for multiple secrets and ONE later fetch fails, the earlier secrets'
    ``allowed`` audits must NOT have been emitted — those substituted
    bytes never actually reach the upstream because we return b"" on
    failure. Two-phase commit (fetch-all then audit+replace) guarantees
    audit history reflects exactly what the upstream sees."""
    yaml = """
version: 1

secrets:
  TOKEN_A:
    placeholder: "aaa_PLACEHOLDER_01HXY1234567890ABC"
    inject:
      type: body
      format: "{TOKEN_A}"
    bindings:
      - host: "hooks.example.com"
        methods: [POST]
  TOKEN_B:
    placeholder: "bbb_PLACEHOLDER_01HXY1234567890ABC"
    inject:
      type: body
      format: "{TOKEN_B}"
    bindings:
      - host: "hooks.example.com"
        methods: [POST]

unmatched_destination_policy: forward_unmodified

audit:
  path: __AUDIT_PATH__
  fail_on_unwritable: true
"""
    addon, audit_path = _build_addon(tmp_path, yaml)
    # TOKEN_A available, TOKEN_B fails.
    addon.client = _make_client(
        per_name={"TOKEN_A": "real-A", "TOKEN_B": "real-B"},
        fail_names={"TOKEN_B"},
    )
    flow = _make_request("hooks.example.com")
    addon.requestheaders(flow)

    body = b'{"a":"aaa_PLACEHOLDER_01HXY1234567890ABC","b":"bbb_PLACEHOLDER_01HXY1234567890ABC"}'
    out = _stream_through(flow.request.stream, [body])
    # Fail-closed: nothing emitted (real-A's bytes never reach upstream).
    assert out == b""
    assert flow.response is not None and flow.response.status_code == 503

    events = _read_audit(audit_path)
    allowed = [e for e in events if e.get("decision") == "allowed"]
    denied = [e for e in events if e.get("decision") == "denied"]
    # No orphan allowed audit for TOKEN_A — its substituted bytes never
    # reached the upstream, so the audit history MUST NOT claim it did.
    assert allowed == [], (
        "TOKEN_A allowed audit emitted but its bytes never reached upstream "
        "(fail-closed on TOKEN_B). Audit history is inconsistent."
    )
    assert len(denied) == 1
    assert denied[0]["secret_name"] == "TOKEN_B"


def test_body_injector_fail_closed_clears_buffer(tmp_path: Path) -> None:
    """the streaming replacer's
    held buffer should be released the moment fail-closed fires,
    not held until GC. Defensive memory hygiene — subsequent chunks
    are eaten unconditionally, no reason to keep their predecessors."""
    addon, _ = _build_addon(tmp_path, _BODY_ONLY_CONFIG)
    addon.client = _make_client(per_name={"WEBHOOK_TOKEN": BODY_REAL}, fail_names={"WEBHOOK_TOKEN"})
    flow = _make_request("hooks.example.com")
    addon.requestheaders(flow)

    replacer = flow.request.stream
    body = f'{{"token":"{BODY_PLACEHOLDER}"}}'.encode()
    _ = replacer(body)
    # Failure should have fired and cleared the buffer.
    assert replacer._fetch_failed is True
    assert len(replacer._buffer) == 0, "buffer should be cleared on fail-closed"


# NOTE: body composite (inject.template + compose:) was deferred in P0.6 and
# is now supported — the original "rejects template" test is replaced by the
# composite acceptance + render tests below.


# ---------------------------------------------------------------------------
# Composite body bindings — inject.template + compose: on a body injector
# ---------------------------------------------------------------------------

# 35-char placeholder for the composite-rendered output; distinct from the
# single-secret BODY_PLACEHOLDER above so the existing fixture-config tests
# stay deterministic.
COMPOSITE_BODY_PLACEHOLDER = "cmp_PLACEHOLDER_01HXY1234567890ABC"  # 35 chars


_BODY_COMPOSITE_CONFIG = f"""
version: 1

secrets:
  WEBHOOK_HMAC:
    placeholder: "{COMPOSITE_BODY_PLACEHOLDER}"
    inject:
      type: body
      content_type: "application/json"
      template: "{{{{ (KEY + ':' + MSG) | b64encode }}}}"
    compose:
      - KEY
      - MSG
    bindings:
      - host: "hooks.example.com"
        methods: [POST]

unmatched_destination_policy: forward_unmodified

audit:
  path: __AUDIT_PATH__
  fail_on_unwritable: true
"""


def test_body_composite_renders_via_b64encode(tmp_path: Path) -> None:
    """Body composite with two compose secrets + b64encode filter renders
    deterministically and the placeholder in the body is replaced with the
    rendered bytes. Mirrors the header composite end-to-end shape."""
    addon, audit_path = _build_addon(tmp_path, _BODY_COMPOSITE_CONFIG)
    addon.client = _make_client(per_name={"KEY": "alice", "MSG": "ping"})

    flow = _make_request(
        "hooks.example.com",
        headers={"Content-Type": "application/json"},
    )
    addon.requestheaders(flow)
    assert callable(flow.request.stream), "expected streaming replacer attached"

    body_in = json.dumps({"sig": COMPOSITE_BODY_PLACEHOLDER, "ok": True}).encode()
    body_out = _stream_through(flow.request.stream, [body_in])
    assert COMPOSITE_BODY_PLACEHOLDER.encode() not in body_out
    parsed = json.loads(body_out)
    # b64encode("alice:ping") = "YWxpY2U6cGluZw=="
    assert parsed["sig"] == "YWxpY2U6cGluZw=="
    assert parsed["ok"] is True

    events = _read_audit(audit_path)
    allowed = [e for e in events if e.get("decision") == "allowed"]
    assert len(allowed) == 1
    assert allowed[0]["reason"] == "body_binding_matched"
    assert allowed[0]["secret_name"] == "WEBHOOK_HMAC"
    # Hot-path audit on success does NOT include compose: list — mirrors
    # the header composite contract (see addon.py:642-646).
    assert "compose" not in allowed[0]


def test_body_composite_fail_closed_on_backend_unavailable(tmp_path: Path) -> None:
    """A composite leg's BWS fetch failure must 503 the request, emit
    ``composite_unavailable`` with the compose list in audit, and eat the
    remaining body bytes (no partial leak of the placeholder upstream)."""
    addon, audit_path = _build_addon(tmp_path, _BODY_COMPOSITE_CONFIG)
    addon.client = _make_client(
        per_name={"KEY": "alice", "MSG": "ping"},
        fail_names={"MSG"},
    )

    flow = _make_request(
        "hooks.example.com",
        headers={"Content-Type": "application/json"},
    )
    addon.requestheaders(flow)
    assert callable(flow.request.stream)

    body_in = json.dumps({"sig": COMPOSITE_BODY_PLACEHOLDER}).encode()
    body_out = _stream_through(flow.request.stream, [body_in])
    # Composite resolver set flow.response = 503 + emitted audit; the
    # replacer signals end-of-stream by returning b"" thereafter, and any
    # already-emitted post-failure bytes must NOT contain the placeholder.
    assert COMPOSITE_BODY_PLACEHOLDER.encode() not in body_out
    assert flow.response is not None
    assert flow.response.status_code == 503

    events = _read_audit(audit_path)
    denied = [e for e in events if e.get("decision") == "denied"]
    assert len(denied) == 1
    assert denied[0]["reason"].startswith("composite_unavailable:")
    assert denied[0]["secret_name"] == "WEBHOOK_HMAC"
    # Failure-path audit MUST include compose: list (operator forensics).
    assert denied[0]["compose"] == ["KEY", "MSG"]


def test_body_composite_render_failed_audits_generic_reason(tmp_path: Path) -> None:
    """Render failure (e.g., b64decode on non-base64 input) must 503 and
    audit ``reason: render_failed`` — generic, no template internals leaked
    via the agent-observable response or the audit log."""
    config_yaml = _BODY_COMPOSITE_CONFIG.replace(
        "\"{{ (KEY + ':' + MSG) | b64encode }}\"",
        '"{{ KEY | b64decode }}"',
    )
    addon, audit_path = _build_addon(tmp_path, config_yaml)
    # KEY is set to a non-base64 value; b64decode will raise
    # TemplateRenderError at render time.
    addon.client = _make_client(per_name={"KEY": "not!base64!", "MSG": "x"})

    flow = _make_request(
        "hooks.example.com",
        headers={"Content-Type": "application/json"},
    )
    addon.requestheaders(flow)

    body_in = json.dumps({"sig": COMPOSITE_BODY_PLACEHOLDER}).encode()
    _stream_through(flow.request.stream, [body_in])
    assert flow.response is not None
    assert flow.response.status_code == 503

    events = _read_audit(audit_path)
    denied = [e for e in events if e.get("decision") == "denied"]
    assert len(denied) == 1
    assert denied[0]["reason"] == "render_failed"
    assert denied[0]["secret_name"] == "WEBHOOK_HMAC"
    assert denied[0]["compose"] == ["KEY", "MSG"]


_BODY_COMPOSITE_TOTP_CONFIG = f"""
version: 1

secrets:
  TOTP_BODY:
    placeholder: "{COMPOSITE_BODY_PLACEHOLDER}"
    inject:
      type: body
      content_type: "application/json"
      template: "{{{{ totp(TOTP_SECRET) }}}}"
    compose:
      - TOTP_SECRET
    bindings:
      - host: "api.example.com"
        methods: [POST]
        paths: ["/account/totp"]

unmatched_destination_policy: forward_unmodified

audit:
  path: __AUDIT_PATH__
  fail_on_unwritable: true
"""


def test_body_composite_totp_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The motivating use case: a 2FA TOTP code computed inside AVP from a
    base32 secret and injected into the request body. Time is frozen against
    the RFC 6238 §5.2 SHA-1 vector at T=59s → 6-digit code 287082."""
    import kow.template as template_module

    monkeypatch.setattr(template_module.time, "time", lambda: 59.0)

    addon, audit_path = _build_addon(tmp_path, _BODY_COMPOSITE_TOTP_CONFIG)
    addon.client = _make_client(
        per_name={"TOTP_SECRET": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"},
    )

    flow = _make_request(
        "api.example.com",
        path="/account/totp",
        headers={"Content-Type": "application/json"},
    )
    addon.requestheaders(flow)
    assert callable(flow.request.stream)

    body_in = json.dumps(
        {"totp_token": "session-handle-from-/login", "code": COMPOSITE_BODY_PLACEHOLDER}
    ).encode()
    body_out = _stream_through(flow.request.stream, [body_in])

    assert COMPOSITE_BODY_PLACEHOLDER.encode() not in body_out
    parsed = json.loads(body_out)
    assert parsed["code"] == "287082"
    assert parsed["totp_token"] == "session-handle-from-/login"  # untouched

    events = _read_audit(audit_path)
    allowed = [e for e in events if e.get("decision") == "allowed"]
    assert len(allowed) == 1
    assert allowed[0]["reason"] == "body_binding_matched"
    assert allowed[0]["secret_name"] == "TOTP_BODY"


def test_body_composite_coexists_with_single_secret_body_binding(tmp_path: Path) -> None:
    """A single request body that contains BOTH a composite-binding placeholder
    AND a single-secret-binding placeholder must substitute both correctly.
    Pins that the per-target branch (composite vs single) inside the
    replacer's two-phase commit doesn't trip when both paths execute."""
    config_yaml = f"""
version: 1

secrets:
  WEBHOOK_HMAC:
    placeholder: "{COMPOSITE_BODY_PLACEHOLDER}"
    inject:
      type: body
      content_type: "application/json"
      template: "{{{{ (KEY + ':' + MSG) | b64encode }}}}"
    compose:
      - KEY
      - MSG
    bindings:
      - host: "hooks.example.com"
        methods: [POST]
  WEBHOOK_PLAIN:
    placeholder: "{BODY_PLACEHOLDER}"
    inject:
      type: body
      content_type: "application/json"
      format: "{{WEBHOOK_PLAIN}}"
    bindings:
      - host: "hooks.example.com"
        methods: [POST]

unmatched_destination_policy: forward_unmodified

audit:
  path: __AUDIT_PATH__
  fail_on_unwritable: true
"""
    addon, audit_path = _build_addon(tmp_path, config_yaml)
    addon.client = _make_client(
        per_name={"KEY": "alice", "MSG": "ping", "WEBHOOK_PLAIN": BODY_REAL},
    )

    flow = _make_request(
        "hooks.example.com",
        headers={"Content-Type": "application/json"},
    )
    addon.requestheaders(flow)

    body_in = json.dumps({"sig": COMPOSITE_BODY_PLACEHOLDER, "token": BODY_PLACEHOLDER}).encode()
    body_out = _stream_through(flow.request.stream, [body_in])

    assert COMPOSITE_BODY_PLACEHOLDER.encode() not in body_out
    assert BODY_PLACEHOLDER.encode() not in body_out
    parsed = json.loads(body_out)
    assert parsed["sig"] == "YWxpY2U6cGluZw=="
    assert parsed["token"] == BODY_REAL

    events = _read_audit(audit_path)
    allowed = [e for e in events if e.get("decision") == "allowed"]
    assert {e["secret_name"] for e in allowed} == {"WEBHOOK_HMAC", "WEBHOOK_PLAIN"}


def test_body_composite_placeholder_spans_chunk_boundary(tmp_path: Path) -> None:
    """Chunk-boundary correctness must inherit from the single-secret path.
    Splitting the composite placeholder across two chunks at every byte
    boundary still detects + substitutes the rendered value. Same property
    proven for single-secret body bindings; this pins it for composite.
    Review R-9 closes the test gap."""
    addon, _ = _build_addon(tmp_path, _BODY_COMPOSITE_CONFIG)
    addon.client = _make_client(per_name={"KEY": "alice", "MSG": "ping"})

    body = f'{{"sig":"{COMPOSITE_BODY_PLACEHOLDER}","msg":"hi"}}'.encode()
    placeholder_start = body.index(COMPOSITE_BODY_PLACEHOLDER.encode())
    placeholder_end = placeholder_start + len(COMPOSITE_BODY_PLACEHOLDER)

    for split in range(placeholder_start + 1, placeholder_end):
        flow = _make_request(
            "hooks.example.com",
            headers={"Content-Type": "application/json"},
        )
        addon.requestheaders(flow)
        out = _stream_through(flow.request.stream, [body[:split], body[split:]])
        assert COMPOSITE_BODY_PLACEHOLDER.encode() not in out, (
            f"composite placeholder leaked when split at byte {split}"
        )
        assert b"YWxpY2U6cGluZw==" in out, f"rendered value missing when split at byte {split}"

    # Worst case: 1-byte chunks across the entire placeholder.
    flow_one_byte = _make_request(
        "hooks.example.com",
        headers={"Content-Type": "application/json"},
    )
    addon.requestheaders(flow_one_byte)
    out = _stream_through(flow_one_byte.request.stream, [bytes([b]) for b in body])
    assert COMPOSITE_BODY_PLACEHOLDER.encode() not in out
    assert b"YWxpY2U6cGluZw==" in out


def test_body_composite_resolver_uncaught_exception_fails_503(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the composite resolver raises an exception type ``_fetch_and_render
    _composite`` doesn't catch (e.g. RecursionError, MemoryError, a future
    closure-capture bug), the body replacer's catch-all converts it to a
    503 + denied audit instead of propagating through mitmproxy's streaming
    machinery — review R-8 / G6 fail-closed."""
    addon, audit_path = _build_addon(tmp_path, _BODY_COMPOSITE_CONFIG)
    addon.client = _make_client(per_name={"KEY": "alice", "MSG": "ping"})

    # Force the addon's composite render to raise an unexpected type. We
    # patch ``CompositeResolver.fetch_and_render`` itself rather than going
    # through the render layer — the test is specifically about exception
    # types the render layer's catches don't cover.
    def _boom(**_kwargs: object) -> str | None:
        raise RuntimeError("synthetic test failure")

    monkeypatch.setattr(addon._composite, "fetch_and_render", _boom)

    flow = _make_request(
        "hooks.example.com",
        headers={"Content-Type": "application/json"},
    )
    addon.requestheaders(flow)
    body_in = json.dumps({"sig": COMPOSITE_BODY_PLACEHOLDER}).encode()
    body_out = _stream_through(flow.request.stream, [body_in])

    assert COMPOSITE_BODY_PLACEHOLDER.encode() not in body_out
    assert flow.response is not None
    assert flow.response.status_code == 503

    events = _read_audit(audit_path)
    denied = [e for e in events if e.get("decision") == "denied"]
    assert len(denied) == 1
    assert denied[0]["reason"] == "composite_render_unexpected_error:RuntimeError"
    assert denied[0]["secret_name"] == "WEBHOOK_HMAC"


def test_body_composite_render_failure_does_not_leak_input_to_stderr(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The WARNING line emitted on render failure logs only the EXCEPTION
    CLASS NAME (e.g. ``TemplateRenderError``), never the exception message
    — which could legitimately include operator-supplied fragments (a base32
    secret that failed to decode, a Unicode position from an encode step).
    Stderr is commonly piped to log aggregators; this pins the no-leak
    contract — review R-1."""
    import logging

    # Use a body composite whose template fails at render time on a value
    # that is itself a substring of the (non-secret) input: b64decode on a
    # value containing the placeholder marker is enough to force a render
    # failure whose unwrapped message would carry the input shape.
    config_yaml = _BODY_COMPOSITE_CONFIG.replace(
        "\"{{ (KEY + ':' + MSG) | b64encode }}\"",
        '"{{ KEY | b64decode }}"',
    )
    addon, _ = _build_addon(tmp_path, config_yaml)
    # KEY is a fake "secret-shaped" string that exercises the b64decode
    # failure path. The test asserts this string never reaches stderr.
    fake_secret = "TOTPSECRET_DO_NOT_LOG_ME"
    addon.client = _make_client(per_name={"KEY": fake_secret, "MSG": "x"})

    flow = _make_request(
        "hooks.example.com",
        headers={"Content-Type": "application/json"},
    )
    addon.requestheaders(flow)

    with caplog.at_level(logging.WARNING, logger="kow.addon"):
        body_in = json.dumps({"sig": COMPOSITE_BODY_PLACEHOLDER}).encode()
        _stream_through(flow.request.stream, [body_in])

    assert flow.response is not None
    assert flow.response.status_code == 503

    # Iterate every captured record and confirm none of them carry the
    # fake secret value as a substring of the FORMATTED message.
    for record in caplog.records:
        assert fake_secret not in record.getMessage(), (
            f"secret value leaked into log record: {record.getMessage()!r}"
        )
