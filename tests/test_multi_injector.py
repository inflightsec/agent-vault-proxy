"""Tests for P0.7 MultiInjector — one secret feeding multiple injection sites.

The contract these tests pin:

* ``inject.type: multi`` lists 2-4 child injectors; child types are
  ``header`` or ``body`` (P0.7 leaf set). Each child carries its own
  ``format``/``template``/``header``/``content_type`` fields.
* The PARENT ``SecretSpec``'s placeholder is shared by all children —
  one rotatable credential, multiple injection sites.
* Multi cannot nest (no multi inside multi for v0.5.0 P0.7).
* Duplicate target sites per type are rejected at config-load:
  two header children targeting the same header name; more than one
  body child per multi.
* ``compose:`` cannot combine with multi at this phase (composition
  primitive + multi-target primitive don't fit cleanly).
* Header and body branches dispatch independently on the same request
  — the header path mutates ``flow.request.headers`` and the body path
  attaches a streaming replacer, sharing the parent placeholder.

See ``avp-superfly-port-design.md`` §7 P0.7 for the composition-order
roadmap (signer-last, body-mutator-after-signer warning) that activates
when the first signer type lands.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from mitmproxy.test import tflow
from pydantic import ValidationError

from kow.addon import AgentVaultProxyAddon
from kow.audit import AuditWriter
from kow.backends import FetchContext
from kow.caching import CachingSecretsClient
from kow.config import (
    BodyInjector,
    Config,
    HeaderInjector,
    MultiInjector,
    iter_leaf_injectors,
    load_config,
)

PLACEHOLDER = "tok_PLACEHOLDER_01HXY1234567890ABC"
REAL = "tok-real-XYZ"
_FOO_PH = "foo_PLACEHOLDER_01HXY1234567890"


class _FakeBackend:
    def __init__(self, per_name: dict[str, str]) -> None:
        self._per_name = per_name

    def fetch(self, name: str, ctx: FetchContext | None = None) -> str:
        return self._per_name[name]


def _make_client(per_name: dict[str, str]) -> CachingSecretsClient:
    return CachingSecretsClient(
        _FakeBackend(per_name), ttl_seconds=300, jitter_seconds=0, max_entries=100
    )


def _build_addon(tmp_path: Path, config_yaml: str) -> tuple[AgentVaultProxyAddon, Path]:
    audit_path = tmp_path / "audit.jsonl"
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


def _make_request(host: str, *, method: str = "POST", headers: dict[str, str] | None = None) -> Any:
    flow = tflow.tflow()
    flow.request.host = host
    flow.request.port = 443
    flow.request.scheme = "https"
    flow.request.method = method
    flow.request.path = "/v1/webhook"
    if headers:
        for k, v in headers.items():
            flow.request.headers[k] = v
    return flow


def _stream_through(replacer: Any, chunks: list[bytes]) -> bytes:
    out = bytearray()
    for chunk in chunks:
        out.extend(replacer(chunk))
    out.extend(replacer(b""))
    return bytes(out)


# ---------------------------------------------------------------------------
# Config-load tests — shape of the MultiInjector model + cross-validators
# ---------------------------------------------------------------------------


def test_multi_with_header_and_body_loads() -> None:
    """Canonical use case: one secret, header AND body site, both share
    the same placeholder."""
    config = Config.model_validate(
        {
            "version": 1,
            "secrets": {
                "FOO": {
                    "placeholder": _FOO_PH,
                    "inject": {
                        "type": "multi",
                        "injectors": [
                            {
                                "type": "header",
                                "header": "Authorization",
                                "format": "Bearer {FOO}",
                            },
                            {
                                "type": "body",
                                "content_type": "application/json",
                                "format": "{FOO}",
                            },
                        ],
                    },
                    "bindings": [{"host": "api.example.com"}],
                }
            },
            "audit": {"path": "/tmp/x.jsonl"},
        }
    )
    assert isinstance(config.secrets["FOO"].inject, MultiInjector)
    children = config.secrets["FOO"].inject.injectors
    assert len(children) == 2
    assert isinstance(children[0], HeaderInjector)
    assert isinstance(children[1], BodyInjector)


def test_multi_rejects_nested_multi() -> None:
    """Multi inside multi is structurally rejected — Pydantic's
    discriminator union enforces this because LeafInjectorSpec doesn't
    include ``multi`` as a valid type."""
    with pytest.raises(ValidationError):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {
                            "type": "multi",
                            "injectors": [
                                {
                                    "type": "header",
                                    "header": "X-A",
                                    "format": "{FOO}",
                                },
                                {
                                    "type": "multi",  # nested — rejected
                                    "injectors": [
                                        {
                                            "type": "header",
                                            "header": "X-B",
                                            "format": "{FOO}",
                                        },
                                    ],
                                },
                            ],
                        },
                        "bindings": [{"host": "api.example.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_multi_rejects_single_child() -> None:
    """Single-injector secrets should use the leaf type directly, not
    wrap it in a multi. Validator enforces a 2-child minimum."""
    with pytest.raises(ValidationError, match="2-4 children"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {
                            "type": "multi",
                            "injectors": [
                                {"type": "header", "header": "X-A", "format": "{FOO}"},
                            ],
                        },
                        "bindings": [{"host": "api.example.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_multi_rejects_more_than_four_children() -> None:
    """Cap mirrors compose: cap — operator-readable upper bound."""
    with pytest.raises(ValidationError, match="2-4 children"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {
                            "type": "multi",
                            "injectors": [
                                {"type": "header", "header": f"X-{i}", "format": "{FOO}"}
                                for i in range(5)
                            ],
                        },
                        "bindings": [{"host": "api.example.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_multi_rejects_duplicate_header_target() -> None:
    """Two header children targeting the same header name — the second
    would silently overwrite the first."""
    with pytest.raises(ValidationError, match="two header children"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {
                            "type": "multi",
                            "injectors": [
                                {
                                    "type": "header",
                                    "header": "Authorization",
                                    "format": "Bearer {FOO}",
                                },
                                {
                                    "type": "header",
                                    "header": "Authorization",  # collision
                                    "format": "Token {FOO}",
                                },
                            ],
                        },
                        "bindings": [{"host": "api.example.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_multi_rejects_duplicate_header_target_case_insensitive() -> None:
    """HTTP header names are case-insensitive per RFC 7230 — a multi
    declaring ``Authorization`` and ``authorization`` would silently
    overwrite on the wire (mitmproxy's headers dict is case-insensitive)."""
    with pytest.raises(ValidationError, match="case-insensitive"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {
                            "type": "multi",
                            "injectors": [
                                {
                                    "type": "header",
                                    "header": "Authorization",
                                    "format": "Bearer {FOO}",
                                },
                                {
                                    "type": "header",
                                    "header": "authorization",  # case-insensitive collision
                                    "format": "Token {FOO}",
                                },
                            ],
                        },
                        "bindings": [{"host": "api.example.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_multi_rejects_more_than_one_body_child() -> None:
    """Two body children would race on the same placeholder occurrence."""
    with pytest.raises(ValidationError, match="more than one body child"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {
                            "type": "multi",
                            "injectors": [
                                {"type": "body", "format": "{FOO}"},
                                {"type": "body", "format": "sha256:{FOO}"},
                            ],
                        },
                        "bindings": [{"host": "api.example.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_multi_rejects_compose() -> None:
    """`compose:` is for composite single-injector bindings; it does
    not combine with multi at this phase."""
    with pytest.raises(ValidationError, match="cannot be used with inject.type: multi"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {
                            "type": "multi",
                            "injectors": [
                                {"type": "header", "header": "X-A", "format": "{FOO}"},
                                {"type": "header", "header": "X-B", "format": "{FOO}"},
                            ],
                        },
                        "compose": ["X", "Y"],
                        "bindings": [{"host": "api.example.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_multi_format_placeholder_validation_walks_children() -> None:
    """The `validate_format_placeholders` cross-validator must walk
    each multi child's format string. A child whose format misses the
    named placeholder under v2 should still raise."""
    with pytest.raises(ValidationError, match=r"inject.format must contain"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {
                            "type": "multi",
                            "injectors": [
                                {
                                    "type": "header",
                                    "header": "X-A",
                                    "format": "Bearer {FOO}",
                                },
                                {
                                    "type": "body",
                                    "format": "no-placeholder-here",  # missing {FOO}
                                },
                            ],
                        },
                        "bindings": [{"host": "api.example.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_iter_leaf_injectors_flattens_multi() -> None:
    """The dispatch helper flattens a multi into its children; single
    injectors yield themselves."""
    config = Config.model_validate(
        {
            "version": 1,
            "secrets": {
                "FOO": {
                    "placeholder": _FOO_PH,
                    "inject": {
                        "type": "multi",
                        "injectors": [
                            {"type": "header", "header": "X-A", "format": "{FOO}"},
                            {"type": "body", "format": "{FOO}"},
                        ],
                    },
                    "bindings": [{"host": "api.example.com"}],
                }
            },
            "audit": {"path": "/tmp/x.jsonl"},
        }
    )
    leaves = iter_leaf_injectors(config.secrets["FOO"].inject)
    assert len(leaves) == 2
    assert isinstance(leaves[0], HeaderInjector)
    assert isinstance(leaves[1], BodyInjector)


# ---------------------------------------------------------------------------
# Runtime dispatch tests — both header + body fire on the same request
# ---------------------------------------------------------------------------


_MULTI_CONFIG = f"""
version: 1

secrets:
  WEBHOOK_TOKEN:
    placeholder: "{PLACEHOLDER}"
    inject:
      type: multi
      injectors:
        - type: header
          header: Authorization
          format: "Bearer {{WEBHOOK_TOKEN}}"
        - type: body
          content_type: application/json
          format: "{{WEBHOOK_TOKEN}}"
    bindings:
      - host: "hooks.example.com"
        methods: [POST]

unmatched_destination_policy: forward_unmodified

audit:
  path: __AUDIT_PATH__
  fail_on_unwritable: true
"""


def test_multi_dispatches_both_header_and_body(tmp_path: Path) -> None:
    """One secret with multi-injector fires the header path AND wires
    up the body streaming path on the same request."""
    addon, audit_path = _build_addon(tmp_path, _MULTI_CONFIG)
    addon.client = _make_client({"WEBHOOK_TOKEN": REAL})

    flow = _make_request(
        "hooks.example.com",
        headers={
            "Authorization": f"Bearer {PLACEHOLDER}",
            "Content-Type": "application/json",
        },
    )
    addon.requestheaders(flow)

    # Header substitution happened.
    assert flow.request.headers["Authorization"] == f"Bearer {REAL}"
    # Body streaming wired up.
    assert callable(flow.request.stream)
    body_out = _stream_through(flow.request.stream, [f'{{"t":"{PLACEHOLDER}"}}'.encode()])
    assert REAL.encode() in body_out
    assert PLACEHOLDER.encode() not in body_out

    events = _read_audit(audit_path)
    allowed = [e for e in events if e.get("decision") == "allowed"]
    reasons = {e["reason"] for e in allowed}
    # One header audit + one body audit, both for the same secret.
    assert "binding_matched" in reasons
    assert "body_binding_matched" in reasons
    assert all(e["secret_name"] == "WEBHOOK_TOKEN" for e in allowed)


def test_multi_header_only_request_still_audits_header(tmp_path: Path) -> None:
    """If the request contains the placeholder in the header but NOT
    in the body, the header path fires and the body streaming is set
    up but ultimately produces no body substitution."""
    addon, audit_path = _build_addon(tmp_path, _MULTI_CONFIG)
    addon.client = _make_client({"WEBHOOK_TOKEN": REAL})

    flow = _make_request(
        "hooks.example.com",
        headers={
            "Authorization": f"Bearer {PLACEHOLDER}",
            "Content-Type": "application/json",
        },
    )
    addon.requestheaders(flow)

    # Header substitution happened.
    assert flow.request.headers["Authorization"] == f"Bearer {REAL}"
    # Body streaming is wired but the agent's body has no placeholder.
    body_out = _stream_through(flow.request.stream, [b'{"k": "v"}'])
    assert body_out == b'{"k": "v"}'

    events = _read_audit(audit_path)
    allowed = [e for e in events if e.get("decision") == "allowed"]
    reasons = {e["reason"] for e in allowed}
    # Only the header path audits — body path had no match so no audit.
    assert "binding_matched" in reasons
    assert "body_binding_matched" not in reasons


def test_multi_body_only_request_audits_body_alone(tmp_path: Path) -> None:
    """Request without the placeholder in the header but WITH it in
    the body — only the body path fires."""
    addon, audit_path = _build_addon(tmp_path, _MULTI_CONFIG)
    addon.client = _make_client({"WEBHOOK_TOKEN": REAL})

    flow = _make_request(
        "hooks.example.com",
        headers={"Content-Type": "application/json"},
    )
    addon.requestheaders(flow)

    # No header set ⇒ header path no-ops.
    assert flow.request.headers.get("Authorization") is None
    body_out = _stream_through(flow.request.stream, [f'{{"t":"{PLACEHOLDER}"}}'.encode()])
    assert REAL.encode() in body_out

    events = _read_audit(audit_path)
    allowed = [e for e in events if e.get("decision") == "allowed"]
    reasons = {e["reason"] for e in allowed}
    assert "body_binding_matched" in reasons
    assert "binding_matched" not in reasons


def test_multi_unknown_child_type_gets_friendly_error() -> None:
    """Adversarial-review finding: unknown types INSIDE multi.injectors
    would otherwise surface Pydantic's verbose union_tag_invalid error.
    The mode='before' validator now walks multi children too."""
    with pytest.raises(ValidationError, match=r"injectors\[1\].type 'totally_made_up' is unknown"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {
                            "type": "multi",
                            "injectors": [
                                {"type": "header", "header": "X-A", "format": "{FOO}"},
                                {"type": "totally_made_up", "header": "X-B"},
                            ],
                        },
                        "bindings": [{"host": "api.example.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_multi_unimplemented_child_type_gets_friendly_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A known-but-unimplemented child type gets the same operator-facing
    message as the top-level case. All shipped types are implemented, so mark
    one planned to exercise the guard (kept for future reserved types)."""
    from kow import config_models

    monkeypatch.setitem(config_models._INJECTOR_TYPES, "github_app", "planned: P9")
    with pytest.raises(ValidationError, match=r"injectors\[0\].type 'github_app'"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {
                            "type": "multi",
                            "injectors": [
                                {"type": "github_app"},
                                {"type": "header", "header": "X-A", "format": "{FOO}"},
                            ],
                        },
                        "bindings": [{"host": "api.example.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_multi_child_missing_type_gets_friendly_error() -> None:
    """Multi is v0.5.0 P0.7 — no backward-compat reason to default
    child types; require explicit ``type:`` to avoid operator
    ambiguity."""
    with pytest.raises(ValidationError, match=r"injectors\[0\] is missing"):
        Config.model_validate(
            {
                "version": 1,
                "secrets": {
                    "FOO": {
                        "placeholder": _FOO_PH,
                        "inject": {
                            "type": "multi",
                            "injectors": [
                                {"header": "X-A", "format": "{FOO}"},  # missing type:
                                {"type": "body", "format": "{FOO}"},
                            ],
                        },
                        "bindings": [{"host": "api.example.com"}],
                    }
                },
                "audit": {"path": "/tmp/x.jsonl"},
            }
        )


def test_multi_explicit_type_round_trip() -> None:
    """The discriminator field round-trips: dumping then re-loading a
    multi config produces an identical Config."""
    import yaml

    src = _MULTI_CONFIG.replace("__AUDIT_PATH__", "/tmp/x.jsonl")
    parsed = yaml.safe_load(src)
    config_a = Config.model_validate(parsed)
    config_b = Config.model_validate(parsed)
    assert config_a.model_dump(mode="json") == config_b.model_dump(mode="json")
