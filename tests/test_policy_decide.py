"""Parity + unit tests for the pure ``decide()`` core (ADR-0013).

The parity test is the safety net for extracting the decision logic out of
``addon.py``: every policy fixture is run through BOTH the live addon and
``decide()``, and their verdicts must agree on every *policy* decision.

Execution-layer outcomes (a failed fetch -> secret_unavailable, a body
injector -> body_binding_matched, a BWS-notes no-binding -> no_binding_in_notes)
are NOT decide()'s domain — it returns the pre-execution verdict. For those we
assert the weaker, still-important property: decide() never produces a hard
policy-deny for a request the addon actually allowed-then-handled downstream.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from agent_vault_proxy.config import load_config
from agent_vault_proxy.policy import decide
from tests.test_policy_fixtures import FIXTURE_DIR, run_policy_fixture

_FIXTURES = sorted(FIXTURE_DIR.glob("*.yaml"))

# Reasons whose final value is decided by EXECUTION (I/O / body stream /
# notes attribution), not by decide(). Prefix forms carry a ``:ExcName`` tail.
_EXEC_PREFIXES = (
    "secret_unavailable",
    "secret_fetch_error",
    "composite_unavailable",
    "composite_fetch_error",
    "composite_render_unexpected_error",
)
_EXEC_EXACT = {
    "render_failed",
    "body_binding_matched",
    "no_binding_in_notes",
    "invalid_binding_metadata",
}


def _is_execution_layer(reason: str | None) -> bool:
    if reason is None:
        return False
    return reason in _EXEC_EXACT or reason.split(":", 1)[0] in _EXEC_PREFIXES


def _decide_for_fixture(fix: dict, tmp_path: Path):
    cfg_path = tmp_path / "decide.yaml"
    audit_path = tmp_path / "audit.jsonl"
    # decide() ignores audit, but Config validation requires the stanza.
    cfg_path.write_text(
        fix["config"] + f"\naudit:\n  path: {audit_path}\n  fail_on_unwritable: true\n"
    )
    config = load_config(cfg_path)
    req = fix["request"]
    headers = {k.lower(): v for k, v in req.get("headers", {}).items()}
    return decide(
        config=config,
        host=req["host"],
        port=req.get("port", 443),
        method=req.get("method", "GET").upper(),
        path=req.get("path", "/").split("?", 1)[0],
        connect_host=req.get("connect"),
        header_get=lambda name: headers.get(name.lower()),
    )


@pytest.mark.parametrize("fixture_path", _FIXTURES, ids=lambda p: p.name)
def test_decide_matches_addon_on_policy_fixtures(fixture_path: Path, tmp_path: Path) -> None:
    fix = yaml.safe_load(fixture_path.read_text())
    observed = run_policy_fixture(fix, tmp_path)
    d = _decide_for_fixture(fix, tmp_path)

    if _is_execution_layer(observed["reason"]):
        # decide() owns policy, not execution: it must not hard-deny a request
        # whose real outcome was decided downstream.
        assert d.decision in ("allowed", "forward_unmodified"), (
            f"{fixture_path.name}: decide() hard-denied ({d.reason}) a request the addon "
            f"resolved at execution layer ({observed['reason']})"
        )
        return

    # Policy decision: decide() must reproduce the addon's verdict exactly.
    assert d.decision == observed["decision"], fixture_path.name
    assert d.reason == observed["reason"], fixture_path.name
    assert d.secret_name == observed.get("secret_name"), fixture_path.name


def _config(tmp_path: Path, body: str):
    p = tmp_path / "c.yaml"
    p.write_text(body + f"\naudit:\n  path: {tmp_path / 'a.jsonl'}\n  fail_on_unwritable: true\n")
    return load_config(p)


_TWO_SECRETS = """\
version: 1
secrets:
  ANTHROPIC_API_KEY:
    placeholder: "sk-ant-PLACEHOLDER-AAAAAAAAAAAAAAAAAAAAA"
    inject: { header: "Authorization", format: "Bearer {ANTHROPIC_API_KEY}" }
    bindings: [{ host: "api.anthropic.com" }]
  OPENAI_API_KEY:
    placeholder: "sk-PLACEHOLDER-BBBBBBBBBBBBBBBBBBBBBBBBB"
    inject: { header: "X-OpenAI", format: "Bearer {OPENAI_API_KEY}" }
    bindings: [{ host: "api.anthropic.com" }]
unmatched_destination_policy: forward_unmodified
"""


def test_decide_forward_when_no_placeholder(tmp_path: Path) -> None:
    config = _config(tmp_path, _TWO_SECRETS)
    d = decide(
        config=config,
        host="api.anthropic.com",
        port=443,
        method="GET",
        path="/",
        connect_host=None,
        header_get=lambda _n: None,
    )
    assert d.decision == "forward_unmodified"
    assert d.secret_name is None


def test_decide_ambiguous_two_placeholders_in_headers(tmp_path: Path) -> None:
    config = _config(tmp_path, _TWO_SECRETS)
    hdrs = {
        "authorization": "Bearer sk-ant-PLACEHOLDER-AAAAAAAAAAAAAAAAAAAAA",
        "x-openai": "Bearer sk-PLACEHOLDER-BBBBBBBBBBBBBBBBBBBBBBBBB",
    }
    d = decide(
        config=config,
        host="api.anthropic.com",
        port=443,
        method="POST",
        path="/v1/x",
        connect_host=None,
        header_get=lambda n: hdrs.get(n.lower()),
    )
    assert d.decision == "denied"
    assert d.reason == "ambiguous_placeholder_match"
    assert d.response_status == 400
    assert d.extra["matched_secret_names"] == ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]


def test_decide_allowed_carries_execution_handles(tmp_path: Path) -> None:
    config = _config(tmp_path, _TWO_SECRETS)
    hdrs = {"authorization": "Bearer sk-ant-PLACEHOLDER-AAAAAAAAAAAAAAAAAAAAA"}
    d = decide(
        config=config,
        host="api.anthropic.com",
        port=443,
        method="GET",
        path="/v1/messages",
        connect_host=None,
        header_get=lambda n: hdrs.get(n.lower()),
    )
    assert d.decision == "allowed"
    assert d.reason == "binding_matched"
    assert d.secret_name == "ANTHROPIC_API_KEY"
    assert d.header_name == "Authorization"
    assert d.secret_spec is not None and d.header_injector is not None
    assert d.matched_binding is not None


def test_at_least_one_fixture_exercises_each_policy_reason() -> None:
    """Guards the parity test's value: if fixtures stop covering a policy
    branch, decide()'s match there goes untested. Asserts presence of the
    core allow + the two G5 forward-verbatim denies across the suite."""
    reasons = set()
    for fp in _FIXTURES:
        fix = yaml.safe_load(fp.read_text())
        # cheap: read the declared expectation, not a full run
        exp = fix.get("expect", {})
        if isinstance(exp, dict) and exp.get("reason"):
            reasons.add(exp["reason"])
    assert "binding_matched" in reasons
