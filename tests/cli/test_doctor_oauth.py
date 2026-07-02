"""``avp doctor --probe-oauth`` tests (ADR-0017 slice 8).

The probe is the operator-facing self-service verb for an OAuth2 binding:
"is this binding wired correctly without me having to drive a proxied
request through an agent?" The probes are READ-ONLY by default — the
``--exchange`` opt-in is the only path that actually calls the upstream
token endpoint (which on most providers will rotate the refresh token,
i.e. it is a state-mutating call against the upstream).

Each probe returns a ``ProbeResult`` (binding / check / status / message).
Status ``FAIL`` rolls up to exit code 1; ``WARN`` and ``OK`` do not.
"""

from __future__ import annotations

import json
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from agent_vault_proxy.cli.doctor_oauth import (
    ProbeResult,
    probe_all_oauth_bindings,
    probe_oauth_binding,
)
from agent_vault_proxy.config import load_config
from tests import _oauth_helpers as oh
from tests._oauth_helpers import FailingBackend, FakeBackend, FakeResp, ReadOnlyBackend


@pytest.fixture(autouse=True)
def stub_ssrf_dns_public(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    oh.apply_public_ssrf_stub(monkeypatch)
    yield


_GOOD_VAULT = {
    "GOOGLE_OAUTH_CLIENT_ID": "cid-real",
    "GOOGLE_OAUTH_CLIENT_SECRET": "csec-real",
    "GOOGLE_OAUTH_REFRESH_TOKEN": "rtok-real",
}


def _config_with_oauth(tmp_path: Path, write_back: bool = True) -> Path:
    p = tmp_path / "bindings.yaml"
    p.write_text(oh.oauth_yaml(tmp_path / "audit.jsonl", write_back=write_back))
    return p


def _config_with_header_only(tmp_path: Path) -> Path:
    audit_path = tmp_path / "audit.jsonl"
    body = f"""
version: 1
secrets:
  PLAIN_HEADER:
    placeholder: "plain-header-PLACEHOLDER-01HXY1234567890ABCD"
    inject:
      type: header
      header: Authorization
      format: "Bearer {{PLAIN_HEADER}}"
    bindings:
      - host: api.example.com
audit:
  path: {audit_path}
  fail_on_unwritable: true
"""
    p = tmp_path / "bindings.yaml"
    p.write_text(body)
    return p


# ---------------------------------------------------------------------------
# Discovery: no bindings, unknown binding, wrong-type binding
# ---------------------------------------------------------------------------


def test_no_oauth_bindings_warns_but_does_not_fail(tmp_path: Path) -> None:
    cfg = load_config(_config_with_header_only(tmp_path))
    results, any_fail = probe_all_oauth_bindings(cfg, FakeBackend({}))
    assert any_fail is False
    assert len(results) == 1
    assert results[0].status == "WARN"
    assert "no oauth2_refresh bindings" in results[0].message.lower()


def test_unknown_binding_filter_fails(tmp_path: Path) -> None:
    cfg = load_config(_config_with_oauth(tmp_path))
    results = probe_oauth_binding(cfg, "DOES_NOT_EXIST", FakeBackend(_GOOD_VAULT))
    assert len(results) == 1
    assert results[0].status == "FAIL"
    assert results[0].check == "binding-exists"


def test_non_oauth_binding_filter_fails(tmp_path: Path) -> None:
    cfg = load_config(_config_with_header_only(tmp_path))
    results = probe_oauth_binding(cfg, "PLAIN_HEADER", FakeBackend({}))
    assert len(results) == 1
    assert results[0].status == "FAIL"
    assert results[0].check == "binding-type"


# ---------------------------------------------------------------------------
# Happy path: SSRF OK, inputs OK, writable OK
# ---------------------------------------------------------------------------


def test_happy_path_all_ok(tmp_path: Path) -> None:
    cfg = load_config(_config_with_oauth(tmp_path))
    results = probe_oauth_binding(cfg, "GOOGLE_OAUTH", FakeBackend(_GOOD_VAULT))
    by_check = {r.check: r for r in results}
    assert by_check["ssrf"].status == "OK"
    assert by_check["input:client_id"].status == "OK"
    assert by_check["input:client_secret"].status == "OK"
    assert by_check["input:refresh_token"].status == "OK"
    assert by_check["writable"].status == "OK"
    # No secret material in any message.
    blob = json.dumps([(r.check, r.message) for r in results])
    assert "cid-real" not in blob
    assert "csec-real" not in blob
    assert "rtok-real" not in blob


# ---------------------------------------------------------------------------
# SSRF: token_url resolves to private address -> FAIL
# ---------------------------------------------------------------------------


def test_ssrf_blocked_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = load_config(_config_with_oauth(tmp_path))
    # Re-flip the resolver AFTER config load (config-load already passed via
    # the autouse public stub).
    monkeypatch.setattr(
        "agent_vault_proxy._ssrf_guard.socket.getaddrinfo",
        lambda *a, **kw: [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 0)),
        ],
    )
    results = probe_oauth_binding(cfg, "GOOGLE_OAUTH", FakeBackend(_GOOD_VAULT))
    ssrf = next(r for r in results if r.check == "ssrf")
    assert ssrf.status == "FAIL"


# ---------------------------------------------------------------------------
# Inputs: missing or unavailable
# ---------------------------------------------------------------------------


def test_missing_vault_secret_fails_per_input(tmp_path: Path) -> None:
    cfg = load_config(_config_with_oauth(tmp_path))
    partial = {"GOOGLE_OAUTH_CLIENT_ID": "cid", "GOOGLE_OAUTH_CLIENT_SECRET": "csec"}
    results = probe_oauth_binding(cfg, "GOOGLE_OAUTH", FakeBackend(partial))
    rt = next(r for r in results if r.check == "input:refresh_token")
    assert rt.status == "FAIL"
    cid = next(r for r in results if r.check == "input:client_id")
    assert cid.status == "OK"


def test_empty_vault_secret_fails(tmp_path: Path) -> None:
    cfg = load_config(_config_with_oauth(tmp_path))
    bad = {**_GOOD_VAULT, "GOOGLE_OAUTH_REFRESH_TOKEN": ""}
    results = probe_oauth_binding(cfg, "GOOGLE_OAUTH", FakeBackend(bad))
    rt = next(r for r in results if r.check == "input:refresh_token")
    assert rt.status == "FAIL"
    assert "empty" in rt.message.lower()


def test_backend_unavailable_fails(tmp_path: Path) -> None:
    cfg = load_config(_config_with_oauth(tmp_path))
    results = probe_oauth_binding(cfg, "GOOGLE_OAUTH", FailingBackend())
    for label in ("client_id", "client_secret", "refresh_token"):
        rt = next(r for r in results if r.check == f"input:{label}")
        assert rt.status == "FAIL"


# ---------------------------------------------------------------------------
# Writability: read-only backend + write-back True == FAIL.
# Write-back False == WARN (operator opted out — surface, don't block).
# ---------------------------------------------------------------------------


def test_readonly_backend_with_writeback_true_fails(tmp_path: Path) -> None:
    cfg = load_config(_config_with_oauth(tmp_path))
    results = probe_oauth_binding(cfg, "GOOGLE_OAUTH", ReadOnlyBackend(_GOOD_VAULT))
    w = next(r for r in results if r.check == "writable")
    assert w.status == "FAIL"
    assert "read-only" in w.message.lower()


def test_writeback_false_warns_does_not_fail(tmp_path: Path) -> None:
    cfg = load_config(_config_with_oauth(tmp_path, write_back=False))
    results = probe_oauth_binding(cfg, "GOOGLE_OAUTH", ReadOnlyBackend(_GOOD_VAULT))
    w = next(r for r in results if r.check == "writable")
    assert w.status == "WARN"
    assert "write_back" in w.message.lower()


# ---------------------------------------------------------------------------
# probe_all_oauth_bindings rollup
# ---------------------------------------------------------------------------


def test_rollup_any_fail_propagates(tmp_path: Path) -> None:
    cfg = load_config(_config_with_oauth(tmp_path))
    _results, any_fail = probe_all_oauth_bindings(cfg, ReadOnlyBackend(_GOOD_VAULT))
    assert any_fail is True


def test_rollup_all_ok_returns_false(tmp_path: Path) -> None:
    cfg = load_config(_config_with_oauth(tmp_path))
    _results, any_fail = probe_all_oauth_bindings(cfg, FakeBackend(_GOOD_VAULT))
    assert any_fail is False


def test_binding_filter_restricts_scope(tmp_path: Path) -> None:
    cfg = load_config(_config_with_oauth(tmp_path))
    results, _ = probe_all_oauth_bindings(
        cfg, FakeBackend(_GOOD_VAULT), binding_filter="GOOGLE_OAUTH"
    )
    binding_names = {r.binding_name for r in results}
    assert binding_names == {"GOOGLE_OAUTH"}


# ---------------------------------------------------------------------------
# --exchange opt-in: ACTUALLY calls the token endpoint (mocked here)
# ---------------------------------------------------------------------------


def test_exchange_success_no_rotation(tmp_path: Path) -> None:
    cfg = load_config(_config_with_oauth(tmp_path))
    body = json.dumps({"access_token": "at-PROBE", "expires_in": 3600}).encode()
    with patch("urllib.request.urlopen", return_value=FakeResp(body)):
        results = probe_oauth_binding(
            cfg, "GOOGLE_OAUTH", FakeBackend(_GOOD_VAULT), do_exchange=True
        )
    ex = next(r for r in results if r.check == "exchange")
    assert ex.status == "OK"
    # No access-token bytes in the operator-visible message.
    assert "at-PROBE" not in ex.message


def test_exchange_success_with_rotation_warns_about_consumed_token(tmp_path: Path) -> None:
    """When the upstream rotates the refresh token during a probe, the
    operator MUST see that the old refresh token is now invalid —
    otherwise they may roll back assuming the probe was non-destructive."""
    cfg = load_config(_config_with_oauth(tmp_path))
    body = json.dumps(
        {"access_token": "at-PROBE", "expires_in": 3600, "refresh_token": "rtok-NEW"}
    ).encode()
    with patch("urllib.request.urlopen", return_value=FakeResp(body)):
        results = probe_oauth_binding(
            cfg, "GOOGLE_OAUTH", FakeBackend(_GOOD_VAULT), do_exchange=True
        )
    ex = next(r for r in results if r.check == "exchange")
    assert ex.status == "WARN"
    assert "rotat" in ex.message.lower()


def test_exchange_invalid_grant_fails(tmp_path: Path) -> None:
    cfg = load_config(_config_with_oauth(tmp_path))
    from urllib.error import HTTPError

    err = HTTPError(
        url="https://oauth2.example.com/token",
        code=400,
        msg="HTTP 400",
        hdrs=None,  # type: ignore[arg-type]
        fp=__import__("io").BytesIO(json.dumps({"error": "invalid_grant"}).encode()),
    )
    with patch("urllib.request.urlopen", side_effect=err):
        results = probe_oauth_binding(
            cfg, "GOOGLE_OAUTH", FakeBackend(_GOOD_VAULT), do_exchange=True
        )
    ex = next(r for r in results if r.check == "exchange")
    assert ex.status == "FAIL"
    assert "invalid_grant" in ex.message


def test_exchange_skipped_if_input_fetch_failed(tmp_path: Path) -> None:
    """If we couldn't fetch the inputs, the live exchange can't run.
    Distinct outcome (SKIP, not FAIL) so the operator sees the actual
    failure (the input fetch) rather than a secondary symptom."""
    cfg = load_config(_config_with_oauth(tmp_path))
    results = probe_oauth_binding(cfg, "GOOGLE_OAUTH", FailingBackend(), do_exchange=True)
    ex = next(r for r in results if r.check == "exchange")
    assert ex.status == "SKIP"


# ---------------------------------------------------------------------------
# CLI integration — `avp doctor --probe-oauth` exit code + output shape
# ---------------------------------------------------------------------------


def test_cli_doctor_probe_oauth_clean_returns_0(tmp_path: Path, capsys: Any) -> None:
    cfg_path = _config_with_oauth(tmp_path)
    # Patch build_backend so we don't try to construct a BWS client.
    from agent_vault_proxy import cli as _cli_pkg  # noqa: F401
    from agent_vault_proxy.cli.doctor import run_doctor

    with patch(
        "agent_vault_proxy.cli.doctor.build_backend",
        return_value=(FakeBackend(_GOOD_VAULT), None),
    ):
        rc = run_doctor(
            ca_cert_path="/nonexistent/cert",
            ca_key_path="/nonexistent/key",
            config_path=str(cfg_path),
            probe_oauth=True,
        )
    assert rc == 0
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "GOOGLE_OAUTH" in combined
    assert "OK" in combined


def test_cli_doctor_probe_oauth_fail_returns_1(tmp_path: Path, capsys: Any) -> None:
    cfg_path = _config_with_oauth(tmp_path)
    from agent_vault_proxy.cli.doctor import run_doctor

    with patch(
        "agent_vault_proxy.cli.doctor.build_backend",
        return_value=(ReadOnlyBackend(_GOOD_VAULT), None),
    ):
        rc = run_doctor(
            ca_cert_path="/nonexistent/cert",
            ca_key_path="/nonexistent/key",
            config_path=str(cfg_path),
            probe_oauth=True,
        )
    assert rc == 1


def test_cli_no_probe_oauth_runs_only_ca_checks(tmp_path: Path, capsys: Any) -> None:
    """Default ``avp doctor`` (no --probe-oauth) MUST NOT touch the config
    or the backend — the CA checks are independent of OAuth wiring."""
    from agent_vault_proxy.cli.doctor import run_doctor

    with patch("agent_vault_proxy.cli.doctor.build_backend") as bb:
        rc = run_doctor(
            ca_cert_path="/nonexistent/cert",
            ca_key_path="/nonexistent/key",
        )
        assert bb.call_count == 0
    assert rc == 0


def test_probe_result_dataclass_shape() -> None:
    r = ProbeResult("X", "ssrf", "OK", "msg")
    assert r.binding_name == "X"
    assert r.check == "ssrf"
    assert r.status == "OK"
    assert r.message == "msg"
