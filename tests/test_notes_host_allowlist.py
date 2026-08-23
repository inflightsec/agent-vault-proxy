"""File-side notes host allowlist (ADR-0024): annotations only NARROW.

The GSM confused-deputy: `secretmanager.secrets.update` (edit the
`avp-binding` annotation) and `versions.access` (read the value) are
independently grantable, so a metadata-only writer could point a secret
at a host they control and let AVP exfiltrate it. With
`notes_host_allowlist` set, a notes/annotation host outside the file-side
list is rejected fail-closed (`host_not_in_allowlist`); absent, behavior
is unchanged — the zero-config North Star stays intact.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from mitmproxy.test import tflow

from kow.addon import AgentVaultProxyAddon
from kow.placeholders import derive_placeholder
from tests.fakes import FakeNotesListBackend as _FakeNotesListBackend

_SALT = b"\x0b" * 32

_GOOD = "api.good.example"
_EVIL = "evil.attacker.example"


def _read_audit(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def _make_request(host: str, headers: dict[str, str], *, method: str = "POST") -> Any:
    flow = tflow.tflow()
    flow.request.host = host
    flow.request.port = 443
    flow.request.scheme = "https"
    flow.request.path = "/v1/messages"
    flow.request.method = method
    for k, v in headers.items():
        flow.request.headers[k] = v
    return flow


def _config_path(
    tmp_path: Path,
    *,
    allowlist: list[str] | None,
    allow_wildcards: bool = False,
    file_secret_host: str | None = None,
) -> tuple[Path, Path]:
    audit_path = tmp_path / "audit.jsonl"
    salt_path = tmp_path / "install-salt"
    salt_path.write_bytes(_SALT)
    salt_path.chmod(0o600)
    lines = ["version: 1"]
    if file_secret_host is not None:
        lines += [
            "secrets:",
            "  FILE_SECRET:",
            '    placeholder: "file_PLACEHOLDER_0123456789abcdef"',
            "    inject:",
            '      header: "Authorization"',
            '      format: "Bearer {FILE_SECRET}"',
            "    bindings:",
            f'      - host: "{file_secret_host}"',
            "binding_source: both",
        ]
    else:
        lines += ["secrets: {}", "binding_source: notes"]
    if allow_wildcards:
        lines.append("allow_wildcard_hosts: true")
    if allowlist is not None:
        entries = ", ".join(f'"{h}"' for h in allowlist)
        lines.append(f"notes_host_allowlist: [{entries}]")
    lines += [
        f"install_salt_path: {salt_path}",
        "unmatched_destination_policy: forward_unmodified",
        "audit:",
        f"  path: {audit_path}",
        "backend:",
        "  type: static",
        "  config:",
        "    type: static",
        f"    path: {tmp_path / 'unused.yaml'}",
    ]
    p = tmp_path / "bindings.yaml"
    p.write_text("\n".join(lines) + "\n")
    return p, audit_path


def _build(
    tmp_path: Path,
    secrets: dict[str, tuple[str, str | None]],
    **cfg_kwargs: Any,
) -> tuple[AgentVaultProxyAddon, Path]:
    config_path, audit_path = _config_path(tmp_path, **cfg_kwargs)
    addon = AgentVaultProxyAddon()
    addon.configure_from_path(str(config_path), backend_override=_FakeNotesListBackend(secrets))
    return addon, audit_path


# ---------------------------------------------------------------------------
# (1) OPT-IN: absent key = unchanged North Star
# ---------------------------------------------------------------------------


def test_no_allowlist_key_behavior_unchanged(tmp_path: Path) -> None:
    """Key absent: a host-only note binds and injects exactly as before,
    and none of the new rejection state is populated."""
    real = "sk-REAL-north-star"
    addon, audit_path = _build(
        tmp_path, {"NS": (real, f"# avp-binding\nhost: {_GOOD}")}, allowlist=None
    )
    ph = derive_placeholder("NS", _SALT)
    flow = _make_request(_GOOD, {"Authorization": f"Bearer {ph}"})
    addon.requestheaders(flow)
    assert flow.request.headers["Authorization"] == f"Bearer {real}"
    assert addon._allowlist_rejected_names == set()
    assert addon._header_handler.allowlist_rejected_hosts == {}
    allowed = [e for e in _read_audit(audit_path) if e.get("decision") == "allowed"]
    assert len(allowed) == 1


# ---------------------------------------------------------------------------
# (2) The confused-deputy scenario itself
# ---------------------------------------------------------------------------


def test_confused_deputy_annotation_host_rejected(tmp_path: Path) -> None:
    """An annotation-only writer points the secret at their own host.
    With the allowlist set, the binding never activates: no injection
    fires, the real value never leaves, and the audit says precisely
    host_not_in_allowlist."""
    real = "sk-REAL-must-not-exfiltrate"
    addon, audit_path = _build(
        tmp_path, {"DEPUTY": (real, f"# avp-binding\nhost: {_EVIL}")}, allowlist=[_GOOD]
    )
    ph = derive_placeholder("DEPUTY", _SALT)
    flow = _make_request(_EVIL, {"Authorization": f"Bearer {ph}"})
    addon.requestheaders(flow)
    # Placeholder forwards verbatim — the real value is never injected.
    assert flow.request.headers["Authorization"] == f"Bearer {ph}"
    assert real not in str(flow.request.headers)
    events = _read_audit(audit_path)
    denied = [e for e in events if e.get("decision") == "denied"]
    assert denied and denied[0]["reason"] == "host_not_in_allowlist"
    assert denied[0]["secret_name"] == "DEPUTY"
    assert real not in audit_path.read_text()


# ---------------------------------------------------------------------------
# (3) Narrowing within an allowed host still works
# ---------------------------------------------------------------------------


def test_narrowing_within_allowed_host_works(tmp_path: Path) -> None:
    real = "sk-REAL-narrowed"
    note = f"# avp-binding\nhost: {_GOOD}\nmethods: [POST]"
    addon, audit_path = _build(tmp_path, {"NARROW": (real, note)}, allowlist=[_GOOD])
    ph = derive_placeholder("NARROW", _SALT)
    # POST (inside the narrowed scope) injects.
    flow = _make_request(_GOOD, {"Authorization": f"Bearer {ph}"}, method="POST")
    addon.requestheaders(flow)
    assert flow.request.headers["Authorization"] == f"Bearer {real}"
    # GET (outside the note's own scope) is denied — the note still narrows.
    flow2 = _make_request(_GOOD, {"Authorization": f"Bearer {ph}"}, method="GET")
    addon.requestheaders(flow2)
    assert flow2.request.headers["Authorization"] == f"Bearer {ph}"
    reasons = [e.get("reason") for e in _read_audit(audit_path) if e.get("decision") == "denied"]
    assert "binding_scope_violation" in reasons


# ---------------------------------------------------------------------------
# (4) ADR-0021 multi-host: partial rejection, sibling survives
# ---------------------------------------------------------------------------


def test_multihost_partial_rejection_keeps_sibling(tmp_path: Path) -> None:
    real = "sk-REAL-multihost"
    note = f'# avp-binding\nhosts:\n- {_GOOD}\n- {_EVIL}\nformat: "Bearer {{secret}}"'
    addon, audit_path = _build(tmp_path, {"MULTI": (real, note)}, allowlist=[_GOOD])
    ph = derive_placeholder("MULTI", _SALT)
    # Allowed sibling injects.
    flow = _make_request(_GOOD, {"Authorization": f"Bearer {ph}"})
    addon.requestheaders(flow)
    assert flow.request.headers["Authorization"] == f"Bearer {real}"
    # Rejected host: placeholder verbatim + precise reason naming the host.
    flow2 = _make_request(_EVIL, {"Authorization": f"Bearer {ph}"})
    addon.requestheaders(flow2)
    assert flow2.request.headers["Authorization"] == f"Bearer {ph}"
    denied = [e for e in _read_audit(audit_path) if e.get("decision") == "denied"]
    assert denied and denied[-1]["reason"] == "host_not_in_allowlist"
    assert denied[-1]["destination"]["host"] == _EVIL


# ---------------------------------------------------------------------------
# (5) Wildcard allowlist entries ride the existing opt-in
# ---------------------------------------------------------------------------


def test_wildcard_allowlist_entry_requires_opt_in(tmp_path: Path) -> None:
    config_path, _ = _config_path(tmp_path, allowlist=["*.corp.example"])
    addon = AgentVaultProxyAddon()
    with pytest.raises(Exception, match="allow_wildcard_hosts"):
        addon.configure_from_path(str(config_path), backend_override=_FakeNotesListBackend({}))


def test_wildcard_allowlist_entry_matches_with_opt_in(tmp_path: Path) -> None:
    real = "sk-REAL-wild"
    addon, _ = _build(
        tmp_path,
        {"WILD": (real, "# avp-binding\nhost: api.corp.example")},
        allowlist=["*.corp.example"],
        allow_wildcards=True,
    )
    ph = derive_placeholder("WILD", _SALT)
    flow = _make_request("api.corp.example", {"Authorization": f"Bearer {ph}"})
    addon.requestheaders(flow)
    assert flow.request.headers["Authorization"] == f"Bearer {real}"


# ---------------------------------------------------------------------------
# (6) Empty list = notes fully fenced; file tier stays exempt
# ---------------------------------------------------------------------------


def test_empty_allowlist_fences_notes_but_not_file_tier(tmp_path: Path) -> None:
    real_file = "sk-REAL-file-tier"
    real_note = "sk-REAL-noted"
    secrets = {
        "FILE_SECRET": (real_file, None),
        "NOTED": (real_note, f"# avp-binding\nhost: {_GOOD}"),
    }
    addon, audit_path = _build(tmp_path, secrets, allowlist=[], file_secret_host="api.file.example")
    # File-tier secret (trusted) still injects under an empty allowlist.
    flow = _make_request(
        "api.file.example", {"Authorization": "Bearer file_PLACEHOLDER_0123456789abcdef"}
    )
    addon.requestheaders(flow)
    assert flow.request.headers["Authorization"] == f"Bearer {real_file}"
    # Notes-tier secret is fenced off entirely.
    ph = derive_placeholder("NOTED", _SALT)
    flow2 = _make_request(_GOOD, {"Authorization": f"Bearer {ph}"})
    addon.requestheaders(flow2)
    assert flow2.request.headers["Authorization"] == f"Bearer {ph}"
    denied = [e for e in _read_audit(audit_path) if e.get("decision") == "denied"]
    assert denied and denied[-1]["reason"] == "host_not_in_allowlist"


# ---------------------------------------------------------------------------
# Cross-vendor review (Cato lead): case-normalization consistency.
# A mixed-case allowlist entry must still match the lowercased note host —
# else the operator silently breaks the control they just enabled.
# ---------------------------------------------------------------------------


def test_mixed_case_allowlist_entry_still_allows_lowercased_note_host(tmp_path: Path) -> None:
    real = "sk-REAL-case"
    addon, audit_path = _build(
        tmp_path, {"CASE": (real, f"# avp-binding\nhost: {_GOOD}")}, allowlist=["API.Good.Example"]
    )
    ph = derive_placeholder("CASE", _SALT)
    flow = _make_request(_GOOD, {"Authorization": f"Bearer {ph}"})
    addon.requestheaders(flow)
    # Uppercase allowlist entry is normalized; the legit binding is NOT
    # falsely rejected — it injects.
    assert flow.request.headers["Authorization"] == f"Bearer {real}"
    assert addon._allowlist_rejected_names == set()


def test_mixed_case_note_host_outside_allowlist_still_rejected(tmp_path: Path) -> None:
    """Normalizing case must NOT weaken the block: an attacker host in any
    case is still rejected (the fix is about false-rejection, not letting
    un-approved hosts through)."""
    real = "sk-REAL-still-blocked"
    addon, audit_path = _build(
        tmp_path, {"BLOCK": (real, "# avp-binding\nhost: EVIL.Attacker.Example")}, allowlist=[_GOOD]
    )
    ph = derive_placeholder("BLOCK", _SALT)
    flow = _make_request("evil.attacker.example", {"Authorization": f"Bearer {ph}"})
    addon.requestheaders(flow)
    assert flow.request.headers["Authorization"] == f"Bearer {ph}"  # verbatim, not injected
    assert real not in str(flow.request.headers)
