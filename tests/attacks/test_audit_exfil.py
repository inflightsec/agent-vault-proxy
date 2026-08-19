"""Audit-stream exfil — read the secret out of kow's own logs.

THREAT: T-1  (the audit trail must record the decision, never the value)

An authorized injection really happens (proving we exercised the live path),
but the real secret must appear nowhere in the audit stream an operator or a
log-shipping sidecar can read.
"""

from __future__ import annotations

import pytest

from tests.attacks import _harness as h

pytestmark = pytest.mark.attacks


def test_authorized_injection_never_writes_the_secret_to_audit(tmp_path):
    addon, audit = h.build_addon(tmp_path, bindings=h.WIDE)
    flow = h.make_flow(
        h.BOUND_HOST,
        "POST",
        "/v1/chat",
        headers={"Authorization": f"Bearer {h.PLACEHOLDER}"},
    )
    h.drive_outbound(addon, flow)

    # Sanity: the real inject path fired.
    assert h.REAL in flow.request.headers.get("Authorization", "")
    # Guarantee: the value is not in the audit trail.
    assert audit.exists()
    assert h.REAL not in audit.read_text()
