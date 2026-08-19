"""Scope bypass — launder a bound token onto an off-scope request.

THREAT: T-1.5  (laundering through a legitimately-bound destination)

The secret is bound to POST /v1/** only. A prompt-injected agent tries to
spend it on a GET /admin — same host, wrong operation. The real secret must
not ride an off-scope request; the placeholder forwards verbatim (G5).
"""

from __future__ import annotations

import pytest

from tests.attacks import _harness as h

pytestmark = pytest.mark.attacks


def test_offscope_request_never_receives_the_real_secret(tmp_path):
    addon, _audit = h.build_addon(tmp_path, bindings=h.NARROW)
    flow = h.make_flow(
        h.BOUND_HOST,
        "GET",
        "/admin",
        headers={"Authorization": f"Bearer {h.PLACEHOLDER}"},
    )
    h.drive_outbound(addon, flow)

    # This must be forward-verbatim (G5), NOT a deny — pin that distinction so
    # the test can't pass on the wrong behavior (Oracle C3): a 403 gate would
    # also leave the placeholder unchanged and the secret absent.
    assert flow.response is None, "off-scope on a bound host forwards verbatim, not deny"

    outbound = flow.request.headers.get("Authorization", "")
    assert h.REAL not in outbound, "off-scope request must not receive the real secret"
    # G5 forward-verbatim: the placeholder leaves unchanged, no substitution.
    assert h.PLACEHOLDER in outbound
