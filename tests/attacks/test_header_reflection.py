"""Header-reflected exfil — the upstream echoes the secret into a RESPONSE HEADER.

THREAT: T-1  (reflected-input exfil via a response header, not the body)
EXPECTED-LEAK: response-side echo scrubbing is not implemented yet.
BLOCKED-BY: ADR-0031

Body reflection is not the only echo channel (Oracle C5): a hostile or buggy
upstream can bounce the Authorization value back into a response header —
``X-Echo-Auth``, ``Set-Cookie``, ``Location``, a diagnostic header. ADR-0031's
scan must cover response headers too, so this asserts the desired scrubbed
state and xfails until it ships. No sanity assert here (Oracle C1) — the
precondition is guarded by ``test_inject_precondition.py``.
"""

from __future__ import annotations

import pytest

from tests.attacks import _harness as h

pytestmark = pytest.mark.attacks


@pytest.mark.xfail(
    strict=True,
    reason="expected-leak until response echo scrubbing ships — BLOCKED-BY: ADR-0031",
)
def test_reflected_secret_in_response_header_is_scrubbed(tmp_path):
    addon, _audit = h.build_addon(tmp_path, bindings=h.WIDE)
    flow = h.make_flow(
        h.BOUND_HOST,
        "POST",
        "/v1/chat",
        headers={"Authorization": f"Bearer {h.PLACEHOLDER}"},
    )
    h.drive_outbound(addon, flow)
    injected = flow.request.headers.get("Authorization", "")

    # Upstream bounces the injected credential back in a response header.
    response = h.simulate_upstream(
        addon, flow, status=200, content=b"ok", headers={"X-Echo-Auth": injected}
    )

    # DESIRED end state (fails today -> xfail): the secret never reaches the agent.
    assert h.REAL not in h.agent_visible(response)
