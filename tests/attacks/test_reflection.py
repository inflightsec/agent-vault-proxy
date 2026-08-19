"""Reflected-secret exfil — the upstream echoes the injected secret back.

THREAT: T-1  (prompt-injection exfil via reflected input)
EXPECTED-LEAK: response-side echo scrubbing is not implemented yet.
BLOCKED-BY: ADR-0031

kow substitutes the real secret onto the outbound request, so a hostile or
merely sloppy upstream can reflect it into an error body (``invalid token:
<value>``) that the agent then reads. Until ADR-0031's response scan ships,
kow's ``response`` hook only records the status — the secret flows straight
back. This test asserts the DESIRED end state (secret scrubbed from the
response), so it xfails today and flips to a hard pass the moment the defense
lands. ``strict=True`` makes an un-flipped pass fail the build.
"""

from __future__ import annotations

import pytest

from tests.attacks import _harness as h

pytestmark = pytest.mark.attacks


@pytest.mark.xfail(
    strict=True,
    reason="expected-leak until response echo scrubbing ships — BLOCKED-BY: ADR-0031",
)
def test_reflected_secret_is_scrubbed_from_response(tmp_path):
    addon, _audit = h.build_addon(tmp_path, bindings=h.WIDE)
    flow = h.make_flow(
        h.BOUND_HOST,
        "POST",
        "/v1/chat",
        headers={"Authorization": f"Bearer {h.PLACEHOLDER}"},
    )
    h.drive_outbound(addon, flow)

    # NOTE (Oracle C1): no sanity `assert` lives in an xfail test — a failing
    # precondition would be swallowed as an expected failure and hide a real
    # inject regression. `test_inject_precondition.py` guards that injection
    # actually happens; this test asserts ONLY the desired end state, so if
    # injection silently broke, the assertion below would pass -> XPASS(strict)
    # -> red, never a false green.
    injected = flow.request.headers.get("Authorization", "")

    # Hostile/buggy upstream reflects the Authorization value into its 400 body.
    response = h.simulate_upstream(
        addon, flow, status=400, content=f"invalid token: {injected}".encode()
    )

    # DESIRED end state (fails today -> xfail): the secret never reaches the agent.
    assert h.REAL not in h.agent_visible(response)
