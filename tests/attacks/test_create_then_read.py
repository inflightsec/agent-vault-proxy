"""Create-then-read exfil — store the placeholder, read the secret back later.

THREAT: T-1  (persistent reflection; scrubbing's hardest case)
EXPECTED-LEAK: response-side echo scrubbing is not implemented yet.
BLOCKED-BY: ADR-0031

The agent POSTs the placeholder to *create* a resource; kow substitutes, so the
upstream now stores the REAL secret. A later plain GET returns it — and on that
GET kow injected nothing, so any defense that only inspects requests where a
substitution happened is blind to this variant. That blindness is exactly why
this is the acceptance test ADR-0031's response scan must satisfy. Asserts the
desired end state, so it xfails today and flips when the scan ships.
"""

from __future__ import annotations

import pytest

from tests.attacks import _harness as h

pytestmark = pytest.mark.attacks


@pytest.mark.xfail(
    strict=True,
    reason="expected-leak until response echo scrubbing ships — BLOCKED-BY: ADR-0031",
)
def test_stored_secret_is_scrubbed_on_a_later_read(tmp_path):
    addon, _audit = h.build_addon(tmp_path, bindings=h.WIDE)

    # 1) create: POST the placeholder; kow injects the real secret into stored state.
    # (No sanity `assert` here — Oracle C1: it would be masked by xfail.
    # `test_inject_precondition.py` guards that injection works.)
    create = h.make_flow(
        h.BOUND_HOST,
        "POST",
        "/v1/resources",
        headers={"Authorization": f"Bearer {h.PLACEHOLDER}"},
    )
    h.drive_outbound(addon, create)

    # The upstream now stores exactly the value kow injected on create. Derive
    # the stored token from that injection (Oracle C2) rather than hard-coding
    # the sentinel — this proves the *same* value laundered through storage.
    stored_token = create.request.headers.get("Authorization", "").removeprefix("Bearer ")

    # 2) read: a later plain GET returns the stored value. kow injected NOTHING here.
    read = h.make_flow(h.BOUND_HOST, "GET", "/v1/resources/1")
    h.drive_outbound(addon, read)
    response = h.simulate_upstream(
        addon, read, status=200, content=f'{{"token": "{stored_token}"}}'.encode()
    )

    # DESIRED end state (fails today -> xfail): the stored secret is scrubbed on read.
    assert h.REAL not in h.agent_visible(response)
