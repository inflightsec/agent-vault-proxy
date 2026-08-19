"""Injection precondition — the real secret DOES reach an authorized request.

THREAT: T-1  (guards the expected-leak tests against silently proving nothing)

The `expected-leak` exploits (reflection, header reflection, create-then-read)
carry no sanity `assert` of their own: a failing precondition inside an
`xfail(strict=True)` test would be swallowed as an expected failure and mask a
real inject regression (Oracle C1). This defended test is that guard — if
authorized injection ever stops populating the target header with the real
secret, this goes red immediately, independent of any xfail.
"""

from __future__ import annotations

import pytest

from tests.attacks import _harness as h

pytestmark = pytest.mark.attacks


def test_authorized_request_receives_the_real_secret(tmp_path):
    addon, _audit = h.build_addon(tmp_path, bindings=h.WIDE)
    flow = h.make_flow(
        h.BOUND_HOST,
        "POST",
        "/v1/chat",
        headers={"Authorization": f"Bearer {h.PLACEHOLDER}"},
    )
    h.drive_outbound(addon, flow)

    authorization = flow.request.headers.get("Authorization", "")
    assert h.REAL in authorization, "authorized request must receive the real secret"
    assert h.PLACEHOLDER not in authorization, "the placeholder must be fully substituted"
