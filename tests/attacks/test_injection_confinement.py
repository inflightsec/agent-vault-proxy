"""Placeholder smuggling — hide a placeholder in a second header.

THREAT: T-1.5  (coax substitution outside the declared injection target)

On a legitimately authorized request the agent plants a copy of the
placeholder in a header kow does NOT inject into (here ``X-Smuggle``), betting
kow fills the placeholder in wherever it appears. Substitution is confined to
the declared target header: the smuggled copy stays a placeholder.
"""

from __future__ import annotations

import pytest

from tests.attacks import _harness as h

pytestmark = pytest.mark.attacks


def test_placeholder_in_untargeted_header_is_not_substituted(tmp_path):
    addon, _audit = h.build_addon(tmp_path, bindings=h.WIDE)
    flow = h.make_flow(
        h.BOUND_HOST,
        "POST",
        "/v1/chat",
        headers={
            "Authorization": f"Bearer {h.PLACEHOLDER}",
            "X-Smuggle": f"Bearer {h.PLACEHOLDER}",
        },
    )
    h.drive_outbound(addon, flow)

    # The declared target legitimately receives the secret...
    assert h.REAL in flow.request.headers.get("Authorization", "")
    # ...but substitution does not follow the placeholder into other headers.
    assert h.REAL not in flow.request.headers.get("X-Smuggle", "")
    assert h.PLACEHOLDER in flow.request.headers.get("X-Smuggle", "")
