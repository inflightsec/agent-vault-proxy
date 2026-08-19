"""Cross-binding leak — spend secret A's value under secret B's binding.

THREAT: T-1.5  (one secret's value must never cross into another's binding)

Two secrets, each bound to its own host. The agent warms secret A (OpenAI) so
its real value is live in the cache, then hits host B (GitHub) carrying A's
placeholder, betting kow injects A's value — or serves it from cache — on B's
request. Injection requires BOTH an authorized binding AND the secret's own
placeholder in the target header: on host B, A's placeholder matches nothing,
so A's value never appears. A control request with B's own placeholder proves
the machinery is live (not a vacuous pass) and that B only ever gets B's value.
"""

from __future__ import annotations

import pytest

from tests.attacks import _harness as h

pytestmark = pytest.mark.attacks


def test_secret_value_never_crosses_into_another_binding(tmp_path):
    addon, _audit = h.build_addon_two_secrets(tmp_path)

    # Warm secret A on its own host so its real value is live in the cache.
    warm = h.make_flow(
        h.BOUND_HOST, "POST", "/v1/chat", headers={"Authorization": f"Bearer {h.PLACEHOLDER}"}
    )
    h.drive_outbound(addon, warm)
    assert h.REAL in warm.request.headers.get("Authorization", ""), "sanity: A injected on A"

    # Attack: hit host B carrying A's placeholder, with A hot in the cache.
    attack = h.make_flow(
        h.BOUND_HOST_B, "POST", "/repos", headers={"Authorization": f"Bearer {h.PLACEHOLDER}"}
    )
    h.drive_outbound(addon, attack)
    attack_auth = attack.request.headers.get("Authorization", "")
    assert h.REAL not in attack_auth, "secret A must never ride a host-B request"
    assert h.REAL_B not in attack_auth, "B is not injected either — wrong placeholder for B"

    # Control: host B WITH B's own placeholder → B (and only B) is injected.
    # Proves the path is live and A never bleeds in even when B legitimately fires.
    control = h.make_flow(
        h.BOUND_HOST_B, "POST", "/repos", headers={"Authorization": f"Bearer {h.PLACEHOLDER_B}"}
    )
    h.drive_outbound(addon, control)
    control_auth = control.request.headers.get("Authorization", "")
    assert h.REAL_B in control_auth, "host B must receive its own secret"
    assert h.REAL not in control_auth, "secret A must not cross into host B's injection"
