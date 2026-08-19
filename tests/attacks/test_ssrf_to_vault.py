"""SSRF at the secret store — point a request straight at the vault/backend.

THREAT: T-1  (prompt-injection exfil; ADR-0035 token-egress surface)

The agent aims a request at the credential backend's own host, hoping kow
proxies or injects toward it. The vault host is not in any binding, so the
connect gate denies it (unmatched_destination_policy: deny) with a 403 and no
secret ever touches the request.
"""

from __future__ import annotations

import pytest

from tests.attacks import _harness as h

pytestmark = pytest.mark.attacks


def test_request_to_unbound_vault_host_is_denied(tmp_path):
    addon, _audit = h.build_addon(tmp_path, bindings=h.WIDE)
    flow = h.make_flow(
        "vault.bitwarden.com",
        "GET",
        "/api/secrets",
        headers={"Authorization": f"Bearer {h.PLACEHOLDER}"},
    )
    h.drive_outbound(addon, flow)

    assert flow.response is not None, "unbound destination must be gated, not proxied"
    assert flow.response.status_code == 403
    assert h.REAL not in flow.request.headers.get("Authorization", "")
