"""Threaded repro: concurrent COLD requests on one binding."""

from __future__ import annotations

import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from tests import _oauth_helpers as oh
from tests._oauth_helpers import PLACEHOLDER, FakeBackend, FakeResp


@pytest.fixture(autouse=True)
def stub_ssrf_dns(monkeypatch: pytest.MonkeyPatch):
    oh.apply_public_ssrf_stub(monkeypatch)
    yield


def test_concurrent_cold_requests_all_inject(tmp_path: Path) -> None:
    vault = {
        "GOOGLE_OAUTH_CLIENT_ID": "cid-real",
        "GOOGLE_OAUTH_CLIENT_SECRET": "csec-real",
        "GOOGLE_OAUTH_REFRESH_TOKEN": "rtok-real",
    }
    addon, audit_path, _client = oh.build_oauth_addon(tmp_path, backend=FakeBackend(vault))

    n = 4
    barrier = threading.Barrier(n)  # all threads reach the transport window together
    exchange_calls: list[int] = []

    def slow_transport(req, timeout=None):
        exchange_calls.append(1)
        import time as _t

        _t.sleep(0.15)  # hold the leader in-flight so followers pile up
        return FakeResp(oh.rotation_body(refresh_token="rtok-real"))  # echo, no rotation

    flows = []
    errors: list[BaseException] = []

    def drive() -> None:
        try:
            flow = oh.make_request("www.googleapis.com", {"Authorization": f"Bearer {PLACEHOLDER}"})
            addon.http_connect(flow)
            barrier.wait(timeout=5)
            addon.requestheaders(flow)
            flows.append(flow)
        except BaseException as e:  # noqa: BLE001
            errors.append(e)

    with patch(
        "kow.injectors.oauth2_refresh._transport_open",
        side_effect=slow_transport,
    ):
        threads = [threading.Thread(target=drive) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

    assert not errors, f"driver thread raised: {errors!r}"
    assert len(flows) == n
    # EVERY request must be served — no spurious 503 on the followers.
    for flow in flows:
        assert flow.response is None, (
            f"follower got denied: {flow.response.status_code if flow.response else None} "
        )
        assert flow.request.headers["Authorization"].startswith("Bearer at-")
    # And the whole storm cost exactly one upstream exchange.
    assert sum(exchange_calls) == 1
