"""Layer 2 smoke test: verify BWS integration end-to-end, no proxy involved.

Reads the smoke bindings.yaml, instantiates the BWS backend directly via the
backend registry, wraps it in the caching client, fetches the configured
secret, and prints the first 8 bytes only (never the full value). If this
fails, BWS itself is the problem, not the proxy.

Run from the repo root:
    BWS_ACCESS_TOKEN=$(cat /tmp/avp-smoke/bws-token) \\
        .venv/bin/python tests/smoke/layer2_bws_read.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from kow.caching import CachingSecretsClient
from kow.config import build_backend, load_config


def main() -> int:
    config_path = Path(__file__).parent / "bindings.smoke.yaml"
    config = load_config(config_path)
    if config.backend is None:
        print("FAIL: bindings.smoke.yaml has no 'backend:' block")
        return 1
    if config.backend.config.get("organization_id") == "REPLACE_BEFORE_RUN":
        print("FAIL: edit bindings.smoke.yaml and set backend.config.organization_id")
        return 1

    backend, _backend_config = build_backend(config)
    client = CachingSecretsClient(
        backend,
        ttl_seconds=config.cache.ttl_seconds,
        jitter_seconds=config.cache.jitter_seconds,
        max_entries=config.cache.max_entries,
    )

    for secret_name in config.secrets:
        try:
            value = client.get(secret_name).reveal()
        except Exception as e:
            print(f"FAIL [{secret_name}]: {type(e).__name__}: {e}")
            return 1
        prefix = value[:8] if len(value) >= 8 else "(short)"
        print(f"OK   [{secret_name}]: fetched, length={len(value)}, prefix={prefix!r}")

    print("PASS: BWS integration works end-to-end")
    return 0


if __name__ == "__main__":
    sys.exit(main())
