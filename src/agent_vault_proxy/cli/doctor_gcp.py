"""``avp doctor --probe-gcp`` — read-only Google Secret Manager scope report.

Loads the configured `gsm` backend and prints what its identity can and cannot
reach: whether it authenticates keyless, whether it can enumerate secrets
outside its `secret_prefix`, whether it holds project-wide `versions.access`,
and how many secrets are in scope. Read-only — every call is a
read / list / testIamPermissions, never a write. Mirrors `--probe-oauth`.
"""

from __future__ import annotations

import sys

from agent_vault_proxy.config import build_backend, load_config


def run_gcp_probe(*, config_path: str | None) -> bool:
    """Print the read-only GSM scope report. Returns True if any ``FAIL`` row
    (or a pre-probe config/backend error) — the caller folds it into the exit
    code."""
    if config_path is None:
        print("avp doctor --probe-gcp: --config <path> is required.", file=sys.stderr)
        return True
    try:
        config = load_config(config_path)
    except Exception as e:  # noqa: BLE001 — operator-facing CLI surface
        print(
            f"avp doctor --probe-gcp: cannot load config {config_path}: {type(e).__name__}: {e}",
            file=sys.stderr,
        )
        return True

    backend_type = config.backend.type if config.backend is not None else None
    if backend_type != "gsm":
        print(
            f"avp doctor --probe-gcp: backend is {backend_type!r}, not 'gsm' — nothing to probe.",
            file=sys.stderr,
        )
        return True

    try:
        backend, _ = build_backend(config)
    except Exception as e:  # noqa: BLE001 — operator-facing CLI surface
        print(
            f"avp doctor --probe-gcp: cannot build gsm backend: {type(e).__name__}: {e}",
            file=sys.stderr,
        )
        return True

    rows = backend.diagnose()
    # Trust-boundary advisory: when host bindings come from `avp-binding`
    # annotations, whoever holds `secretmanager.secrets.update` controls where
    # each secret is sent — even without `versions.access`. AVP reads with its
    # own identity, so a metadata-only writer can redirect a secret it cannot
    # itself read (confused deputy). Lock annotation-write to the value-read
    # trust tier. Only relevant when annotations are load-bearing.
    if config.binding_source in ("notes", "both"):
        rows.append(
            (
                "WARN",
                "annotation-trust",
                "bindings come from `avp-binding` annotations — restrict "
                "secretmanager.secrets.update to principals already trusted to read these "
                "secrets (annotation-write == binding-control)",
            )
        )
    print()
    print("avp doctor --probe-gcp: GSM identity scope")
    for status, check, msg in rows:
        print(f"    {status:5s} {check:12s} {msg}")
    print()
    any_fail = any(status == "FAIL" for status, _, _ in rows)
    if any_fail:
        print("avp doctor --probe-gcp: one or more FAIL", file=sys.stderr)
    else:
        print("avp doctor --probe-gcp: report complete (WARN rows are advisory)")
    return any_fail
