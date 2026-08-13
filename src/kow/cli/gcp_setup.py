"""``kow gcp-setup`` — grant a service account PER-SECRET Secret Manager access.

The secure-by-default install helper for the `gsm` backend (ADR-0018 §6). It
grants `roles/secretmanager.secretAccessor` on each named secret **individually**
and **REFUSES** to bind at project / folder / org scope — a broad bind would let
the proxy's identity read every secret in the project, exactly the blast radius
the backend's `self_check` exists to prevent.

Shells out to `gcloud` (the operator's authenticated admin session); kow's own
low-privilege runtime identity never runs this.
"""

from __future__ import annotations

import subprocess
import sys

_ROLE = "roles/secretmanager.secretAccessor"


def run_gcp_setup(
    *,
    project: str,
    member: str,
    secrets: list[str],
    scope: str = "secret",
    dry_run: bool = False,
) -> int:
    """Grant ``member`` per-secret ``secretAccessor`` on each of ``secrets``.

    ``scope`` MUST be ``secret``; anything else is refused loudly. Returns 0 on
    success, 1 if a gcloud grant failed, 2 on misuse (broad scope / no secrets).
    """
    if scope != "secret":
        print(
            f"kow gcp-setup: refusing scope={scope!r}. This helper ONLY grants per-secret "
            f"{_ROLE}; a project/folder/org-level bind would give the proxy read access to "
            "EVERY secret in scope — the exact blast radius self_check guards against. Grant "
            "per-secret, or use gcloud directly if you truly intend a broad bind.",
            file=sys.stderr,
        )
        return 2
    if not secrets:
        print("kow gcp-setup: no secrets given (use --secret NAME, repeatable).", file=sys.stderr)
        return 2

    rc = 0
    for secret in secrets:
        cmd = [
            "gcloud",
            "secrets",
            "add-iam-policy-binding",
            secret,
            f"--project={project}",
            f"--member={member}",
            f"--role={_ROLE}",
            "--condition=None",
        ]
        if dry_run:
            print("DRY-RUN: " + " ".join(cmd))
            continue
        print("+ " + " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)  # noqa: S603
        if result.returncode != 0:
            print(f"  FAILED ({result.returncode}): {result.stderr.strip()[:300]}", file=sys.stderr)
            rc = 1
        else:
            print(f"  granted {_ROLE} on {secret} to {member}")
    return rc
