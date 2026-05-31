"""Pytest entry point for the Docker E2E harness.

Marked ``@pytest.mark.docker`` so the regular ``pytest -q`` run skips
it. Trigger explicitly with ``pytest -m docker`` (locally) or via the
``e2e-docker`` CI job (.github/workflows/test.yml).

Delegating to ``run.sh`` keeps the assertion logic in one place — the
shell script doubles as a quickstart smoke test an operator can run by
hand, and the CI / pytest path just shells out to it. If a step
fails, ``run.sh`` returns non-zero and we surface its stderr.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

E2E_DIR = Path(__file__).parent


@pytest.mark.docker
def test_docker_end_to_end() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not on PATH; install Docker to run the E2E harness")

    daemon_check = subprocess.run(
        ["docker", "info"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if daemon_check.returncode != 0:
        pytest.skip(
            "docker daemon unreachable (start Docker Desktop / dockerd to "
            f"run the E2E harness): {daemon_check.stderr.strip()[:200]}"
        )

    result = subprocess.run(
        ["bash", str(E2E_DIR / "run.sh")],
        cwd=str(E2E_DIR),
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        pytest.fail(
            f"E2E harness exited {result.returncode}\n"
            f"--- stdout ---\n{result.stdout}\n"
            f"--- stderr ---\n{result.stderr}"
        )
