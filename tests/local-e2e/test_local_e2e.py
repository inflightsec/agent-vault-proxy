"""Pytest entry point for the container-free E2E harness.

Unmarked, so the regular ``pytest -q`` run (and the main CI job) executes it —
it needs no Docker, only ``mitmdump`` (already a runtime dep via mitmproxy).
The assertion logic lives in ``run.sh`` + ``client.py`` so the same harness is
runnable by hand: ``bash tests/local-e2e/run.sh``.

Robustness/security: this wrapper OWNS the temp dir and runs the harness in its
own process session, so a timeout SIGKILLs the whole group (no orphaned proxy)
and the generated secrets dir is removed on EVERY exit path — including timeout.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

E2E_DIR = Path(__file__).parent


def _resolve_mitmdump() -> str | None:
    beside = Path(sys.executable).parent / "mitmdump"
    if beside.exists():
        return str(beside)
    return shutil.which("mitmdump")


def test_local_end_to_end() -> None:
    mitm = _resolve_mitmdump()
    if mitm is None:
        pytest.skip("mitmdump not found next to the interpreter or on PATH")

    # Own the work dir here so it is removed on every exit path (the harness is
    # SIGKILLed on timeout below and its own EXIT trap would not run).
    workdir = tempfile.mkdtemp(prefix="avp-local-e2e.")
    os.chmod(workdir, 0o700)
    env = {**os.environ, "PYTHON": sys.executable, "MITMDUMP": mitm, "E2E_WORKDIR": workdir}
    proc = subprocess.Popen(
        ["bash", str(E2E_DIR / "run.sh")],
        cwd=str(E2E_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        start_new_session=True,  # own session → group-kill reaps bash + echo + proxy
    )
    try:
        try:
            out, err = proc.communicate(timeout=180)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            out, err = proc.communicate()
            pytest.fail(
                f"local E2E harness timed out (killed process group)\n"
                f"--- stdout ---\n{out}\n--- stderr ---\n{err}"
            )
        if proc.returncode != 0:
            pytest.fail(
                f"local E2E harness exited {proc.returncode}\n"
                f"--- stdout ---\n{out}\n--- stderr ---\n{err}"
            )
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
