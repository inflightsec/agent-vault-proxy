"""Entrypoint / packaging smoke tests.

Regression guard for the 2026-08-03 incident: a wheel was installed WITHOUT
``__main__.py`` (stale pip cache), so ``python -m kow`` died with
"No module named kow.__main__; ... cannot be directly executed"
and the systemd daemon crash-looped for days.

These are cheap invariants on the package's own entrypoint — they do NOT boot
mitmproxy or bind the proxy port.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys


def test_main_module_is_importable() -> None:
    """`kow.__main__` must resolve as a submodule.

    This is the exact condition that broke: find_spec() returns None iff
    __main__.py is absent from the installed/importable package.
    """
    spec = importlib.util.find_spec("kow.__main__")
    assert spec is not None, "kow.__main__ is missing from the package"


def test_entrypoint_callable_imports() -> None:
    """The console-script / `-m` target `...__main__:main` must import and be callable.

    Import-only: defining main() has no side effects; mitmdump is imported lazily
    *inside* main(), so this never starts the proxy.
    """
    from kow.__main__ import main

    assert callable(main)


def test_daemon_import_chain_loads() -> None:
    """The exact import chain `main()` runs at startup must resolve.

    Guards dependency drift such as the 2026-08-03 crash-loop
    "module 'mitmproxy_rs' has no attribute 'Stream'" — an incompatible
    mitmproxy / mitmproxy-rs / mitmproxy-linux set installs cleanly but blows
    up when mitmdump is imported. Importing mitmdump does not start the proxy.
    """
    from mitmproxy.tools.main import mitmdump  # noqa: F401

    from kow.__main__ import main

    assert callable(main)


def test_python_dash_m_resolves_the_package() -> None:
    """`python -m kow` must not fail with a module-resolution error.

    We pass a deliberately bogus flag so mitmdump's own argparse rejects it fast
    and we never open a listening socket. A missing __main__.py fails *earlier*,
    at the interpreter's -m runpy stage, with the tell-tale message below — that
    is the failure this test exists to catch.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "kow", "--__smoke_bogus_flag__"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    combined = proc.stdout + proc.stderr
    assert "No module named kow.__main__" not in combined, combined
    assert "cannot be directly executed" not in combined, combined
