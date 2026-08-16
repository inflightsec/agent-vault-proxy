"""``kow`` daemon entry point (``__main__``).

Covers argv assembly for mitmdump and return-code passthrough. mitmdump is
imported lazily inside ``main`` from ``mitmproxy.tools.main``, so we patch it
there.
"""

from __future__ import annotations

import sys

import kow.__main__ as entry


def test_main_assembles_mitmdump_args_and_returns_zero(monkeypatch) -> None:
    captured: dict[str, list[str]] = {}

    def fake_mitmdump(args: list[str]):
        captured["args"] = args
        return  # mitmdump returns None on a clean exit

    monkeypatch.setattr("mitmproxy.tools.main.mitmdump", fake_mitmdump)
    monkeypatch.setattr(sys, "argv", ["kow", "--set", "x=1"])

    rc = entry.main()

    assert rc == 0
    a = captured["args"]
    assert a[0] == "-s"
    assert a[1].endswith("addon.py")
    assert a[2:6] == ["--listen-host", "127.0.0.1", "--listen-port", "14322"]
    assert a[-2:] == ["--set", "x=1"]  # passthrough of sys.argv[1:]


def test_main_passes_through_nonzero_mitmdump_return(monkeypatch) -> None:
    monkeypatch.setattr("mitmproxy.tools.main.mitmdump", lambda args: 3)
    monkeypatch.setattr(sys, "argv", ["kow"])
    assert entry.main() == 3
