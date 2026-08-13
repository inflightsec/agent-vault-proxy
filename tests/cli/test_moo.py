"""Tests for the hidden ``kow moo`` easter egg."""

from __future__ import annotations

import pytest

from kow.cli import main as cli_main
from kow.cli.moo import _LINES, cowsay, run_moo


def test_cowsay_wraps_text_and_draws_cow() -> None:
    art = cowsay("hi")
    assert "< hi >" in art
    # Bubble border scales to the text.
    assert "____" in art
    # The cow itself.
    assert "^__^" in art
    assert "(oo)" in art


def test_run_moo_prints_known_line_and_succeeds(capsys: pytest.CaptureFixture[str]) -> None:
    rc = run_moo()
    assert rc == 0
    out = capsys.readouterr().out
    assert any(line in out for line in _LINES)
    assert "(oo)" in out


def test_moo_dispatches_through_the_cli(capsys: pytest.CaptureFixture[str]) -> None:
    rc = cli_main.main(["moo"])
    assert rc == 0
    assert "(oo)" in capsys.readouterr().out


def test_moo_is_hidden_from_help(capsys: pytest.CaptureFixture[str]) -> None:
    # It's an easter egg: it must dispatch, but never appear in --help — not
    # even in the subcommand choices metavar.
    with pytest.raises(SystemExit):
        cli_main.main(["--help"])
    assert "moo" not in capsys.readouterr().out
