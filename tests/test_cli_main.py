"""``avp`` CLI dispatcher — argparse wiring for the operator subcommands.

The daemon entry point is ``agent-vault-proxy`` (mitmdump). ``avp`` is the
separate operator CLI (``avp env``, ``avp doctor``). This tests only the
arg parsing/dispatch, not the per-subcommand behaviour (covered in
test_cli_env / test_cli_doctor).
"""

from __future__ import annotations

import pytest

from kow.cli.main import main


def test_no_subcommand_prints_help_and_errors(capsys) -> None:
    rc = main([])
    assert rc != 0


def test_unknown_subcommand_errors() -> None:
    # argparse exits with SystemExit(2) on an unknown choice.
    with pytest.raises(SystemExit):
        main(["frobnicate"])


def test_env_dispatch_invokes_run_env(monkeypatch) -> None:
    called = {}

    def fake_run_env(**kwargs):
        called.update(kwargs)
        return 0

    monkeypatch.setattr("kow.cli.main.run_env", fake_run_env)
    rc = main(["env", "--config", "/tmp/b.yaml", "--print"])
    assert rc == 0
    assert called["config_path"] == "/tmp/b.yaml"
    assert called["print_only"] is True


def test_doctor_dispatch_invokes_run_doctor(monkeypatch) -> None:
    called = {}

    def fake_run_doctor(**kwargs):
        called.update(kwargs)
        return 0

    monkeypatch.setattr("kow.cli.main.run_doctor", fake_run_doctor)
    rc = main(["doctor"])
    assert rc == 0
    # run_doctor is called (kwargs may be all-None defaults).
    assert "ca_cert_path" in called
