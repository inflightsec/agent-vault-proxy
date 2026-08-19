"""The gallery's own guard (ADR-0043 decision 4).

Every exploit must declare the threat-model entry it defends, and every
``expected-leak`` must name the ADR/issue that will close it — so a known gap
can never rot into a silent "we leak here forever". This file is not an
exploit; it enforces the catalog convention on all the others.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.attacks

_DIR = Path(__file__).parent
_SELF = Path(__file__).name


def _attack_files() -> list[Path]:
    return sorted(p for p in _DIR.glob("test_*.py") if p.name != _SELF)


@pytest.mark.parametrize("path", _attack_files(), ids=lambda p: p.name)
def test_every_exploit_declares_a_threat(path: Path) -> None:
    assert re.search(r"THREAT:\s*T-\S+", path.read_text()), (
        f"{path.name} is missing a `THREAT: T-...` marker"
    )


@pytest.mark.parametrize("path", _attack_files(), ids=lambda p: p.name)
def test_expected_leaks_link_a_blocking_adr(path: Path) -> None:
    text = path.read_text()
    # Bind to real signals, not prose (Oracle C10): an `EXPECTED-LEAK:` marker
    # line or an actual `@pytest.mark.xfail` decorator — NOT a docstring that
    # merely mentions the word "xfail".
    is_expected_leak = bool(re.search(r"^EXPECTED-LEAK:", text, re.MULTILINE)) or (
        "@pytest.mark.xfail" in text
    )
    if is_expected_leak:
        assert re.search(r"BLOCKED-BY:\s*(ADR-\d{4}|#\d+)", text), (
            f"{path.name} is an expected-leak but declares no `BLOCKED-BY: ADR-NNNN`"
        )
