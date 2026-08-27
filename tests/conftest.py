"""Guard: the suite must exercise the working tree, not an installed copy.

Without this, running pytest in an environment where `keys-on-the-wire` is
installed non-editable (a wheel, a pipx install, or the /opt/kow service venv)
silently imports THAT `kow` while collecting THIS repo's tests. New tests then
fail against old code with confusing errors (AttributeError on a field the
source clearly has), and — worse — a green run can certify code that is not the
code in front of you.

Fail loudly instead, naming the fix.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_REPO_SRC = Path(__file__).resolve().parent.parent / "src"


def pytest_configure(config: pytest.Config) -> None:
    import kow

    kow_path = Path(kow.__file__).resolve()
    try:
        kow_path.relative_to(_REPO_SRC)
    except ValueError:
        raise pytest.UsageError(
            f"kow resolves to {kow_path}, not this repo's src/ ({_REPO_SRC}).\n"
            "The tests would run against an installed copy instead of your working tree.\n"
            "Fix with an editable install in the venv you are testing with:\n"
            "    python -m pip install -e .\n"
            "or run the suite with the source tree first on the path:\n"
            "    PYTHONPATH=src python -m pytest"
        ) from None
