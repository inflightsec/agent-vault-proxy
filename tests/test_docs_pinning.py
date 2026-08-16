"""Doc-pinning: facts the code owns must not be hand-copied into docs and drift.

The docs-sweep runbook records that architecture.md repeatedly drifted by
hand-copying code-owned values, and twice documented mechanisms that never
existed. These assert the doc claim against the source of truth instead.
"""

from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[1]
DOCS = list((REPO / "docs").glob("*.md")) + [REPO / "README.md"]

_REAL_SUBCOMMANDS = {
    "binding",
    "doctor",
    "env",
    "gcp-setup",
    "mcp",
    "oauth",
    "run",
    "sandvault",
    "secret",
    "setup",
}


def _parser_subcommands() -> set[str]:
    from kow.cli.main import _build_parser

    parser = _build_parser()
    for action in parser._actions:
        if getattr(action, "choices", None):
            return set(action.choices)
    raise AssertionError("no subparser action found")


def test_subcommand_list_matches_the_parser() -> None:
    """If a subcommand is added or removed, this fails and the docs get looked at."""
    assert _parser_subcommands() == _REAL_SUBCOMMANDS


def test_live_docs_do_not_advertise_a_nonexistent_subcommand() -> None:
    """A backticked `kow <verb>` in the live docs must be a real verb.

    ADR files are excluded: they record decisions as they were made and may
    name commands that were proposed and never shipped.
    """
    real = _parser_subcommands()
    pattern = re.compile(r"`(?:\$ )?(?:kow|avp) ([a-z][a-z0-9-]*)")
    unshipped_marker = re.compile(r"not yet shipped|planned|unshipped", re.I)
    offenders: list[str] = []
    for doc in DOCS:
        for line in doc.read_text().splitlines():
            # A line that says the command is planned is honest, not drift.
            if unshipped_marker.search(line):
                continue
            for match in pattern.finditer(line):
                verb = match.group(1)
                if verb not in real:
                    offenders.append(f"{doc.relative_to(REPO)}:{verb}")
    assert offenders == [], f"docs advertise unshipped commands as real: {offenders}"


def test_healthz_sentinel_in_docs_matches_the_code() -> None:
    """ROADMAP quotes the probe host; it must be the one the addon answers."""
    from kow._healthz import HEALTHZ_HOST

    roadmap = (REPO / "docs" / "ROADMAP.md").read_text()
    if "healthz." in roadmap:
        assert HEALTHZ_HOST in roadmap


def test_systemd_unit_name_is_consistent_everywhere() -> None:
    """The docs and the installer's closing hint must name the unit that is
    actually written. `keys-on-the-wire` was never the unit name — following the
    old instruction gave operators `Unit not found`.
    """
    from kow import _paths

    unit = _paths.LINUX_SERVICE_UNIT
    assert f"{unit}.service" == _paths.LINUX_SERVICE
    bad = re.compile(
        r"(?:systemctl (?:start|stop|restart|status|is-active|enable|disable)"
        r"(?: --now)?|journalctl -u) (?!" + unit + r"\b)([a-z][a-z0-9._-]*)"
    )
    offenders: list[str] = []
    for doc in DOCS:
        for m in bad.finditer(doc.read_text()):
            offenders.append(f"{doc.relative_to(REPO)}: {m.group(0)}")
    assert offenders == [], f"docs name a unit that is not {unit!r}: {offenders}"
