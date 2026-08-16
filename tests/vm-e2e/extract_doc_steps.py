#!/usr/bin/env python3
"""Extract the runnable install steps from the documentation.

The documentation IS the test: this pulls the fenced ``bash`` blocks out of
`docs/install-systemd.md` in order, so a doc that drifts from reality breaks the
VM run. Blocks are filtered to the ones that make sense unattended (no editor,
no interactive prompt) and rewritten for the static backend.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

FENCE = re.compile(r"```bash\n(.*?)```", re.S)

# Lines that cannot run unattended in a fresh VM.
SKIP_LINE = re.compile(
    r"^\s*(?:sudoedit|\$EDITOR|vim?|nano)\b"
    r"|dscl "  # macOS-only user listing
    r"|read -rs"  # interactive token prompt
    r"|^\s*#",
)


def extract(doc: pathlib.Path) -> list[str]:
    steps: list[str] = []
    for block in FENCE.findall(doc.read_text()):
        lines = [ln for ln in block.splitlines() if ln.strip()]
        kept = [ln for ln in lines if not SKIP_LINE.search(ln)]
        if kept:
            steps.append("\n".join(kept))
    return steps


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("doc", type=pathlib.Path)
    ap.add_argument("--list", action="store_true", help="print blocks with indices")
    args = ap.parse_args()
    blocks = extract(args.doc)
    if args.list:
        for i, b in enumerate(blocks):
            print(f"--- block {i} ---")
            print(b)
        return 0
    print(f"{len(blocks)} runnable bash blocks in {args.doc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
