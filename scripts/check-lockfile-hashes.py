#!/usr/bin/env python3
# Structural check: every pinned package in a lockfile must carry at least one
# --hash=sha256:... continuation. Catches the "someone hand-edited the lockfile
# and dropped hashes" or "someone ran pip-compile without --generate-hashes"
# cases without needing network access or uv installed.
#
# SCOPE — read carefully. This script is a STRUCTURAL guard, not an
# enforcement mechanism. It confirms the lockfile is shaped correctly. It does
# NOT verify that hashes are valid (correct algorithm, sufficient length,
# associated with the right requirement, distinct per wheel, etc.), and it
# does NOT install anything. The ACTUAL enforcement is `pip install
# --require-hashes --only-binary :all: -r requirements.lock` — used by CI's
# `test` job (.github/workflows/test.yml) and the Dockerfile install path.
# pip itself refuses any install where a requirement lacks a matching hash.
#
# The two checks are complementary:
#   - This script catches "lockfile is structurally wrong" early (every commit).
#   - The install-time --require-hashes catches "lockfile is structurally
#     right but a hash doesn't match the wheel pip actually downloaded".
# Removing either weakens the supply-chain posture; do not.
#
# Pairs with the verify-lockfile CI job, which catches the third case:
# pyproject.toml deps drifted from the lockfile content.

import re
import sys
from pathlib import Path

LOCKFILES = ("requirements.lock", "requirements-dev.lock")
PIN_RE = re.compile(r"^([a-z0-9_.-]+)==([^\s\\]+)")


def check(path: Path) -> list[str]:
    failures: list[str] = []
    if not path.exists():
        return [f"{path}: missing"]
    lines = path.read_text().splitlines()
    for i, raw in enumerate(lines):
        line = raw.rstrip()
        m = PIN_RE.match(line)
        if not m:
            continue
        # A pinned package line must end with `\` so the next line(s) carry hashes.
        if not line.endswith("\\"):
            failures.append(f"{path}:{i + 1}: {m.group(1)}=={m.group(2)} has no hash continuation")
            continue
        # Peek ahead: at least one of the continuation lines must be a --hash=sha256:
        j = i + 1
        has_hash = False
        while j < len(lines):
            nxt = lines[j].rstrip()
            if "--hash=sha256:" in nxt:
                has_hash = True
            if not nxt.endswith("\\"):
                break
            j += 1
        if not has_hash:
            failures.append(f"{path}:{i + 1}: {m.group(1)} has no --hash=sha256:")
    return failures


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    all_failures: list[str] = []
    for name in LOCKFILES:
        all_failures.extend(check(root / name))
    if all_failures:
        print("Lockfile hash-pinning check FAILED:", file=sys.stderr)
        for f in all_failures:
            print(f"  {f}", file=sys.stderr)
        print(
            "\nRegenerate with:\n"
            "  CUTOFF=$(date -u -d '7 days ago' +%Y-%m-%dT%H:%M:%SZ)\n"
            '  uv pip compile --generate-hashes --exclude-newer "$CUTOFF" '
            "pyproject.toml -o requirements.lock\n"
            '  uv pip compile --generate-hashes --exclude-newer "$CUTOFF" '
            "--extra dev pyproject.toml -o requirements-dev.lock",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
