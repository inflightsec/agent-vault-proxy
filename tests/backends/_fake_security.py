#!/usr/bin/env python3
"""A fake ``/usr/bin/security`` — enough of it to test the keychain backend.

The keychain backend is a wrapper around a subprocess, so the interesting
failure modes (argv leakage, the ``security -i`` quoting protocol, exit-code 44
vs a locked keychain) live in the process boundary itself. Monkeypatching
``subprocess.run`` would test the code either side of that boundary and skip the
boundary. This stub is a real executable instead: the backend spawns it exactly
as it would spawn the real tool, so argv, stdin, exit codes and stdout are all
genuinely exercised — on Linux, where the code is written.

It is NOT a keychain. It stores items as JSON and has no crypto, no ACLs, and no
locking beyond a simulated one. The real tool's behaviour is confirmed
separately by ``tests/vm-e2e/macos-e2e.sh --keychain`` on a live Mac.

Driven by the environment:

    FAKE_SECURITY_STORE     path to the JSON item store (required)
    FAKE_SECURITY_ARGV_LOG  path; one JSON argv list appended per invocation
    FAKE_SECURITY_FAIL      "locked" | "boom" — inject a failure mode
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_NOT_FOUND = 44


def _store_path() -> Path:
    return Path(os.environ["FAKE_SECURITY_STORE"])


def _load() -> list[dict[str, str]]:
    p = _store_path()
    if not p.exists():
        return []
    data: list[dict[str, str]] = json.loads(p.read_text() or "[]")
    return data


def _save(items: list[dict[str, str]]) -> None:
    _store_path().write_text(json.dumps(items))


def _tokenize(line: str) -> list[str]:
    """Split one ``security -i`` command line.

    Mirrors the real tool's parser: double quotes group, backslash escapes the
    next character. The backend's ``_quote`` is written against exactly this,
    and ``update()`` read-back-compares in production precisely because this
    agreement is an assumption rather than a guarantee.
    """
    out: list[str] = []
    cur: list[str] = []
    in_quotes = False
    escaped = False
    started = False
    for ch in line:
        if escaped:
            cur.append(ch)
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            started = True
            continue
        if ch == '"':
            in_quotes = not in_quotes
            started = True
            continue
        if ch.isspace() and not in_quotes:
            if started:
                out.append("".join(cur))
                cur, started = [], False
            continue
        cur.append(ch)
        started = True
    if started:
        out.append("".join(cur))
    return out


def _opts(argv: list[str]) -> tuple[dict[str, str], list[str]]:
    """Split ``-a NAME -s SVC -w [VALUE] -U`` into flags plus positionals."""
    flags: dict[str, str] = {}
    rest: list[str] = []
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in ("-a", "-s"):
            flags[tok] = argv[i + 1]
            i += 2
        elif tok == "-w":
            # `-w` takes a value on the write verbs and takes none on find.
            if i + 1 < len(argv) and not argv[i + 1].startswith("-"):
                flags["-w"] = argv[i + 1]
                i += 2
            else:
                flags["-w"] = ""
                i += 1
        elif tok == "-U":
            flags["-U"] = ""
            i += 1
        else:
            rest.append(tok)
            i += 1
    return flags, rest


def _find(items: list[dict[str, str]], acct: str, svce: str) -> dict[str, str] | None:
    for it in items:
        if it["acct"] == acct and it["svce"] == svce:
            return it
    return None


def _dispatch(argv: list[str]) -> int:  # noqa: C901 — flat verb table, one branch per verb
    fail = os.environ.get("FAKE_SECURITY_FAIL", "")
    if fail == "locked":
        print("SecKeychainCopySettings: User interaction is not allowed.", file=sys.stderr)
        return 51
    if fail == "boom":
        print("security: something went wrong", file=sys.stderr)
        return 1

    if not argv:
        return 2
    verb, argv = argv[0], argv[1:]
    flags, _rest = _opts(argv)
    items = _load()

    if verb == "show-keychain-info":
        print("Keychain has no timeout set.", file=sys.stderr)
        return 0

    if verb == "find-generic-password":
        it = _find(items, flags.get("-a", ""), flags.get("-s", ""))
        if it is None:
            print(
                "security: SecKeychainSearchCopyNext: The specified item could "
                "not be found in the keychain.",
                file=sys.stderr,
            )
            return _NOT_FOUND
        if "-w" in flags:
            # The real tool writes the password plus exactly one newline.
            sys.stdout.write(it["value"] + "\n")
        return 0

    if verb == "add-generic-password":
        acct, svce = flags.get("-a", ""), flags.get("-s", "")
        existing = _find(items, acct, svce)
        if existing is not None:
            if "-U" not in flags:
                print(
                    "security: The specified item already exists in the keychain.", file=sys.stderr
                )
                return 45
            existing["value"] = flags.get("-w", "")
        else:
            items.append({"acct": acct, "svce": svce, "value": flags.get("-w", "")})
        _save(items)
        return 0

    if verb == "delete-generic-password":
        it = _find(items, flags.get("-a", ""), flags.get("-s", ""))
        if it is None:
            print(
                "security: SecKeychainSearchCopyNext: The specified item could "
                "not be found in the keychain.",
                file=sys.stderr,
            )
            return _NOT_FOUND
        items.remove(it)
        _save(items)
        return 0

    if verb == "dump-keychain":
        for it in items:
            print('keychain: "/fake/test.keychain-db"')
            print('class: "genp"')
            print("attributes:")
            print(f'    "acct"<blob>="{it["acct"]}"')
            print(f'    "svce"<blob>="{it["svce"]}"')
        return 0

    print(f"security: unknown command {verb!r}", file=sys.stderr)
    return 2


def main() -> int:
    argv = sys.argv[1:]
    log = os.environ.get("FAKE_SECURITY_ARGV_LOG")
    if log:
        with open(log, "a") as fh:
            fh.write(json.dumps(argv) + "\n")

    if argv and argv[0] == "-i":
        rc = 0
        for line in sys.stdin.read().splitlines():
            if not line.strip():
                continue
            rc = _dispatch(_tokenize(line)) or rc
        return rc
    return _dispatch(argv)


if __name__ == "__main__":
    raise SystemExit(main())
