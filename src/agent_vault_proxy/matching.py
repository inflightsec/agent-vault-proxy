from __future__ import annotations

import re
from functools import lru_cache


def host_matches_pattern(host: str, pattern: str) -> bool:
    if pattern == host:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]
        if not host.endswith(suffix):
            return False
        prefix = host[: -len(suffix)]
        return bool(prefix) and "." not in prefix
    return False


@lru_cache(maxsize=256)
def _compile_path_pattern(pattern: str) -> re.Pattern[str]:
    regex_parts: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern[i : i + 2] == "**":
            regex_parts.append(".*")
            i += 2
        elif pattern[i] == "*":
            regex_parts.append("[^/]*")
            i += 1
        else:
            regex_parts.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(regex_parts))


def path_glob_matches(pattern: str, path: str) -> bool:
    """Glob-match a URL path with segment-aware semantics.

    `*`  matches anything except `/` (single path segment)
    `**` matches anything including `/` (any number of segments)
    Everything else is matched literally.

    Caller is responsible for stripping query strings before calling.
    """
    return _compile_path_pattern(pattern).fullmatch(path) is not None
