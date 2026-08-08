from __future__ import annotations

import re
from functools import lru_cache
from urllib.parse import parse_qs

# Git smart-HTTP is a TWO-PHASE operation. A push (`git-receive-pack`) — and a
# clone/fetch (`git-upload-pack`) — begins with a discovery `GET
# <repo>.git/info/refs?service=<svc>` and only then sends the data-phase
# `POST <repo>.git/<svc>`. The write intent lives in the `?service=` QUERY,
# which `path_glob_matches` strips — so a `paths:` scope written to allow clone
# (`git-upload-pack`) but deny push (`git-receive-pack`) would match BOTH
# discovery GETs identically at `<repo>.git/info/refs`, injecting the
# credential into the push handshake it was meant to refuse. Canonicalising the
# discovery request to its data-phase path makes both phases scope-match as one
# logical operation (ADR-0033). Prior art for the two-phase gap: transparent
# auth-proxies that scope git by path must treat the discovery GET as the
# service it advertises.
_GIT_INFO_REFS_SUFFIX = "/info/refs"
_GIT_SMART_HTTP_SERVICES = frozenset({"git-upload-pack", "git-receive-pack"})


def git_smart_http_effective_path(path: str, query: str | None) -> str:
    """Canonicalise a git smart-HTTP discovery request to its data-phase path.

    For ``GET <repo>.git/info/refs?service=git-receive-pack`` returns
    ``<repo>.git/git-receive-pack`` so ``paths:`` scoping treats the discovery
    handshake identically to the POST it authorises. ``path`` is the
    query-stripped request path; ``query`` is the raw query string (or None).
    Any non-git request — a path not ending in ``/info/refs``, a missing/empty
    ``service`` param, or a ``service`` value outside the known git services —
    is returned UNCHANGED, so this is a no-op for all non-git traffic.
    """
    if not query or not path.endswith(_GIT_INFO_REFS_SUFFIX):
        return path
    services = parse_qs(query).get("service", [])
    if len(services) != 1 or services[0] not in _GIT_SMART_HTTP_SERVICES:
        return path
    base = path[: -len(_GIT_INFO_REFS_SUFFIX)]
    return f"{base}/{services[0]}"


def host_matches_pattern(host: str, pattern: str) -> bool:
    # DNS is case-insensitive; normalize both sides so a request to
    # `API.OpenAI.com` matches a binding written as `api.openai.com`.
    # Config-load already lowercases binding hosts, but the runtime input
    # comes straight from the client's request line / Host header and may
    # carry uppercase — match-time normalization is the load-bearing one.
    host = host.lower()
    pattern = pattern.lower()
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
