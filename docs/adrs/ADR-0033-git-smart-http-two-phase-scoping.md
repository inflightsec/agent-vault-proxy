---
status: proposed
date: 2026-07-24
relates_to: docs/architecture.md §3 (G5 enforcement by omission), BindingSpec.matches_scope, matching.path_glob_matches
---

# ADR-0033: Git smart-HTTP two-phase scoping — canonicalise the discovery GET to its data-phase path

## Context

Git's smart-HTTP protocol is a **two-phase** operation. A push (`git-receive-pack`) — and,
symmetrically, a clone/fetch (`git-upload-pack`) — begins with a **discovery** request:

```
GET  <repo>.git/info/refs?service=git-receive-pack     # phase 1: ref advertisement
POST <repo>.git/git-receive-pack                        # phase 2: the actual data
```

The write-vs-read intent of phase 1 lives entirely in the **`?service=` query parameter**. AVP's
path scoping (`BindingSpec.matches_scope` → `matching.path_glob_matches`) matches the
**query-stripped** path by contract. So both discovery requests — clone and push — reduce to the
same path `<repo>.git/info/refs`, indistinguishable to a `paths:` scope.

Consequence: an operator who scopes a GitHub PAT binding to allow clone but not push —
`paths: ["/**/git-upload-pack"]` — would still have the credential injected into the
**push discovery GET**, because that GET's path (`.../info/refs`) is not the push path the scope
denies. The handshake that authorises a push would be credentialed against the operator's intent.
Method scoping cannot fix this either: both discovery phases are `GET` and both data phases are
`POST`, so method can never separate git read from git write. **Path is the only correct lever, and
it only works if the `service=` query is honoured.**

## Decision

Canonicalise a git smart-HTTP **discovery** request to its **data-phase** path before scope
matching. `matching.git_smart_http_effective_path(path, query)`:

- For `<repo>.git/info/refs?service=git-receive-pack` → returns `<repo>.git/git-receive-pack`.
- For `?service=git-upload-pack` → `<repo>.git/git-upload-pack`.
- For anything else — a path not ending in `/info/refs`, a missing/empty/duplicate `service`, or a
  `service` value outside the two known git services — returns the path **unchanged** (strict no-op
  for all non-git traffic).

The addon (`requestheaders`) applies this at the boundary where the full path+query is still
available, then passes the canonical path to the pure `decide()`. A `paths:` scope now treats a
service's discovery and data phases as **one logical operation**: `paths: ["/**/git-upload-pack"]`
permits clone (both phases) and denies push (both phases). A denied push discovery falls through to
G5 enforcement-by-omission — the placeholder is forwarded verbatim, audited `binding_scope_violation`
with the canonical data-phase path, and the upstream returns its own auth failure. No proxy-originated
error, no oracle.

## Consequences

**Good**
- `paths:`-based git read/write separation is now correct across both protocol phases.
- The audited scope-violation `path` names the git service (`git-receive-pack`), a clearer operator
  signal than the raw `/info/refs`.
- Pure, isolated helper — unit-tested directly; zero effect on non-git traffic.

**Bad / cost**
- One more transform on the request path. Bounded, allocation-light, and gated on the `/info/refs`
  suffix so the common path pays ~nothing.

**Out of scope**
- Method scoping for git (documented as the wrong tool — clone's data phase is itself a POST, so a
  `methods: [GET]` "read-only" binding would break clone anyway; use `paths:`).
- The git-over-SSH transport (AVP brokers HTTP(S) only).
- Dumb-HTTP git (no `?service=`), which is already matched literally by path.
