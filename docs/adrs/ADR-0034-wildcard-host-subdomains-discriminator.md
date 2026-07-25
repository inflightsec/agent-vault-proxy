---
status: proposed
date: 2026-07-24
relates_to: ADR-0021 (multi-host notes binding), docs/architecture.md §4.2, BindingSpec.matches_host, config.allow_wildcard_hosts
---

# ADR-0034: Wildcard-host `subdomains:` discriminator — narrow a `*.` binding to a named label allowlist

## Context

AVP supports `*.` wildcard binding hosts, gated behind the `allow_wildcard_hosts: true` opt-in and a
public-suffix denylist (a wildcard may not span a registry TLD). But an opted-in `*.jfrog.io` binding
still injects the credential into **any** single-label subdomain — `mycompany.jfrog.io` and
`evil.jfrog.io` alike. For multi-tenant SaaS whose tenants are subdomains (JFrog Artifactory, many
`*.zendesk.com`/`*.atlassian.net`-style hosts), the wildcard's blast radius is "every tenant under the
suffix", when the operator only ever means their own.

The exact-host binding (`mycompany.jfrog.io`) avoids this but forces the operator to enumerate full
hosts and loses the wildcard's convenience when several known tenant subdomains share one credential
policy. What's missing is a way to keep the wildcard **shape** while pinning **which** subdomains it
may match.

## Decision

Add an optional `subdomains:` list to `BindingSpec`, valid **only** on a `*.` wildcard host. When set,
the wildcard's single matched leftmost label must be one of the listed exact labels:

```yaml
bindings:
  - host: "*.jfrog.io"
    subdomains: ["mycompany", "mycompany-staging"]   # never evil.jfrog.io
```

Enforced by a new `BindingSpec.matches_host(host)` — the host gate `policy.matched_binding` now uses
in place of a bare `host_matches_pattern` call. `matches_host` first applies the wildcard pattern
(guaranteeing a single-label match), then requires the leftmost label ∈ `subdomains`. A non-listed
subdomain yields no matched binding → G5 forward-verbatim, no injection, audited
`destination_not_in_binding`.

Validation (config-load, fail-closed): `subdomains:` on an exact host is rejected (meaningless — the
host already pins the subdomain); an empty list is rejected (deny-all — omit instead); each entry must
be a single DNS label (no dots, no wildcard), lowercased.

## Consequences

**Good**
- Shrinks a wildcard's blast radius from "every subdomain under the suffix" to a named allowlist,
  without enumerating full hosts — defence-in-depth on top of `allow_wildcard_hosts`.
- Fail-closed and G5-preserving: a disallowed subdomain leaks nothing (placeholder forwarded, upstream
  rejects), never a proxy-originated error.

**Bad / cost**
- `config.secrets_for_host()` — the config-load host **index** used by the `unmatched_destination:
  deny` allow-list gate — remains pattern-based and does not know the discriminator, so a wildcard host
  still counts as "a bound destination" for that coarse pre-gate. This is harmless: the load-bearing
  injection gate (`matched_binding` → `matches_host`) is exact and fail-closed, so a disallowed
  subdomain is still never injected. Tightening the index is a possible follow-up, not required for
  correctness.

**Out of scope**
- Notes/annotation-sourced `subdomains:` (file-config only for now; extending the notes surface is a
  separate decision — `_ALLOWED_NOTE_KEYS` is unchanged).
- Multi-label discriminators (AVP wildcards match exactly one label by construction).
- Relaxing `allow_wildcard_hosts` for discriminated wildcards (a discriminated `*.` is safer, but the
  opt-in stays required; revisit if operators ask).
