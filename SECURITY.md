# Security Policy

## Supported versions

The current minor version receives security fixes. Older versions do not, upgrading is the supported path. Once we cut `v1.0.0`, this policy will be revised to support the most recent major version + the immediately previous one.

| Version | Supported |
|---|---|
| `0.4.x` | ✓ |
| `< 0.4` | ✗ |

## Reporting a vulnerability

**Please do not report security issues via public GitHub issues, pull requests, or discussions.**

Use **GitHub's private vulnerability reporting** for this repository:

1. Go to the [Security](../../security) tab.
2. Click **Report a vulnerability**.
3. Fill in the form with reproduction steps and impact.

This delivers the report privately to maintainers and lets us coordinate disclosure without exposing the issue before a fix is available.

If GitHub's reporting flow is unavailable to you, open a *minimal* public issue stating "I'd like to discuss a security matter privately - please provide a contact channel," with no details about the vulnerability itself. We will respond with a private channel.

## What to include in a report

A useful report has:

- **Affected version** (`pip show agent-vault-proxy` or commit SHA)
- **Type of issue** (e.g., placeholder substitution bypass, audit log integrity, secret leak to logs, sandbox escape, supply-chain concern)
- **Reproduction steps** - minimal, deterministic, ideally with a config snippet and a curl/python command
- **Impact**, what an attacker gains, under what trust assumptions
- **Suggested fix** if you have one (not required)

If your report falls outside the threat model documented in [`docs/architecture.md`](./docs/architecture.md) §3, please say so - we may still want to know about it, but the response will be different (likely a documentation update rather than a code fix).

## Response targets

We aim for:

| Phase | Target |
|---|---|
| Acknowledgement of receipt | 3 business days |
| Initial triage + severity assessment | 7 business days |
| Fix + coordinated disclosure window | 90 days (adjustable by mutual agreement) |

These are targets, not contractual guarantees. This is an open-source project maintained on a best-effort basis. If a report sits longer than the target, please follow up - it may have been missed.

### Example coordinated-disclosure timeline

```
Day  0   Report received via GitHub private vulnerability reporting
Day  1   Acknowledgement; clarifying questions if any
Day  5   Triage complete; severity assigned (CVSS); fix path agreed
Day 30   Patch landed in main; SECURITY advisory drafted
Day 35   Release with fix (point release on the supported minor)
Day 45   Public advisory published; CVE assigned if appropriate; reporter credited
Day 90   Hard deadline for full public disclosure (sliding earlier on mutual agreement, later only by mutual agreement)
```

The 90-day clock starts at receipt, not at fix. We will not silently extend it.

## Scope

**In scope**: please report:

- Violations of any of the G1–G9 atomic guarantees (see [`docs/architecture.md`](./docs/architecture.md) §3)
- Placeholder substitution bypass (e.g., substring/encoding tricks that get the real secret out without a matching binding)
- Audit log integrity (events missed, fsync skipped, ordering wrong relative to upstream write)
- Secret leakage into the daemon's own logs, stack traces, or error messages
- Sandbox escape from the `avp` system user
- Hardening regression in the shipped systemd unit example
- `bindings.example.yaml` or documentation that could lead an operator into a materially insecure default
- Supply-chain concerns about how we build/ship the package (lockfile, install-time controls, action pinning)

**Out of scope**: please report upstream:

- CVEs in `mitmproxy`, `bitwarden-sdk`, `pydantic`, `pyyaml`, or other transitive dependencies, **where the impact is limited to that dependency's own behavior**, report to those projects. We will track and bump the lockfile after the cooldown window. **However**: if a dependency CVE is exploitable *through AVP's deployment* in a way that affects the G1–G9 guarantees or any of our public claims (e.g., a `mitmproxy` parser bug that lets an upstream response inject headers back into the agent, or a `bitwarden-sdk` bug that leaks the access token into our logs under specific request shapes), that is **in-scope**. Root-cause disclosure still goes to the upstream maintainer; the AVP-specific exposure analysis and any mitigation (patch, scope tightening, pin update with cooldown override) is ours.
- The operator's own bindings configuration (e.g., declaring an overly broad host wildcard, omitting `methods: [GET]` on a binding that should have it)
- The operator's host firewall, OS, BWS organization configuration, or shell history hygiene
- Anything in [`docs/architecture.md`](./docs/architecture.md) §11 (Out of scope): those are documented non-defenses, not vulnerabilities

## Threat-model boundaries

We document accepted residual risks explicitly in [`docs/architecture.md`](./docs/architecture.md) §12. A report that targets one of those acknowledged risks (e.g., "UID-of-proxy compromise discloses bound secrets") is welcome but won't be treated as a fix-required vulnerability - it's a known trade-off. A report demonstrating that one of the documented atomic guarantees (G1–G9) can be violated **is** a fix-required vulnerability.

## Public disclosure

After a fix ships, we will:

- Publish a GitHub Security Advisory with a CVE if appropriate
- Credit the reporter (with their permission) in the advisory and CHANGELOG
- Provide a backport patch if practical and the affected version is still supported

Reporters who prefer anonymity will be credited as "an anonymous security researcher" or omitted entirely on request.

## Bug bounty

There is no monetary bounty program at this time. Thanks-and-credit only.
