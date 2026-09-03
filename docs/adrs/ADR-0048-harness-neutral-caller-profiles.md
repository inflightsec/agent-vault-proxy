---
status: proposed
date: 2026-08-29
relates_to:
  - ADR-0012
  - ADR-0020
  - ADR-0029
  - ADR-0040
---

# ADR-0048: Harness-neutral caller profiles and parity verification

## Context

Keys on the Wire can protect any HTTPS client, but an agent harness only benefits when its launch environment carries the complete caller profile:

- proxy variables that route supported HTTP stacks through kow;
- a CA bundle each stack can use without losing the system trust roots;
- placeholder variables for every credential the harness is meant to use;
- a bypass list limited to control-plane and internal destinations that should not cross the proxy;
- filesystem permissions that let the harness read the public CA but not backend tokens, bindings, state or install salt.

Today operators assemble that profile in shell files, sandbox wrappers, service units or MCP configuration. Two harnesses on the same machine can therefore appear equivalent while exposing different credentials or using different trust settings. A shared shell template can also hide the gap: both processes inherit the same values, but neither integration owns an explicit capability contract.

The existing install check proves that the daemon imports, listens and remains active. It does not prove that a caller sends placeholders, that kow substitutes them, that a direct placeholder request fails, or that the caller cannot read backend material. A green daemon check can therefore coexist with a caller that has no working credential path.

## Decision

Treat each agent harness as a named caller profile. A profile is deployment configuration, not a new trust domain and not a copy of any real credential.

Each profile declares:

1. the HTTP stacks the harness and its child processes use;
2. the proxy, CA and bypass variables required by those stacks;
3. the set of placeholder capabilities exposed to the harness;
4. the backend files and directories the harness must not read;
5. one non-destructive round-trip probe for every capability class.

Deployment tooling renders caller environments from one shared credential catalog. Harness-specific files may select a subset or add stack-specific variables, but they do not duplicate placeholder literals. A deployment fails when a selected capability has a binding but no caller placeholder, or a caller placeholder has no binding.

Parity is explicit. Two harnesses have parity only when their selected capability sets and verification results match. Sharing a template or seeing the same environment variable names does not prove parity.

### Verify each caller profile

Every deployed profile runs four gates from the identity of the caller:

1. **Route gate:** the proxy endpoint is reachable and every required client stack uses the configured proxy and CA bundle.
2. **Substitution gate:** a non-destructive request carrying a placeholder succeeds through kow.
3. **Negative gate:** the same request sent without kow fails authentication. This proves the placeholder is not a usable credential by itself.
4. **Custody gate:** the caller cannot read the backend access token, rendered bindings, backend state or install salt. The public CA remains readable.

The verification output records names, destinations, status codes and permission results. It never records request headers, secret values, backend responses containing account data or environment values that may contain credentials.

For catalogs with many credentials, the deployment may group bindings by injector and client-stack class. At least one live probe closes each class, while static catalog checks close exact binding-to-placeholder coverage. Credentials with unusual auth behavior, including signatures, composite templates, request bodies and OAuth refresh, keep their own live probe.

### Keep harness authentication separate

A harness may need its own login material to reach its model provider. That credential is outside the caller profile unless kow can broker it without breaking the harness login flow. Documentation and audits must name this exception instead of claiming that the harness process contains no credential material at all.

The narrower guarantee remains: kow-protected service credentials do not enter the harness address space.

## Consequences

### Good

- Claude Code, Codex and later harnesses can be compared against a concrete capability set.
- Adding a binding without exposing its placeholder, or exposing a stale placeholder without a binding, fails during deployment.
- A listening daemon no longer counts as proof that an agent can use a brokered credential.
- Permission checks keep the backend account separate from agent accounts.
- The shared catalog removes drift without forcing every harness to expose every capability.

### Bad

- Deployment code must maintain live probes and choose endpoints that do not mutate data or incur material cost.
- Some SDKs ignore standard proxy variables, so each new client stack needs a verified adapter or launch setting.
- Full live probing can hit provider rate limits. Grouped probes reduce traffic but leave exact coverage to static checks.
- Harness-owned login tokens remain a documented exception until their native authentication flow supports brokerage.

### Out of scope

- Giving an agent account access to vault tokens, backend state or real credential values.
- Treating kow as the host egress firewall. Kernel-level enforcement remains deployment infrastructure.
- Claiming that credential custody prevents an authorized but malicious API action. Binding scope limits where and how a credential can be used; it does not infer intent.
- Standardizing vendor login stores for the agent harness itself.
