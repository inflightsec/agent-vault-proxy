---
status: accepted
date: 2026-07-18
relates_to: ADR-0011 (notes bindings), ADR-0018 (GSM backend, 4th-pass confused-deputy finding), ADR-0021 (multi-host notes), docs/architecture.md §4.2
---

# ADR-0024: File-side notes host allowlist — annotations may only narrow, never add a host

## Context

A notes/annotation binding (BWS secret `notes`, GSM `avp-binding` annotation) can name the
destination `host:` a credential is injected toward. That is the whole point of the North Star:
add a secret, tag it with a host, done — no config edit, no redeploy.

ADR-0018's fourth cross-vendor review surfaced a confused-deputy in that convenience. On GCP,
`secretmanager.secrets.update` (edit a secret's annotations) and `secretmanager.versions.access`
(read its value) are **independently grantable** permissions. A principal who can write the
`avp-binding` annotation but **cannot read the secret** can point it at a host they control; AVP
then reads the value with its own identity and injects it there — exfiltrating a secret the
attacker could never read directly. The daemon's `_assert_in_scope` bounds the secret *name*, not
the destination host, so it does not mitigate this. `avp doctor --probe-gcp` already emits an
`annotation-trust` WARN, but a warning is not a control.

This is not exploitable on BWS (which does not separate note-write from value-read) and is moot in
a single-operator project where one identity holds both permissions. It bites in **split-IAM /
multi-tenant** GCP deployments — exactly where AVP wants to be credible.

## Decision

Add an **opt-in, file-side host allowlist** for notes-sourced bindings: `notes_host_allowlist`, a
top-level `bindings.yaml` key. The file is AVP's trusted tier (only the operator edits it); the
allowlist lets that trusted tier bound where annotations may route.

**Invariant: annotations may only NARROW scope, never ADD a host.**

1. **Opt-in.** `notes_host_allowlist` defaults to `None` (key absent). When absent, behavior is
   byte-identical to today — the zero-config North Star is untouched. (Proven by a no-allowlist
   regression test.)
2. **Enforcement.** When set and `binding_source` is `notes`/`both`, each notes/annotation-supplied
   host is checked at activation (config-build time). A host not in the allowlist has its binding
   entry dropped fail-closed. A request that later carries that secret's placeholder toward the
   dropped host is denied and audited with the **distinct** reason `host_not_in_allowlist` — telling
   the operator "someone tried to route a secret somewhere un-approved" apart from
   `invalid_binding_metadata` (malformed note).
3. **Narrowing preserved.** Annotations may still narrow `methods`/`paths` within an allowed host —
   only the host set is bounded.
4. **Multi-host (ADR-0021).** Each host in a fan-out list is judged individually: a disallowed host
   drops only its own entry and the audit names that host; allowed siblings stay live. A spec left
   with no allowed host is dropped whole.
5. **Wildcards.** A `*.suffix` allowlist entry widens what notes may bind, so it rides the existing
   `allow_wildcard_hosts` opt-in (config-load rejects a wildcard entry otherwise). A wildcard note
   host matches only an identical wildcard entry — a note can never broaden an exact allowlist entry.
6. **File tier exempt.** A host the file `secrets:` already binds for the same secret is trusted by
   definition and never rejected — including `both`-mode unions.
7. **Uniform across sources.** The check is source-agnostic: structural on GSM (where the deputy
   exists), defense-in-depth on BWS.
8. **Doctor.** `avp doctor --probe-gcp` downgrades the `annotation-trust` WARN to OK when the
   allowlist is set — the control now exists structurally, not just as advice.

## Consequences

**Good**
- Closes the confused-deputy structurally in split-IAM GCP: an annotation-only writer cannot add an
  egress host. The attack requires editing the *file*, which is the trusted tier.
- Zero cost to the North Star: absent key = unchanged; the common single-operator case never sees it.
- One new audit reason, no new event type, no audit-contract bump.

**Bad / accepted**
- Operators in a split-IAM deployment must maintain the allowlist as they add destinations — the
  price of bounding an otherwise-unbounded annotation channel. `avp doctor` nudges toward it.
- Enforcement is at activation, so an allowlist change needs a config reload (same boundary as every
  other binding-policy change).

## Non-goal

This does **not** replace IAM hygiene. Restricting `secretmanager.secrets.update` to the value-read
trust tier remains the right GCP-side control; the allowlist is a defense-in-depth backstop for when
that separation is imperfect. It also does not bound what a principal who can edit the *file* can do
— the file is, and remains, fully trusted.
