# ADR-0029 — Stored placeholders: the note pins what the consumer emits

- **Status:** Accepted
- **Date:** 2026-07-20
- **Relates to:** ADR-0011 (notes bindings, salt-derived placeholders), ADR-0018 (annotation trust), ADR-0025 (binding marker)

## Context

In notes/`both` mode the placeholder for each secret is derived on the daemon
host from a per-install salt (`avp-PLACEHOLDER-` + HMAC tail, ADR-0011). The
derivation is sound, but it created a wiring gap that bit in practice:

- A freshly bound secret cannot be consumed until someone with access to the
  daemon host runs `avp env` and copies the derived placeholder into the
  consumer's environment. Operators repeatedly bound a secret in the vault and
  then watched injection "not work" — the consumer was emitting nothing the
  daemon recognised.
- Salt rotation and secret renames silently change every derived placeholder,
  breaking all wired consumers at once.
- Operator-side derivation parity was an open design hole: the salt is 0600
  daemon-owned, so an operator (or the skill guiding one) cannot derive
  placeholders off-box.

The placeholder is a **sentinel, not a secret** — the consumer holds it, the
daemon holds it, it appears on the loopback wire. The only properties it needs
are unforgeability-in-practice (no collisions with other placeholders or with
innocent traffic) and stability.

## Decision

A binding note/annotation MAY carry an explicit `placeholder:` key. When
present and valid, it **wins over salt derivation** for that secret.

Three guardrails make it safe:

1. **Generated, never hand-chosen.** `avp binding new` mints the placeholder
   (`secrets` CSPRNG, 26-char lowercase-base32 tail = 130 bits) and embeds it
   in the note it prints. Hand-authoring remains structurally possible but the
   format gate below rejects anything low-entropy-shaped.
2. **Strict format gate at parse.** A stored placeholder must match
   `^avp-PLACEHOLDER-[a-z2-7]{21,64}$` (same alphabet and prefix as derived
   ones, ≥105-bit tail). A weak string ("token", "Bearer") cannot parse, so a
   note can never aim injection at strings that occur in innocent traffic.
   Violations are `invalid_binding_metadata` — fail closed, loud.
3. **Global uniqueness at resolve, fail closed, thief-loses.** After source
   merge, any placeholder claimed by more than one spec — **equal or
   substring-overlapping** (the addon matches via `in`, and the merge
   validator refuses overlaps by raising, so an unhandled overlap would be a
   whole-config DoS) — is contested. A claim is *legitimate* when it is the
   claimant's own derived placeholder or comes from the file source
   (root-owned config). If exactly one claimant is legitimate, only the
   others (the stored "thieves") are dropped — a note-writer cannot
   un-broker a derived- or file-placeholder secret by stealing its
   placeholder. With no single legitimate claimant, all claimants drop. A
   stored placeholder equal to an unbound secret's derived placeholder also
   drops. Every dropped claim is recorded with a diagnostic naming both
   secrets and stays attributable in the request path (audited, never
   injectable).

Consequences for the surfaces:

- `avp binding new` mints by default and prints a consumer-wiring hint on
  stderr (`export NAME='<placeholder>'`); `--no-placeholder` restores the
  legacy salt-derived flow.
- `avp env` reads notes and projects the stored placeholder where one is
  pinned, derived otherwise — the projection always matches what the daemon
  enforces. Backends that cannot serve notes degrade to derived-only with a
  warning.
- The derived placeholder for a stored-placeholder secret remains in the
  attribution map: a stale consumer still fails closed with a named secret in
  the audit log rather than an anonymous passthrough.

## Why this does not widen the ADR-0018 trust boundary

Whoever can write a secret's note can already redirect that credential to an
attacker-controlled host — annotation-write is the trust boundary, and it must
be gated to the value-read tier regardless. A `placeholder:` key adds no
meaningful power on top: collisions are neutralised fail-closed (with the
legitimate owner surviving), and the format gate prevents traffic-matching
strings. Meanwhile the file source has always trusted operator-chosen
placeholders; this brings notes to parity under stricter rules than the file
source itself applies.

## Consequences

- The one-sitting onboarding flow becomes real: generate note → paste into
  vault → wire the printed placeholder into the consumer → reload daemon.
  No daemon-host access needed for discovery.
- Stored placeholders survive salt rotation and secret renames.
- Notes without `placeholder:` keep working unchanged (salt derivation is the
  fallback, not deprecated).
- An older daemon that does not know the key fails a new-style note loud
  (`unknown note key`) — fail-closed on version skew; upgrade the daemon
  before adopting stored-placeholder notes.
- Notes are still read at configure(): adding or changing a binding requires
  a daemon reload (unchanged; TTL refresh remains a separate follow-up).
- **Residual, documented DoS between two stored claimants:** there is no
  ownership signal to arbitrate two notes storing the same (or overlapping)
  placeholder, so both drop — an actor with note-write in the same vault
  scope can take a *stored-placeholder* secret offline (never mis-inject
  it). Derived- and file-placeholder secrets are immune (the thief drops
  alone). Accepted because note-write is already gated to the value-read
  tier (ADR-0018); mitigation candidate if it ever bites: a stable
  ownership marker (e.g. first-seen pinning) to arbitrate.
- `avp env` now reads notes; on backends whose listing is value-coupled
  (BWS) the CLI touches secret values at projection time — the same surface
  the daemon's configure() already uses. Run it on the daemon host, as ever.
- Projection is format-checked, not activation-checked: `avp env` does not
  re-run the resolve-time drops, so a secret the daemon dropped can still
  appear in the projected env (as was already true for invalid/unbound
  secrets). `avp doctor` remains the enforcement view.
- The tail-length floor prevents low-entropy strings, not overlap; overlap
  is neutralised by the resolve-time pass above.
