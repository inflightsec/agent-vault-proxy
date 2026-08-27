# ADR-0047 — Explicit binding scope at authoring time

**Status:** Accepted
**Date:** 2026-08-24
**Revised:** 2026-08-25 — the per-binding rate ceiling proposed and built here was **removed before release**. See "Rejected: rate ceilings".
**Supersedes:** none
**Related:** ADR-0013 (declarative policy fixtures, the `decide()` core), ADR-0023 (closed set of audit event types)

## Context

kow's guarantee is precise: the agent never holds the key. External feedback from a solo macOS operator running live commerce credentials (Amazon Seller Central, Printful, Google Ads) named the gap on the other side of that guarantee, and named it correctly:

> Today this stops a key being read out of my agent's context. It doesn't stop the agent being talked into using it. If a scraped page injects "cancel all the Printful orders", that call goes through the proxy and gets a real key attached on the way out.

He pre-empted the two obvious rebuttals, so neither is available to us. Host and method rules are not authorisation, because the semantics live in the payload. And an agent holding a shell can drop `HTTPS_PROXY` and go direct, so nothing enforced at the proxy binds a determined agent.

What already exists: `methods:` and `paths:` per binding, enforced in `config.py` and reaching `decide()` in `policy.py`, plus per-service defaults in `notes_binding.py` applied when the skill writes a binding. The primitive for verb scoping exists and is enforced. The gap is that it is optional, and a binding that omits `methods:` allows every verb.

## Decision

**Strictness at authoring time, not a default flip in the engine.** The first draft proposed flipping the omitted-`methods:` default to deny mutating verbs. Rejected: it spends a major version and risks silently breaking every hand-written binding, to buy accident coverage that a determined agent bypasses anyway.

Bindings are authored by the bundled kow skill, so that is where the strong default belongs. The skill now **always writes `methods:` explicitly**, proposing the narrowest set that works: read-only `GET` unless the credential's purpose needs more, and `DELETE` never implied, always named out loud. New bindings are scoped by construction, and no existing config changes behaviour.

Engine semantics are unchanged: omitting `methods:` still allows any verb. A binding that does so and takes a mutating verb emits a **`binding_methods_unscoped`** advisory, **once per (secret, host, verb) per process**. This is a permanent config-smell signal, not a deprecation countdown, and it is deduped because emitting it per request would bury the injection records an operator actually reads.

**Advisories get their own audit event type.** `policy_advisory`, not `inject_decision`. Consumers count allowed `inject_decision` records as successful injections, and an advisory is not one, so folding it into that type would silently inflate every operator's injection count. Registering the type went through the ADR-0023 closed set, which forced a declared field allowlist and a representative record. Advisory writes are best-effort: an advisory carries no verdict, so an unwritable audit must never convert an otherwise-allowed request into a failure. Terminal verdicts keep the strict G6 path in `_fail_closed`.

Audit contract version moves 3 to 4 for the new event type (AGENTS.md hard constraint #3).

## Rejected: rate ceilings

An optional per-binding rate ceiling (`rate:` with `max_requests`, `per_seconds`, `on_exceed`) was proposed here, implemented, reviewed across three adversarial passes, and then **removed in full**. The reasoning is worth keeping, because the idea will come back.

The operator asked for it directly, alongside the verb deny, and it does bound one real failure mode: "cancel *all* the orders" is a loop, and a ceiling turns hundreds of destructive calls into a handful plus a loud audit trail.

It was removed anyway, because it is not what kow is for:

- **Wrong tool.** kow is a credential proxy. Its one job is that the agent never holds the key. A per-destination request-rate policy is an API gateway feature, and putting one here starts a slide toward payload inspection and per-service rule sets that the "Not doing" section below already refuses.
- **Narrow benefit.** It bounds volume, never accuracy. A precise injection ("cancel order 4471") is a single call and passes every ceiling.
- **Real cost.** It put mutable, clock-dependent state into a request path that had been stateless, which review immediately turned into findings: shared counters across path scopes, ordering-dependent keys, unbounded key growth, and a hole where body-injected credentials were never covered at all.
- **Opt-in anyway.** Absent unless configured, so it protected nobody who had not already thought about the problem.

The verb-scoping half of the same feedback survives, and it is the half that carries the weight.

## Consequences

**Good.** New bindings come out scoped, so the most common accident (a broad token taking a destructive verb nobody intended) is narrowed at the moment of authoring, where the operator is already paying attention. No existing binding changes behaviour. The advisory gives operators a way to find unscoped bindings without noise. The request path stays stateless.

**Bad.** Strictness now depends on bindings being authored through the skill; a hand-written binding stays as permissive as it always was and gets only an advisory line. Coverage arrives as bindings are re-authored, not on upgrade. A new audit event type ships, which operators parsing the stream should know about.

## Not doing

Payload inspection to determine intent. That is where the real semantics live, and it is also where this stops being a credential proxy and becomes an API firewall with a per-service rule set for every destination anyone routes. Out of scope, deliberately. Rate ceilings were removed for the same reason.
