---
status: accepted
date: 2026-07-18
relates_to: docs/architecture.md (§4.4 audit minimization, G6), ADR-0011 (audit contract v2), ADR-0017 (token_exchange / refresh_token_rotated events), ADR-0019 (honeytoken_triggered event)
---

# ADR-0023: Closed audit event-type set + `emit()` choke-point guard

## Context

AVP's audit stream is contractually secret-free: `docs/architecture.md` §4.4 ("Vault-style audit minimization") forbids header values, bodies, query strings, and any secret material in a record. The strongest existing enforcement is the stateful no-leak property tests (`test_addon*_noleak_stateful.py`), which drive the addon and scan the *whole* audit stream for secret bytes — proving no secret VALUE reaches disk for the paths they exercise.

That leaves one residual gap: the no-leak machines only cover the event types they know to drive. Audit event types have accreted over several ADRs — `inject_decision` / `deny` (ADR-0011 audit v2), `token_exchange` / `refresh_token_rotated` (ADR-0017), `honeytoken_triggered` (ADR-0019), plus operational `proxy_restart` and `upstream_response`. Nothing structural stops a *future* new event type — a new emit site — from shipping unclassified, written to the audit log before anyone has vetted its minimization or brought it under no-leak coverage.

ADR-0022 (cross-instance rotation) deliberately adds **no** new event types (§6) and is not the home for this guard. The type-closure contract is a general audit-hardening concern and earns its own record.

## Decision

1. **Closed set.** `audit.py` declares `AUDIT_EVENT_TYPES: frozenset[str]` — the complete, enumerated set of `"type"` values AVP may ever write.

2. **Choke-point guard.** `AuditWriter.emit()` refuses (raises `ValueError`, fail-closed) any event whose `type` is not in the set. It is the single structural rule that keeps the stream free of unclassified records; all current emit sites use a listed type, so it never fires on the hot paths.

3. **Freeze test.** `tests/test_audit_event_type_contract.py` asserts the `"type"` literals at the real emit sites equal `AUDIT_EVENT_TYPES` (a new type at an existing site fails here — the friendly early warning), and proves the `emit()` guard fires on an unlisted type (the runtime backstop for a new emit site in a new module).

4. **Declared per-type field allowlist.** The test pins the allowed top-level fields per event type as the documented contract and the basis for a future field-level runtime guard. Every listed field is metadata or a vault REFERENCE name, never a secret VALUE.

## Scope, stated honestly

This guard is **type-level, not field-level**. It does not by itself stop a value-bearing field being added to a *known* type — that is caught by the no-leak state machines (which scan for secret bytes regardless of field) plus the declared field allowlist. The three layers together are the "no secret in the audit" guarantee; this frozenset is the type-closure layer.

## Consequences

**Good**
- One structural choke-point makes "the audit stream contains only vetted record types" true by construction, not by convention.
- A new event type cannot ship without a conscious edit to `AUDIT_EVENT_TYPES` — exactly the point where PR review can demand no-secret-material plus no-leak coverage.
- Cheap and prod-safe: no hot-path behaviour change beyond a set-membership test.

**Bad / accepted**
- Type-level only; field-level enforcement is deferred (below).
- The freeze test must be kept in sync with the emit sites — which is the point, not a cost.

## Deferred (future ADR)

- Typed event builders, or a per-type field allowlist enforced at `emit()` rather than only pinned in the test. Deferred because it needs the full optional-field enumeration and a careful pass over the G6 fsync ordering path.
