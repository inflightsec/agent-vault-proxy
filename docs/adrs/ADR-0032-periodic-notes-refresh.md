---
status: accepted
date: 2026-07-23
relates_to: docs/ROADMAP.md (Config hot-reload), ADR-0011 (notes bindings / activation), ADR-0018 (GSM backend), ADR-0023 (closed audit event-type set), ADR-0025 (notes-binding marker), ADR-0029 (stored placeholders), docs/architecture.md §4.4 (configure() = binding-policy refresh boundary)
references:
  - RFC (n/a) — internal reload semantics
---

# ADR-0032: Periodic notes refresh for vault backends

> **Status: ACCEPTED (2026-07-23).** Closes the friction that a *new* secret added to a live vault
> (BWS notes / GSM annotations) was only brokered after a daemon **restart**.

## Context

The binding *policy* — which host gets which secret — is resolved from BWS secret notes / GSM
annotations at `configure()` time only (`NotesActivator.activate()` inside
`configure_from_path`). There is no background re-fetch, so adding a **new** secret + `# avp-binding`
note to a live vault does nothing until the daemon reloads/restarts — **even for BWS and GSM, where
the vault is the live source of truth.** (Changing an *existing* secret's *value* is already picked
up within `cache.ttl_seconds`; only a *new binding* needs the reload.) For a static file backend a
restart is defensible — the file is local and inert. For a vault backend it is not: the "drop a
secret in the vault, done — no config edit, no redeploy" promise is broken by the restart step.

The note→binding resolution runs fail-closed validation (placeholder uniqueness, host allowlist,
collision checks — ADR-0011/0025/0029). That validation rightly stays **off the request hot path**,
so per-request re-resolution is wrong. But that argues for running it on a **timer**, not only at
boot.

## Decision (accepted)

Add a **background notes-refresh loop** for listable vault backends in notes/`both` mode. Every
`notes_refresh_seconds` it re-runs the same `activate()` resolution against the **existing backend**,
and atomic-swaps the binding snapshot — no restart, no dropped connections.

1. **New config knob `notes_refresh_seconds`** (top-level, default **60**, `0` = disabled, capped
   `[0, 86400]`). Only meaningful when `binding_source != "file"`; ignored in file mode (nothing to
   refresh).
2. **Notes-only refresh, warm caches preserved.** The refresh swaps `config` + the six attribution
   maps (+ the audit honeytoken set). It **keeps** the existing `CachingSecretsClient` (warm value
   cache), `AuditWriter`, and — critically — the `DerivedTokenCache`. A full reconfigure would drop
   the OAuth token cache and force a token re-exchange every interval; the refresh must not.
3. **Fresh listing.** `backend.flush_name_map()` invalidates the backend's cached listing so the
   re-list picks up newly-added secrets; the file is re-read too (a free bonus: file-binding edits
   land on the same timer). Backend *config* changes still need a restart (the backend instance is
   reused) — documented.
4. **Off the event loop.** Vault listing is blocking; the loop runs each refresh via
   `asyncio.to_thread` so it never stalls request handling. Started in `running()`, cancelled in
   `done()`. Atomic `STORE_ATTR` publish (maps before config, same ordering as `configure`) so an
   in-flight request captured at handler entry never tears.
5. **Fail-safe.** Any refresh error (vault unreachable, transiently invalid notes) **keeps the old
   snapshot** and logs — never crashes, never serves a torn or empty binding set. Same posture as
   "bad config on hot-reload: keep old config" (architecture.md).
6. **Audited on change only.** When the resolved binding set actually changes (secret added/removed),
   emit `notes_refreshed` (count + added/removed names, never values) — added to the ADR-0023 closed
   set. A no-op refresh emits nothing (no audit noise).

## Rejected / alternatives

- **Full `configure_from_path()` on the timer.** Rejected — rebuilds the client + token cache,
  dropping warm secret values and forcing OAuth re-exchange every interval.
- **Per-request note re-resolution.** Rejected — puts vault listing + fail-closed validation on the
  hot path.
- **File-mtime / inotify watch as the trigger.** Orthogonal (still on the roadmap for the file part);
  this ADR targets the *vault* source. The refresh happens to re-read the file too, which covers the
  common file-edit case as a side effect.
- **Default `0` (opt-in).** Rejected as the default — it would leave the restart friction in place
  unless the operator knew to enable it. Default `60` makes the "add a secret, done" promise true out
  of the box; the cost is one cheap list call per minute per vault backend, tunable or disable-able.

## Consequences

**Good** — a new vault secret is brokered within `notes_refresh_seconds` with zero restart and zero
dropped connections; quickstart's last step becomes "add the secret, done".

**Trade-offs** — one background list call per interval per vault backend (default 60s; negligible for
BWS/GSM, tunable). A newly-added secret has up to `notes_refresh_seconds` latency before it's live
(bounded, documented). Backend *config* changes (not bindings) still need a restart. Two concurrent
`activate()` runs (a manual reload racing the timer) are possible but safe — the backend listing is
cache-guarded and the publish is atomic.

## Test strategy

- New binding appears after `refresh_notes()` (fake backend gains a note → refresh → the host is now
  brokered) without rebuilding client/token cache (assert same instances).
- Fail-safe: backend raises on re-list → old snapshot retained, no crash.
- Gating: `binding_source: file` or `notes_refresh_seconds: 0` → loop is a no-op / not started.
- `notes_refreshed` audited on change, silent on no-op; added to the event-type contract test.
- Off-loop: refresh runs via `to_thread` (no blocking of the event loop) — smoke via the loop test.
