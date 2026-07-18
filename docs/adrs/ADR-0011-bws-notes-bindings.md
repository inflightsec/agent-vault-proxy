---
status: accepted
date: 2026-06-02
amended: 2026-06-12
relates_to: docs/architecture.md (§4 binding lifecycle, §4.4 audit log), ADR-0012 (narrow-trust CA)
---

# ADR-0011: Bindings as structured metadata in BWS secret notes (with file-based bindings retained as escape hatch)

> **Amended 2026-06-12 (accepted).** The original `## Decision` schema below required `inject_header` + `inject_format` in every note. The 2026-06-12 simple-mode design review simplified this: the **only required field is `host:`**, with `Authorization: Bearer {secret}` as the default and a bundled exception table for the non-Bearer minority. The `## Amendment` section is now authoritative for the schema; the original `## Decision` is retained for history (the two-source/precedence/fail-closed parts of it still stand verbatim).

## Context

The `agent-vault-proxy` daemon originally read its binding policy from a local `bindings.yaml` file. Each binding entry maps a placeholder string to one or more destination hosts, an `inject_header`, an `inject_format`, and optional `methods`/`paths` scope.

This file-based model has several frictions that compound as the user base grows:

1. **Two sources of truth.** Secrets live in BWS; bindings live in a file. Adding a new service requires editing both. Drift between them is silent.
2. **Distribution problem.** Shipping pre-baked "common service" bindings inside the daemon doesn't scale — the universe of services is effectively unbounded, and every user has internal SaaS we can't anticipate.
3. **Update channel problem.** Pushing a binding-only change (e.g., "a provider added a new endpoint") to every installed daemon requires either rebundling the daemon (slow) or a separate signed update channel (signing infrastructure that doesn't yet exist).
4. **Homebrew distribution.** The forthcoming `agent-vault-proxy` Homebrew formula needs SOMETHING for binding state. Bundling `bindings.yaml` defaults, shipping an update channel, or asking a non-technical user to hand-author binding policy are all bad options for that audience.

The proposal: store binding policy AS structured metadata attached to the secret itself in Bitwarden Secrets Manager, fetched inline with the secret value. BWS becomes the single source of truth for both the credential and the policy that controls its use.

BWS data model: each secret exposes only **Name**, **Value**, **Notes**, and **Project**. There are no first-class custom fields. The Notes field is free-form text and is the carrier for the binding metadata blob.

## Decision

The AVP daemon supports two binding sources, with explicit precedence:

1. **BWS-notes binding (default, primary):** A YAML blob in the BWS secret's `notes` field. Schema:
   ```yaml
   binding:
     inject_header: Authorization          # required
     inject_format: "Bearer {secret}"      # required; `{secret}` is the substitution token
     scope:                                # required, at least one entry
       - host: api.example.com             # required per entry
         methods: [GET, POST]              # optional, list
         paths: ["/v1/*"]                  # optional, list of glob patterns
   ```
   Daemon fetches the secret AND parses its notes inline. If notes is empty, malformed, or missing required fields, **the daemon FAILS CLOSED** for that secret — the placeholder forwards unmodified to the upstream, the audit log records `reject_reason: invalid_binding_metadata` with a precise diagnostic.

2. **File-based binding (escape hatch, retained):** The existing `bindings.yaml` file continues to work. Use cases: Ansible-driven fleet deployment where pre-generated YAML is preferred; air-gapped environments where BWS is unreachable; teams that prefer GitOps for binding policy.

**Precedence:** if a placeholder appears in BOTH sources (a BWS secret with binding metadata AND a `bindings.yaml` entry for the same placeholder), the **BWS-notes binding wins**. Rationale: BWS is closer to the secret, less likely to be stale, and the explicit fail-closed behavior of malformed notes makes precedence safer than the older file-pinned model.

**Both sources MUST yield identical structural validation.** Same required fields, same scope semantics, same fail-closed behavior. The two paths differ only in storage location, not in semantics.

**Diagnostic UX is part of this ADR.** When a binding fails (malformed metadata, missing required fields, no scope match), the daemon emits a structured audit event with a precise reason AND surfaces it via `avp doctor --secret <name>` for human investigation. Example output:

```
$ avp doctor --secret OPENAI_API_KEY
Fetching from BWS...                           [OK]
Parsing binding metadata from notes...         [FAIL]

REASON: Required field "inject_header" is missing.

Current notes content:
  binding:
    inject_format: "Bearer {secret}"
    scope:
      - host: api.openai.com

Expected:
  binding:
    inject_header: Authorization      <-- MISSING
    inject_format: "Bearer {secret}"
    scope:
      - host: api.openai.com

Fix: edit the secret in Bitwarden Secrets Manager and add `inject_header` to the notes field.
For an OpenAI-shaped template: avp template openai
```

This level of diagnostic specificity is a HARD requirement, not optional. A non-technical user must be able to read the error and act on it without consulting documentation.

## Amendment (2026-06-12) — authoritative schema after the simple-mode design review

The two-source model, BWS-notes precedence, fail-closed-on-malformed, and the diagnostic UX above all stand. **Only the notes schema changes**, to make the common case need almost nothing while keeping the rich per-integration scope the original ADR had (the GitHub gist-exfil case below is exactly why the rich scope is retained).

### Notes schema (reconciled)

```yaml
# Minimum — the Tier-1 case. ONE required field.
host: api.example.com
```

```yaml
# Full — Tier-2 overrides. Everything except `host` is optional and defaulted.
host: api.example.com
header: X-Api-Key            # default: Authorization
format: "Token {secret}"     # default: "Bearer {secret}"   ({secret} = substitution token)
methods: [GET, POST]         # default: any
paths: ["/v1/**"]            # default: any
```

Changes from the original `## Decision` schema:
- **Dropped the `binding:` wrapper key** and the `scope:` nesting — fields are flat and top-level. A note is now human-pasteable in seconds.
- **`inject_header` → `header`, `inject_format` → `format`** (both now optional, defaulted to Bearer/Authorization).
- **Only `host` is required.** Empty notes no longer fail closed *as malformed*; a secret with no `host` simply has no binding (no injection anywhere) — still fail-closed by omission, but distinguished in audit from a *malformed* note.
- The substitution token stays `{secret}` (matches the daemon's existing `_render_substitution`; note this differs from the product `bindings.yaml` which uses `{SECRET_NAME}` — the BWS-notes path uses the generic `{secret}` alias since the note has no separate name key).

### Bundled exception table (replaces the dropped Tier-0 prefix catalog)

A small **host-keyed** table ships in the daemon. When the user-typed `host` matches a row, that row supplies the non-default `header`/`format`/companion-headers/**default scope**; otherwise the Bearer default applies. ~6-10 rows. Keyed on the **host the human typed**, never inferred from key bytes. Initial rows:

| host | header / format | default scope (shipped tight) |
|---|---|---|
| api.anthropic.com | `x-api-key: {secret}` + `anthropic-version: 2023-06-01` | `POST /v1/**` |
| api.openai.com | `Authorization: Bearer {secret}` | `POST /v1/**` |
| **api.github.com** | `Authorization: Bearer {secret}` | **GET `/repos/**`,`/user`,`/orgs/**`,`/search/**` only — NO `POST /gists`, no write paths** |
| api.stripe.com | `Authorization: Bearer {secret}` (Basic fallback documented) | `POST /v1/**` |
| api.notion.com | `Authorization: Bearer {secret}` + `Notion-Version: 2022-06-28` | `POST,PATCH /v1/**` |
| api.linear.app | `Authorization: {secret}` (raw, no Bearer) | `POST /graphql` |

The **GitHub row is the worked example of why rich scope survived the simplification**: a PAT bound to `api.github.com` with no path scope can `POST /gists` and exfiltrate data into a public gist. The shipped default scope is GET-read-only, so the simple "paste key + host" case is already gist-safe with zero user effort; a user who needs writes opts in explicitly via the `methods:`/`paths:` overrides above.

### Placeholder origin (speced here because the backend depends on it)

The original ADR assumed hand-authored placeholders. Simple mode derives them:
- **Deterministic, salted:** `avp-PLACEHOLDER-<base32(HMAC(install_salt, secret_name))[:n]>`, length ≥24, contains `PLACEHOLDER`, satisfying the `config.py` placeholder invariants (unique, no substring overlap). The per-install `install_salt` (random, generated at `avp setup`, stored `0600` under the `avp` user) means placeholders are **not globally precomputable**.
- **`avp env`:** lists the BWS project's secrets, validates each **name** against `^[A-Za-z_][A-Za-z0-9_]*$` (reject, don't sanitize), and writes a validated env file (`~/.config/avp/env`: `NAME=<placeholder>` per secret). Profile does `set -a; . ~/.config/avp/env; set +a` — **never `eval $(...)`**. Refreshed on demand / on a TTL.
- The daemon builds the same placeholder↔name↔notes map from the BWS secret list, so both sides agree without configuration. Collision on the truncated placeholder is a **hard startup failure** listing the conflicting names.

### Audit-schema bump

Adding `binding_source: bws_notes | file` to the `inject_decision` event is a **contract-version bump** (the audit event schema is versioned; this ADR bumps the version). Implementation must: bump the audit JSON contract version, update `docs/architecture.md §4.4`, and add a new audit reason `no_binding_in_notes` (distinct from `invalid_binding_metadata`).

## Consequences

**Positive:**

- Single source of truth for credential + binding. Adding a new service is one BWS-side action: create secret with binding metadata in notes. No second file to edit.
- The "thousands of services" / "internal services" distribution problem disappears. Each user's BWS holds only the bindings they need.
- Homebrew distribution simplifies dramatically: `avp setup` only needs the BWS machine token; no `bindings.yaml` management.
- Fail-closed at the daemon (rather than at a file-author's discretion) makes the security guarantee structural.
- The 5-minute BWS cache TTL becomes the natural refresh interval for binding changes — no daemon restart needed.
- File-based path retained for Ansible / fleet / air-gapped scenarios. Not abandoned, just deprioritized.

**Negative:**

- Daemon code change: substitution path now parses notes structure for every fetched secret. Test surface expands. Audit event schema gains a `binding_source: bws_notes | file` field (which means an audit-schema version bump, per the versioning constraint).
- Blast radius shifts marginally: compromise of the AVP machine token now leaks binding policy structure in addition to credential bytes. Already keys-to-the-kingdom, so the marginal increase is small.
- Operational visibility shifts: "what bindings does this daemon enforce" is no longer `cat bindings.yaml` but `avp bindings list` (which queries BWS and renders). Tooling must be high quality to compensate.
- Migration tool needed: `avp bindings migrate-to-bws` reads existing `bindings.yaml`, for each entry calls BWS API to attach binding metadata to the corresponding secret's notes. One-time migration. Existing installs run it when they're ready.
- Multi-secret-backend future is more work. If a second backend is ever added, each backend needs its own notes-equivalent convention. v0.1 is BWS-only; deferred problem.

**Neutral:**

- Audit-schema version bump required. Plan as part of this ADR's implementation.
- Documentation updates: `docs/architecture.md` §4 (binding lifecycle), `bindings.example.yaml` gets a parallel "BWS notes example" sibling, README updates.
- The Homebrew distribution path designs around this from v0.1 — never ships `bindings.yaml` to Homebrew users.

## Migration plan

1. **Daemon refactor (this ADR's implementation):**
   - Add `BindingsResolver` abstraction with two backends: `BwsNotesBackend`, `FileBackend`.
   - Resolver prefers BWS-notes over file when both are present for a placeholder.
   - Audit event schema bumps version, adds `binding_source` field.
   - Tests cover both backends, precedence, malformed-notes fail-closed, and the diagnostic surface.

2. **`avp bindings migrate-to-bws` CLI verb:**
   - Reads existing `bindings.yaml`, for each entry calls BWS API to write the YAML-encoded binding to the matching secret's notes.
   - Idempotent: re-running detects unchanged notes and no-ops.
   - Dry-run mode shows what would change.

3. **Ansible role update:**
   - Default install creates `bindings.yaml` as empty. Bindings come from BWS-notes.
   - Existing installs with populated `bindings.yaml` keep working; migration is opt-in via `avp bindings migrate-to-bws`.
   - Ansible role can optionally template a `bindings.yaml` for users who prefer GitOps; both modes documented.

4. **Homebrew formula (forthcoming):**
   - Ships from v0.1 with NO `bindings.yaml` machinery. Pure BWS-notes path.
   - `avp setup` collects only the BWS machine token, configures the service, configures the proxy env.
   - File-based escape hatch is documented but not the default path on Homebrew.

5. **Deprecation timeline:**
   - 6 months: both backends actively supported, BWS-notes is the default in docs.
   - 12 months: file-based path is marked deprecated in `avp doctor` output (warning if `bindings.yaml` has entries).
   - 18-24 months: major daemon version bump removes file backend. Until then, file path is reliably available for the Ansible/fleet use case.

## Cross-references

- `docs/architecture.md` §4 — binding lifecycle (updated as part of implementation); §4.4 — audit log (schema version bumped here).
- The audit event schema is versioned; this ADR bumps the version.
- A planned semantic-diff CLI becomes load-bearing for both backends; the same renderer renders BWS-notes diffs and file diffs.
- The Homebrew distribution design closes out the "bindings update channel" question by referencing this ADR's outcome.
- ADR-0012 (narrow-trust CA) — shares the per-install `install_salt` generated at `avp setup`.
