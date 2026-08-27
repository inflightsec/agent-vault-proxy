# Workflow: AddSecret

Guide the user to broker ONE new credential through kow via the notes/annotation source. Output the exact artifact to paste; the user applies it. **Never write the value or annotation to the vault yourself.**

## 1. Interview (ask only what's unknown; recommend a default each time)

1. **Backend** — Bitwarden Secrets Manager (`notes`), Google Secret Manager (`kow-binding` annotation), or the static file fallback? Default: whatever `binding_source` the install already uses (usually BWS notes).
2. **Auth shape** — Bearer token / `token` scheme / `X-API-Key` (custom header) / Basic / composite (multi-part). If unsure, ask how the service's docs say to authenticate a `curl`.
3. **Host(s)** — the exact hostname(s) the credential is sent to. Get them from the API docs or a real request. Flag immediately if there's more than one (see §4).
4. **Scope — always write `methods:` explicitly.** Never leave it out and rely on the engine's permissive default (ADR-0047). Propose the narrowest set that still works, state it, and let the user widen:

   | What the credential is for | Propose |
   |---|---|
   | Reading data (search, list, fetch, status) | `GET` (add `HEAD`, `OPTIONS` only if the client needs them) |
   | Creating or sending (messages, events, jobs) | `GET, POST` |
   | Full CRUD against a resource API | `GET, POST, PUT, PATCH` |
   | Anything that can delete | name `DELETE` explicitly and say so out loud |
   | Genuinely admin-broad token | all verbs, but say why in one line before writing it |

   A binding that omits `methods:` still works and gets a one-time `binding_methods_unscoped` advisory in the audit log. Treat that advisory as a bug in the binding, not as noise. `paths:` on top of this is encouraged wherever the API has a stable prefix.

## 2. Choose the source

- **Single host + single secret** → notes/annotation (the default, no config, no redeploy).
- **Multiple hosts, or composite (multi-secret) auth** → the kow **config file source** instead — a note can't express either (see SKILL Gotchas). Say so plainly and emit the file-source `bindings:` block instead, and note it needs a config reload/redeploy.

## 3. Emit the exact artifact

Pick a secret **name** in `SCREAMING_SNAKE_CASE` (e.g. `ACME_API_KEY`).

### Generate it with the tool — do NOT hand-write the note (preferred)

**Run `kow binding new` and hand the user its output verbatim.** The tool builds the note and **validates it through the daemon's own parser before printing** — so the marker is always present, the token is always the generic `{secret}`, and an invalid host is refused (exit non-zero) instead of silently producing a dead binding. Hand-authoring the YAML is exactly what caused two prior outages; let the code do it.

```bash
# BWS (default) — prints the note block to paste into the secret's Notes field:
kow binding new --host api.acme.com --name ACME_API_KEY
#   stdout → the note (now includes a minted `placeholder:` line, ADR-0029)
#   stderr → the consumer wiring line `export ACME_API_KEY='avp-PLACEHOLDER-…'` — CAPTURE IT for §5
#   --header / --format for non-Bearer auth (see NoteSchema)
#   --methods GET,POST  --paths /v1/**   to scope
#   --host A --host B    for multi-host
#   --backend gsm --name ACME_API_KEY    prints the gcloud annotation command instead
#   --no-placeholder     legacy salt-derived flow (omits the placeholder: line)
```

If the tool exits non-zero, it printed a diagnostic on stderr — relay it; do NOT paste a partial/edited note. (Source install without `avp` on PATH: `/opt/kow/.venv/bin/kow`.)

Manual-fallback notes must OMIT `placeholder:` — only the tool mints one (the daemon's format gate rejects hand-typed strings); a note without it uses the legacy derived flow.

The rest of this section documents the artifact shape the tool emits (for review / manual fallback only):

- **Marker is mandatory (ADR-0025):** every note/annotation MUST begin with the exact first non-blank line `# kow-binding`. Without it the metadata is treated as a human description and never binds (uniform across BWS notes and the GSM annotation value). The tool guarantees this.

### Bitwarden Secrets Manager
> 1. Create a secret named **`ACME_API_KEY`**; set its **value** to your real token (you paste it — I never see it).
> 2. Paste this into that secret's **Notes** field:
> ```yaml
> # kow-binding
> host: api.acme.com
> header: Authorization
> format: "Bearer {secret}"
> ```
> (The `# kow-binding` first line is mandatory — without it the note is a description, not a binding. Add `methods:` / `paths:` lines if you scoped it — see NoteSchema.)

### Google Secret Manager
> ```bash
> printf 'YOUR_TOKEN' | gcloud secrets create ACME_API_KEY --data-file=-
> gcloud secrets update ACME_API_KEY --update-annotations="kow-binding=$(printf '# kow-binding\nhost: api.acme.com\nheader: Authorization\nformat: \"Bearer {secret}\"')"
> ```
> (Run these yourself; the token stays in your shell, never in this chat.)

### Static file fallback (only if no vault)
> `sudo kow secret add ACME_API_KEY` (prompts, no echo), then the binding lives in the config — this is the one path that does touch config.

## 4. Multi-host warning (do not skip)

If the credential needs >1 host (common for download/CDN-backed APIs), a single note can't do it. Recommend the **file source** with a host list, OR one secret per host (same value duplicated). Never silently emit a note that only covers one of several required hosts — the others will fail (401 / unauthenticated).

## 5. Wire the consumer (BLOCKING — SKILL.md hard rule 3; do not end the session without it)

Skipping this step is the #1 cause of "kow doesn't inject": the binding is only half the job — the consuming app must EMIT the placeholder for kow to swap. The placeholder is minted ONCE on the `kow binding new` output; persist it now. It is a non-secret sentinel, so writing it needs no special permission — the assistant should do it.

1. Capture the placeholder from `kow binding new`'s stderr (`export <NAME>='avp-PLACEHOLDER-…'`).
2. Write that line into the consuming app's `.env` / config yourself, or hand the user the exact line to add.
3. Tell the user to **reload the kow daemon** — notes are read at configure() only; the new binding is inert until a restart.
4. Legacy note without `placeholder:`? Discover the derived value on the kow host: `sudo kow env --print | grep <NAME>`.

## 6. Verify (user runs)

- `kow doctor` — flags no-annotation/invalid-annotation secrets and the annotation-trust advisory.
- Confirm the consumer emits the exact placeholder from §5 — `kow env --print` shows what the daemon enforces (stored placeholder preferred, derived fallback).
- Reminder: a secret with **no** annotation is never injected (fail-closed) — and an **unmarked** note is a description, not a binding, so it won't inject either. If it "doesn't work," check the note parsed, that its first non-blank line is exactly `# kow-binding`, that the consumer was wired (§5), and that the daemon was reloaded.

## 7. Record nothing sensitive

Do not echo the token, do not store it, do not commit it. The deliverable is the *instructions*, not the secret.
