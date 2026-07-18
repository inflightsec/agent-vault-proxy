# Workflow: AddSecret

Guide the user to broker ONE new credential through AVP via the notes/annotation source. Output the exact artifact to paste; the user applies it. **Never write the value or annotation to the vault yourself.**

## 1. Interview (ask only what's unknown; recommend a default each time)

1. **Backend** — Bitwarden Secrets Manager (`notes`), Google Secret Manager (`avp-binding` annotation), or the static file fallback? Default: whatever `binding_source` the install already uses (usually BWS notes).
2. **Auth shape** — Bearer token / `token` scheme / `X-API-Key` (custom header) / Basic / composite (multi-part). If unsure, ask how the service's docs say to authenticate a `curl`.
3. **Host(s)** — the exact hostname(s) the credential is sent to. Get them from the API docs or a real request. Flag immediately if there's more than one (see §4).
4. **Scope (optional, encouraged)** — HTTP `methods` and URL `paths` to bind. Narrower = smaller blast radius. Default: no scope (all methods/paths) only for admin-broad tokens.

## 2. Choose the source

- **Single host + single secret** → notes/annotation (the default, no config, no redeploy).
- **Multiple hosts, or composite (multi-secret) auth** → the AVP **config file source** instead — a note can't express either (see SKILL Gotchas). Say so plainly and emit the file-source `bindings:` block instead, and note it needs a config reload/redeploy.

## 3. Emit the exact artifact

Pick a secret **name** in `SCREAMING_SNAKE_CASE` (e.g. `ACME_API_KEY`). Then produce, for the chosen backend:

### Bitwarden Secrets Manager
> 1. Create a secret named **`ACME_API_KEY`**; set its **value** to your real token (you paste it — I never see it).
> 2. Paste this into that secret's **Notes** field:
> ```yaml
> host: api.acme.com
> header: Authorization
> format: "Bearer {secret}"
> ```
> (Add `methods:` / `paths:` lines if you scoped it — see NoteSchema.)

### Google Secret Manager
> ```bash
> printf 'YOUR_TOKEN' | gcloud secrets create ACME_API_KEY --data-file=-
> gcloud secrets update ACME_API_KEY --update-annotations="avp-binding=$(printf 'host: api.acme.com\nheader: Authorization\nformat: \"Bearer {secret}\"')"
> ```
> (Run these yourself; the token stays in your shell, never in this chat.)

### Static file fallback (only if no vault)
> `sudo avp secret add ACME_API_KEY` (prompts, no echo), then the binding lives in the config — this is the one path that does touch config.

## 4. Multi-host warning (do not skip)

If the credential needs >1 host (common for download/CDN-backed APIs), a single note can't do it. Recommend the **file source** with a host list, OR one secret per host (same value duplicated). Never silently emit a note that only covers one of several required hosts — the others will fail (401 / unauthenticated).

## 5. Verify (user runs)

- `avp doctor` — flags no-annotation/invalid-annotation secrets and the annotation-trust advisory.
- Confirm the placeholder: in notes/both mode AVP derives it; the consuming app must fetch/derive it, not hardcode.
- Reminder: a secret with **no** annotation is never injected (fail-closed) — if it "doesn't work," check the note parsed.

## 6. Record nothing sensitive

Do not echo the token, do not store it, do not commit it. The deliverable is the *instructions*, not the secret.
