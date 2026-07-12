---
name: avp-bindings
description: >
  Author agent-vault-proxy (AVP) secret bindings the NOTES-FIRST way — tell the user
  EXACTLY what to add to Bitwarden Secrets Manager notes, Google Secret Manager
  annotations, or a future backend so a new credential is brokered through the proxy,
  with NO config-file edit and NO redeploy. Proposes only; never writes the secret to
  the vault. USE WHEN add avp secret, avp binding, broker or route an API key/token
  through agent-vault-proxy, "what do I put in the bitwarden notes", "add a secret to
  gsm for avp", new backend secret, onboard a credential to the vault proxy. NOT FOR
  editing the AVP config file directly (that's the discouraged file source), running or
  deploying the proxy, or having the assistant store the secret value.
---

# avp-bindings

Helps an agent walk a user through brokering a **new** secret through **agent-vault-proxy (AVP)** — the local proxy that swaps a placeholder for the real secret in-flight, so the calling process never holds the credential. This skill's whole job is to hand the user the **exact thing to paste where**, using the **notes/annotation source** so nothing in AVP's config file changes and nothing is redeployed.

## Two hard rules

1. **Notes-first, config never.** Modern AVP reads bindings from each secret's own metadata — the **BWS `notes` field**, the **GSM `avp-binding` annotation**, and equivalent per-secret metadata on future backends (`binding_source: both` is the default; notes win over file). So a new credential is added entirely in the vault UI/CLI — **no editing `bindings`/`secrets:` in the AVP config, no `ansible`/`avp setup` redeploy.** Only reach for the config (file source) when a note genuinely can't express the binding (see Gotchas).
2. **Propose, never apply.** This skill NEVER writes the secret value or the annotation to the vault for the user. It prints the secret name, tells the user where to put the value, and prints the annotation text to paste. The human applies it. (The assistant handling the raw secret is exactly what AVP exists to prevent.)

## Workflow routing

| Trigger | Workflow |
|---------|----------|
| "add/route/broker a secret through AVP", "what do I put in the notes" | `Workflows/AddSecret.md` |

## Quick reference — the note is tiny

A binding annotation is **flat YAML** with only these keys: `host`, `header`, `format`, `methods`, `paths`. The credential is referenced as the generic token **`{secret}`** (the note has no name key — the secret *is* the value). Bare-host shorthand (`host: api.example.com`) works when the defaults (Authorization / Bearer) fit.

```yaml
# Bearer API on one host — paste into the BWS secret's Notes field
host: api.example.com
header: Authorization
format: "Bearer {secret}"
```

- **Fail-closed:** a secret with *no* annotation is never injected.
- **Backends:** BWS → the secret's **Notes**; GSM → `--annotations=avp-binding=<yaml>`; future backends → their per-secret metadata field.
- Full schema, the auth-pattern catalog (Bearer / token / X-API-Key / Basic / composite), and scoping live in `References/NoteSchema.md`.

## Discover a secret's placeholder (notes/both mode) — and wire it in

In notes/`both` mode AVP **derives** each secret's placeholder from a per-install salt; the operator
never sets it, so a consumer must discover it. The config pins `install_salt_path`, so `avp env`
resolves the daemon's own salt on its own — the command is a flagless one-liner (run on the AVP host):

```bash
sudo /opt/agent-vault-proxy/.venv/bin/avp env --print | grep <SECRET_NAME>
# → export <SECRET_NAME>='avp-PLACEHOLDER-...'
```

**How the skill wires it (the value is a sentinel, NOT a secret — safe for the agent to fetch,
print, and write):**
1. Run the one-liner for `<NAME>` and capture the `avp-PLACEHOLDER-...` value.
2. Then either (a) tell the user the exact line to add, or (b) write it straight into the target
   `.env` / consumer config, e.g. `HF_TOKEN=avp-PLACEHOLDER-...`. Writing a placeholder needs no
   special permission — it is not a credential.
3. The consumer emits that placeholder as its token through the AVP proxy; AVP swaps in the real
   secret on the wire, only for the bound hosts.

Notes:
- The agent runs sandboxed and may lack `sudo` on the AVP host — if the command is denied, hand the
  user the one-liner, then take the value they return and write the `.env` for them.
- Stable per install (changes only if the salt is rotated), so it's a one-time wire-up per secret.
  `avp env` prints every valid secret's line; `grep` for the one you want.
- The salt behind it is an HMAC key: keep it on-box; reading it locally to mint a placeholder is
  exactly its purpose.

## Gotchas

- **Multi-host notes (ADR-0021).** `host` accepts a list (or a `hosts:` alias) — a token spanning several hosts fans out to one binding per host. A multi-host list must set an explicit `format`, may **not** include a curated host (`api.github.com` etc.) or a `*.` wildcard element, and applies one **uniform** `methods`/`paths` scope. For per-host scope, a curated host in the mix, or a machine consumer that needs a **fixed** placeholder (see the salt-derived gotcha below), use the **file source** instead. See `References/NoteSchema.md`.
- **Composite/multi-part auth is file-source-only.** Basic auth assembled from two secrets (`email:token`) needs the config's `compose:` + `inject_template` — a note holds one secret. To stay notes-only, pre-encode the whole credential into a single secret and use `format: "Basic {secret}"`.
- **Placeholder is salt-derived in notes/both mode.** You don't choose the placeholder string; AVP derives it deterministically from a per-install salt + the secret key. A consuming app must therefore *discover* its placeholder from AVP rather than hardcode one. (Hardcoding a placeholder only works with the file source, where the operator sets it.)
- **`both` precedence + the `:file` pin.** With `binding_source: both`, a notes binding wins over a file binding for the same secret, and file-only bindings can be dropped unless pinned `:file`. Don't declare the same secret in both places without understanding which wins.
- **Wildcard hosts need explicit opt-in.** A note cannot widen a credential's blast radius to `*.suffix` unless `allow_wildcard_hosts` is enabled — fail-closed by default. Keep hosts exact.
- **Annotation-write is a trust boundary (ADR-0018).** Whoever can edit a secret's notes/annotation can redirect the credential to a host they control (confused-deputy). Annotation-write must be locked to the same trust tier as value-read; `avp doctor` warns when it isn't. So "anyone can add a binding" is only safe when note-write is gated.
- **Never pre-encode a secret the assistant can see.** For Basic/base64 cases, tell the user to compute the encoding themselves (or use the file-source composite template); don't ask them to paste the raw credential to you to encode.
