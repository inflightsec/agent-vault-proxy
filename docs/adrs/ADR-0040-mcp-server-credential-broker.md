---
status: accepted
date: 2026-07-28
decided: 2026-07-29
relates_to: ADR-0017 (oauth2_refresh), ADR-0027 (sigv4), ADR-0030 (client-credentials + github_app), ADR-0029 (stored placeholders), ADR-0026 (tls-termination-scoping), ADR-0024 (notes-host-allowlist), ADR-0031 (response-echo-scrubbing), ADR-0018 (annotation-write trust boundary)
supersedes_dependency: ADR-0020 (service templates) — no longer a v1 dependency; see Decision §3
priority: P2
references:
  - MCP Authorization spec 2025-06-18 — stdio servers "SHOULD NOT" use OAuth, "retrieve credentials from the environment"; server→upstream credentials undefined, only token-passthrough forbidden
  - MCP Transports spec 2025-06-18 — stdio server is a raw subprocess; env inheritance is implementation-defined
  - Claude Code MCP docs — `claude mcp add --env`, `${VAR}` expansion, `headersHelper` for remote servers
  - Codex CLI 0.142.5 — `codex mcp add --env`, `shell_environment_policy.inherit` (default allowlist), native remote-OAuth (`codex mcp login`)
  - FastMCP / TS+Python SDK `getDefaultEnvironment()` — restricted child-env allowlist
---

# ADR-0040: AVP as an MCP-server credential broker (skill-derived bindings, env-block onboarding)

> **Implemented 2026-07-30.** Landed as `avp mcp install` —
> `cli/mcp.py` (`register_mcp_subparser` + `run_mcp`), wired in `cli/main.py`,
> covered by `tests/test_cli_mcp.py`; full unit suite green. The bundled `avp` skill
> gained the `InstallMcp` workflow (docs-derived binding, mandatory human host-confirm).
> Hardened after a three-lens review + two Oracle passes: Unicode-line-break YAML
> injection closed (Cc/Cf/Zl/Zp reject), host-intent assertion, `shlex`-quoted output,
> `--apply` failure/missing-binary handling, canonical proxy/CA defaults.
>
> **Delta from the plan below:** the §3 step-5 post-install smoke ships as a printed
> `--smoke` command, not an auto-executed fail-closed check. Propose-only install can't
> authenticate before the note is pasted into the vault and the daemon reloads, so an
> automatic request literally can't verify injection at install time — the printed
> command (run once the note is live) is the correct realization. The design sections
> below are preserved as the record of the decision.

## Context

MCP servers are a fast-growing credential-leak surface. A stdio MCP server is
almost always a subprocess that holds a long-lived upstream secret (a GitHub PAT,
a Slack `xoxb-`, a Brave/Firecrawl/Perplexity API key) **in cleartext in the
client config**, and every server the client loads shares a process tree that can
read the others' environment. This is the exact "personal AI is a security
disaster" case (N7) AVP exists to close, applied to the tooling layer.

Three facts were established before deciding.

### 1. The standard hands us the job (and tells us where to inject)

- The MCP **Authorization spec (2025-06-18)** covers exactly one thing: a
  **client authenticating to a remote HTTP MCP server** via OAuth 2.1 + PKCE. It
  says stdio servers **"SHOULD NOT"** follow it and should instead **"retrieve
  credentials from the environment."**
- The spec defines **nothing** about how a server authenticates to its **own
  upstream API**. Its only statement is a prohibition: the server **MUST NOT**
  pass the client's token through (confused-deputy). No injection concept, no
  secret references, no proxying. **That gap is AVP's wedge, not a workaround —
  and, critically, it means there is no standard metadata from which a server's
  upstream host or auth can be auto-discovered** (drives Decision §3).

### 2. `~/.zshrc` is the wrong injection layer, twice over

- Clients `spawn` the server **command directly** — a raw exec, never `zsh -ic`.
  **Claude Desktop is a GUI app (launchd/Finder): it never sees `~/.zshrc`,
  `~/.zprofile`, or `~/.zshenv`** (the same root cause as the well-known "MCP
  can't find my PATH" bug). Claude Code from a terminal only "works" because it
  inherited the shell's already-sourced env; the Dock-launched desktop build does
  not.
- Worse: the reference SDKs (and Codex's `shell_environment_policy`) do **not**
  hand the child the full parent env. They start from a restricted allowlist
  (`HOME, PATH, SHELL, TERM, USER`) and merge the server's `env` block on top.
  `HTTPS_PROXY` and CA-trust vars get **stripped** unless listed explicitly.
- The one portable injection point is the **per-server `env` block**, and both
  target clients expose a CLI that writes it: `claude mcp add --env`,
  `codex mcp add --env`.

### 3. AVP's injector taxonomy already covers almost every MCP auth type

Audit of the top ~25 MCP servers by auth mechanism, against the current injector
set (ADR-0030: *"the taxonomy is now complete"*):

| Auth pattern (MCP servers) | AVP injector | Status |
|---|---|---|
| Static key / Bearer in header (Slack, Brave, Firecrawl, Perplexity, Google Maps, Neon, Exa, Stripe restricted-key, Supabase PAT, GitHub PAT) | `header` / token / X-API-Key | **ships** |
| HTTP Basic (email:token) | `multi` / composite | ships (file-source) |
| AWS SigV4 (AWS API MCP) | `sigv4` | ADR-0027 |
| OAuth2 refresh-token (Google, MS, Atlassian, Slack, Okta, Auth0 estates) | `oauth2_refresh` | ADR-0017 |
| OAuth2 client-credentials (m2m) | `oauth2_client_credentials` | ADR-0030 |
| GitHub App installation token | `github_app` | ADR-0030 |
| **Interactive auth-code + PKCE bootstrap** (mint the *first* refresh token via browser consent) | — | **deferred → v2** (ADR-0017 §1) |
| **DB connection string / non-HTTP wire** (Postgres, MySQL, Mongo) | — | **out of scope** (not HTTPS) |
| No upstream secret (filesystem, fetch, git, memory, time, …) | — | nothing to secure |

**v1 needs no new crypto.** For every static-key server and for every OAuth server
where a refresh token or client-credentials pair already lives in the vault, the
injector exists today. The only missing auth leg is the interactive auth-code+PKCE
consent that mints the first refresh token — an inherently-interactive, one-time,
per-user human action — deferred to v2.

## Decision

Ship **AVP-for-MCP as a skill-derived onboarding feature, scoped to stdio servers
with an injectable credential.** No new injector types, and **no maintained
catalog.**

### 1. Scope (v1) and target class

- **In:** stdio MCP servers whose upstream auth is any injector AVP already ships.
- **Target class (positioning):** the **structurally-static** servers —
  CI / headless / self-hosted / API-key utilities — where a browser OAuth consent
  is impossible, so static keys persist by necessity (this is also AVP's own usage:
  SecOps pipelines, bounty automation, the mainframe). The research shows the
  consumer-desktop ecosystem migrating to hosted OAuth; v1 explicitly does **not**
  target that set — v2 does (§6).
- **Out (this ADR):** interactive auth-code+PKCE bootstrap (v2); DB / non-HTTP wire
  protocols; remote HTTP MCP servers' client→server auth (the MCP OAuth spec's job).

### 2. Clients: Claude Code + Codex, via their native `mcp add` CLIs

v1 supports **Claude Code and Codex** — chosen because both are locally
smoke-testable and both expose `mcp add --env`. **Drive each client's own CLI
rather than hand-writing config files** — the client owns its schema, so drift is
its problem, not ours. Cursor and Claude Desktop are **deferred** (documented
manual path in the interim).

### 3. Onboarding: `avp mcp install <server>` derives the binding via the AVP skill

**No shipped/maintained catalog** (rejected: maintenance treadmill, and the target
long-tail is unbounded). Instead, for an uncataloged server the command invokes the
**AVP skill** to *derive* the binding:

1. Skill inspects the MCP server (package/README/registry) for its **credential
   env var** and **runtime**, and reads the **upstream API's docs** for **host,
   auth header, format**, and a sensible **default method scope**.
2. Skill **proposes** the binding — never applies it (the AVP skill's standing
   rule). The proposal **foregrounds the `host` for a mandatory one-line human
   confirm** (§5 — this is the prompt-injection checkpoint).
3. On confirm, `avp binding new` mints the placeholder + writes the vault note
   (ADR-0029). **The note is the durable artifact** — a second install of the same
   server reads the existing note and re-derives nothing. The "catalog" is thus an
   *emergent, lazily-written* side-effect of use, never hand-maintained.
4. `claude mcp add --env` / `codex mcp add --env` writes the env block (§4).
5. **Post-install smoke check:** make one scoped request through AVP to the bound
   host and confirm injection succeeded (fail-closed + clear diagnostic if not) —
   catches the `NODE_USE_ENV_PROXY` / CA-trust traps at install time, not first use.

A `--host/--env-var/--header/--format/--methods` flag path remains for fully
manual definition (and for scripting), bypassing the skill.

### 4. The env contract (per-runtime) — the real plumbing

Because the child env is an allowlist, every var is listed **explicitly**:

```jsonc
"env": {
  "HTTPS_PROXY": "http://127.0.0.1:<avp-port>",
  "HTTP_PROXY":  "http://127.0.0.1:<avp-port>",
  "NO_PROXY":    "localhost,127.0.0.1",
  "NODE_USE_ENV_PROXY": "1",              // Node/undici bypasses HTTPS_PROXY without this
  "NODE_EXTRA_CA_CERTS": "<avp-ca.pem>",  // Node runtimes
  "REQUESTS_CA_BUNDLE":  "<avp-ca.pem>",  // Python requests
  "SSL_CERT_FILE":       "<avp-ca.pem>",  // Python stdlib / Go / curl
  "<SERVER_TOKEN_ENV>":  "avp-PLACEHOLDER-…"  // ADR-0029 stored placeholder
}
```

`install` resolves the runtime from the server's command and emits only the
cert/bypass vars that runtime needs.

**CA trust is per-server only, never a system trust store.** TLS interception
(ADR-0026) requires the AVP CA to be trusted; we point *only the installed server's*
env at the CA file. Blast radius = the servers you opted in, not the whole box —
installing a MITM-capable CA into system trust is a foothold class AVP's own SecOps
posture rejects. **Cert-pinning servers (or runtimes that ignore the env cert var)
are unsupported and named as such in the coverage docs** — fail-closed, not
pretended.

### 5. Security model — what we claim, and the two hardening rules

**Claim (exact, honest):** *the credential value is never exposed — at rest or to a
compromised server — and its use is caged to the endpoints you allow.* We do **not**
claim malicious-server containment.

Rationale, against a supply-chained server running inside the proxied process:

- **Cannot read the key value.** A request to an attacker-controlled host gets **no
  injection** (host allowlist, ADR-0024); a header-reflecting endpoint on the bound
  host cannot leak it back (echo-scrub, ADR-0031). The value stays hidden even from
  hostile in-process code.
- **Can abuse the key's *use*** (ambient authority): it can call the legit API with
  the injected credential. This is the residual, shrunk by scope.

Two rules:

- **Scoping.** **Bare-host is allowed and is the default** (zero-friction "broker any
  MCP in one line" — still gets no-secret-at-rest + value-hidden). **Method scoping
  is the recommended default hardening** — stable (methods don't churn like paths)
  and it blocks the worst residual (a `GET`-only binding can't POST/PUT/DELETE:
  can't touch billing, mutate, or plant an exfil webhook). **Path scoping is
  optional and, when used, prefix/glob (`/v1/*`) not exact** — exact paths are
  brittle against upstream API growth (Radek, 2026-07-29). No mandatory path scope.
- **Untrusted-docs / prompt-injection defense.** The skill reads
  attacker-influenceable text (MCP README, upstream docs) to decide where a real
  credential is injected — a confused-deputy chain (cf. ADR-0018: annotation-write
  is a trust boundary). The skill treats docs as **T3 untrusted**: it extracts
  *facts*, ignores *instructions*, and the **`host` field is a mandatory human
  confirm** because it is the one field that, if attacker-controlled, leaks the key.

### 6. Remote HTTP MCP servers — v2, via `headersHelper`

AVP is not the injection point for the client→server leg (OAuth/headers own it).
But Claude Code exposes a **`headersHelper`** hook (dynamic header command, built for
SSO/short-lived tokens) and Codex has native remote-OAuth. v2 implements
`avp mcp headers <server>` as that helper to inject short-lived headers, and takes on
the interactive auth-code+PKCE bootstrap for migrating servers.

## Consequences

**Good**
- Covers ~10-12 of the most popular MCP servers **today** with existing injectors,
  no new crypto.
- **No maintained catalog** — the AVP skill derives bindings from docs and the vault
  note persists them; the credentialing surface writes itself, lazily, by use.
- Standard-sanctioned: the MCP spec points stdio servers at env-supplied credentials
  and leaves server→upstream secrets undefined.
- Honest, demoable claim: *value never exposed, even to a compromised server; use
  caged by scope.*
- Post-install smoke check turns the silent-failure traps into a loud install-time
  error (matches the automated-smoke-test preference).
- The env contract is reusable for any sandboxed subprocess, not just MCP.

**Bad**
- TLS interception needs the AVP CA trusted per runtime — a cert-pinning server
  breaks (named unsupported).
- Skill-derived bindings are non-deterministic on first derivation — mitigated by the
  mandatory host-confirm, the T3 untrusted-docs posture, the note persisting after
  first use, and the post-install smoke check.
- Ambient-*use* residual (a compromised server calling the legit API) is not
  eliminated — mitigated by recommended method scoping.
- Placeholders remain visible in client config (non-secret sentinel, ADR-0029, but
  *looks* like a secret to a reviewer — needs a doc note).
- Two client config writers (via their CLIs) to keep working across client upgrades.

**Out of scope**
- Interactive auth-code+PKCE bootstrap → v2 (§6).
- DB connection strings / non-HTTP wire protocols — wrong transport; separate product.
- Cursor / Claude Desktop clients — deferred (manual path documented).

## Open questions

1. **v2 — proxy or human for interactive OAuth?** For hosted OAuth MCP servers,
   should AVP mediate the browser consent to obtain the first refresh token, or is
   that permanently the human's job (run once, vault the refresh token, AVP takes
   over)? The single biggest v2 scope fork.
2. **Skill derivation reliability.** How accurately can the skill derive
   header/format across diverse API docs? Does the header/format (not just host)
   need a verification step beyond the smoke check — e.g. show the derived
   `Authorization: Bearer {secret}` for confirm too, or is the smoke check
   (does injection actually authenticate?) sufficient proof?
3. **Placeholder-in-config optics.** A reviewer sees `avp-PLACEHOLDER-…` in a client
   config and can't distinguish it from a leaked secret without knowing AVP. Doc
   note, or a visible marker convention?

## References

- ADR-0017 — `oauth2_refresh` (refresh-token grant, provider catalog; PKCE/auth-code deferred §1).
- ADR-0027 — SigV4 injector. · ADR-0030 — client-credentials + github_app; "taxonomy complete."
- ADR-0029 — stored placeholders (the sentinel written into the MCP `env` block).
- ADR-0026 — TLS-termination scoping (the CA the runtimes must trust, per-server).
- ADR-0024 — notes host allowlist (blocks value theft via attacker host).
- ADR-0031 — response-echo scrubbing (blocks value theft via reflecting endpoint).
- ADR-0018 — annotation-write is a trust boundary (the derivation-from-untrusted-docs risk).
- ADR-0020 — service templates: the pattern the skill-derivation *replaces* for MCP; no longer a v1 dependency.
- MCP Authorization / Transports specs 2025-06-18 · Claude Code MCP docs (`env`, `headersHelper`) · Codex CLI `mcp add --env`.
