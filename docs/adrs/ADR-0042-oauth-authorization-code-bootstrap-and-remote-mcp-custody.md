---
status: accepted
date: 2026-07-30
decided: 2026-07-30
relates_to: ADR-0040 (mcp broker — the gap this closes), ADR-0017 (oauth2_refresh runtime + write-back), ADR-0030 (client-credentials + github_app), ADR-0035 (pinned token egress), ADR-0029 (stored placeholders), ADR-0031 (response-echo scrubbing), ADR-0024 (notes host allowlist), ADR-0026 (tls-termination scoping)
priority: P2
references:
  - MCP Authorization spec 2026-07-28 — remote HTTP servers use OAuth 2.1 auth-code + PKCE; server is an OAuth 2.1 resource server; RFC 9728 PRM discovery + WWW-Authenticate 401; RFC 8707 resource indicators MUST; stdio servers SHOULD NOT follow this spec and retrieve credentials from the environment; token passthrough forbidden; DCR deprecated in favour of Client ID Metadata Documents
  - MCP Security Best Practices 2026-07-28 — token-passthrough anti-pattern; audience validation
  - RFC 8252 §7.3/§8 — OAuth 2.0 for native apps (loopback redirect, external user-agent)
  - RFC 7636 — PKCE (S256)
  - RFC 8628 — OAuth 2.0 device authorization grant
  - RFC 8707 — resource indicators (token audience binding)
  - RFC 9728 — OAuth 2.0 protected resource metadata
  - RFC 9207 — OAuth 2.0 authorization server issuer identification (mix-up defence)
  - RFC 7591 — dynamic client registration (deprecated for MCP as of 2026-07-28)
  - RFC 6749 §4.1/§6, RFC 6750 — auth-code grant, refresh grant, bearer usage
  - OWASP MCP Security Cheat Sheet — never store OAuth tokens in plaintext
  - Claude Code MCP docs — `claude mcp add --transport http`, `--client-id/--client-secret/--callback-port`, `headersHelper`
  - Codex CLI MCP docs — `codex mcp login`, `mcp_oauth_credentials_store` (keyring), `mcp_oauth_callback_port`
  - Security-status-quo evidence (see References §): Anthropic connectors doc [A1], Claude Code MCP docs [A2], Mitiga plaintext-token/MitM disclosure [R1], Trail of Bits world-readable MCP config [R2], OWASP MCP Security Cheat Sheet [S1] — all verified resolving 2026-07-30
---

# ADR-0042: Interactive-OAuth bootstrap and remote-MCP token custody (`avp oauth login`)

## Context

ADR-0040 shipped `avp mcp install`: it brokers a stdio MCP server's upstream credential
when that credential is either static or an OAuth token **already in the vault**. It
explicitly deferred the one interactive leg — minting the *first* refresh token via a
human browser consent (also deferred by ADR-0017 §1). This ADR closes that gap and states
what "full OAuth support for MCP" does and does not mean.

**The credential this reaches (verified against the current ecosystem).** An inventory of
the ~20 most-popular MCP servers: **11 gate their first upstream credential behind an
interactive OAuth 2.1 authorization-code + PKCE browser consent** — GitHub, Notion, Slack,
Sentry, Stripe, Linear, Atlassian, Google Workspace, Cloudflare, Supabase, Figma. Ten of
the eleven still expose a static-token side door (PAT / restricted key) for headless use —
which is exactly the seam ADR-0040 already fills. **Figma is the lone hold-out: OAuth-only,
no token fallback, headless blocked.** It is the concrete server AVP cannot serve today.
The remaining nine of the top twenty need no brokering (seven hold no upstream secret; one
is a DB connection string; one is a pure API key ADR-0040 already covers). The ecosystem
trend is unambiguous for consumer SaaS servers — remote Streamable-HTTP + hosted OAuth 2.1 —
while local dev-tool servers stay stdio + env key (an audit of ~7,000 public servers in 2026
found 41% require no auth, 53% of authenticated ones use static keys, only ~8.5% OAuth: the
migration is early but directional).

**What the standard now says (2026-07-28 revision — newer than the 2025-06-18 revision
ADR-0040 cited).** For a client authenticating to a **remote** HTTP MCP server: OAuth 2.1
authorization-code + PKCE is mandatory; the MCP server is an **OAuth 2.1 resource server**
(not an authorization server); the client discovers the authorization server via **RFC 9728
Protected Resource Metadata** advertised in a `401 WWW-Authenticate` challenge (well-known
fallback per SEP-985); the client **MUST** bind every token to the target server with an
**RFC 8707 `resource`** indicator; **token passthrough is forbidden** (a server MUST NOT
accept or forward a token not issued to it — the confused-deputy defence); and **stdio
servers SHOULD NOT** follow the OAuth flow and instead **"retrieve credentials from the
environment."** Notably, **RFC 7591 Dynamic Client Registration is now deprecated** (in
favour of Client ID Metadata Documents, which have near-zero provider support today), and
major providers never implemented DCR — so **pre-registered client credentials are the
pragmatic reality**, not a fallback.

**The status quo AVP displaces (verified 2026-07).** The surface splits three ways, and only
one is AVP's to fix:

- **Hosted web clients (claude.ai / Claude Desktop remote connectors)** run the connector and
  hold the OAuth token **server-side in the vendor's cloud, not on the user's device**
  ("Custom connectors connect to your MCP server from Anthropic's cloud, not from your local
  device" [A1]). AVP is not in that path and does not claim to be.
- **Local CLI clients (Claude Code)** are the wedge. The vendor docs say MCP tokens go to the
  OS keychain / a credentials file, "not in your config" [A2] — but independent research found
  the MCP **bearer/refresh tokens sitting in plaintext in `~/.claude.json`**, the same file that
  carries endpoint routing and trust flags [R1], and the vendor classified the report
  **out-of-scope / "by design" and declined to patch** (disclosed 2026-04-10, out-of-scope
  2026-04-12) [R1]. So for a server added directly to a local CLI, a live refresh token most
  likely rests in cleartext on disk, indefinitely, by vendor policy.
- **Local stdio servers** frequently hold a long-lived API key in a **world-readable** config
  (`claude_desktop_config.json` at `-rw-r--r--`, plaintext keys [R2]) — the ADR-0040 case.

Against all three, the standard is explicit: OWASP's MCP guidance says *"Never store OAuth
tokens in plaintext in MCP config files or application settings"* [S1] and the MCP spec itself
requires refresh-token confidentiality. AVP moves the durable refresh token off disk into the
vault and leases only short-lived access tokens — precisely the plaintext-token leak the
vendor-of-record has declined to close for the local client.

### The gap, from first principles

"Full OAuth support" decomposes into three legs, not one injector:

1. **Acquisition** — obtain the first refresh (or access) token. **Interactive by nature**
   for authorization-code: a human must consent. This is the missing leg.
2. **Custody** — where the durable refresh token lives. Must be the vault, never a config
   or cache file.
3. **Runtime** — mint a short-lived access token per request and inject it. **Already
   shipped**: `oauth2_refresh` (ADR-0017), with refresh-token rotation write-back (§8).

So the work is **acquisition + custody, with no new runtime *injector* crypto** — the
interactive consent, and landing its product in the vault where the existing injector takes
over. The bootstrap CLI itself adds only standard-library primitives: PKCE `code_verifier`/
`code_challenge` and `state` generation, a loopback listener, and a device-grant poller.

## Decision

Ship **`avp oauth login`** — a one-command interactive bootstrap that mints the first token
and writes it to the vault — plus a **device-grant fallback** for headless hosts and a
**dynamic-header custody path** for remote MCP servers. No new injector type.

### 0. Scope and non-goals

- **In (v1):** authorization-code + PKCE loopback bootstrap (`avp oauth login`) landing a
  refresh token in the vault for the existing `oauth2_refresh` runtime, plus the RFC 8628
  device-grant fallback (**Leg 1 + Leg 2**). Flow selection is **auto-detected** — a reachable
  local browser uses loopback, a headless host uses device grant — with `--loopback` / `--device`
  overrides.
- **Deferred to v2:** the `headersHelper` remote-MCP custody path (**Leg 3**, §3 below). Reason
  (decided 2026-07-30): Leg 1 + Leg 2 are self-contained and reuse shipped code, whereas Leg 3
  adds a per-client hook to maintain across Claude Code / Codex upgrades and carries the
  mid-session-expiry and public-vs-confidential-client edges — narrower value (it swaps a
  plaintext token file for vault custody, but the live access token still transits the client).
- **Non-goals:** being the injection point for a well-behaved remote client→server leg where
  the client already stores tokens in an OS keychain (nothing to improve); DPoP / RFC 9449
  sender-constraining (future ADR); Cursor / Claude Desktop (inherit ADR-0040's deferral);
  DB / non-HTTP wire protocols.

### 1. Leg 1 — `avp oauth login <binding>`: loopback authorization-code + PKCE bootstrap

A local, one-time consent that writes the refresh token straight to the vault.

1. Generate a PKCE `code_verifier` + `code_challenge` (**S256 only — the `plain` method is
   rejected**, RFC 7636) and a random `state`.
2. Bind an **ephemeral loopback listener** on `http://127.0.0.1:<os-assigned-port>/callback`
   (RFC 8252 §7.3 — plain HTTP is permitted because the request never leaves the host; the
   authorization server must accept any port on a registered loopback redirect).
3. Open the **system browser** to the provider's `authorization_endpoint` (external
   user-agent per RFC 8252 §8.1 — never an embedded webview) with `code_challenge`, `state`,
   the exact `redirect_uri`, requested `scopes`, and — when a target MCP resource is known —
   the **RFC 8707 `resource`** indicator.
4. The human authenticates and consents in their real browser (existing sessions / passkeys
   apply). The provider redirects to the loopback callback.
5. **Verify `state`** (CSRF) and **exact redirect-URI match**; exchange `code` + `code_verifier`
   at the `token_endpoint`; validate the issuer (`iss`, RFC 9207) against the expected
   authorization server. Shut the listener down immediately.
6. **Write the refresh token directly to the vault.** The *first* mint uses the
   **create/populate path** (the `avp binding new` secret-creation route), **not** the rotation
   `update()` — first-mint is a create, not a rotate, which decouples the bootstrap from the
   known refresh-token half-apply edge on `update()`. Subsequent rotation stays on the existing
   hardened ADR-0017 §8 `SecretsBackend.update` path. **The token value is never printed, logged,
   or placed in client config** — the command's only stdout is a success line naming the vault
   secret it populated.

From that point the **shipped `oauth2_refresh` injector runs unchanged**: it mints
short-lived access tokens at request time, injects them on the header path, and rotates the
refresh token with write-back. `avp doctor --probe-oauth` (ADR-0017 §10) verifies health.

### 2. Leg 2 — device-authorization-grant fallback (RFC 8628) for headless hosts

The loopback flow assumes the browser and the listener share a host. AVP's own fleet — the
mainframe and the SecOps VPS — is reached over SSH with no local browser, where a loopback
redirect is unreachable from the operator's browser. There, `avp oauth login` uses the
**device grant**: POST to the `device_authorization_endpoint`, print the `verification_uri`
and `user_code`, and poll the token endpoint (honouring `interval` / `slow_down`) while the
human opens the URL and enters the code **on their phone or laptop**. Same vault write-back
on success. **Selection is automatic** (device grant when no local browser / display is
detected) with `--device` / `--loopback` overrides and `--callback-port` for a firewalled
loopback. **Coverage is bounded honestly:** the device profile is gated *per client* at the
authorization server — even providers that support RFC 8628 (GitHub, some Google client types)
may not authorize an arbitrary pre-registered `client_id` for it, and device codes expire
(~15 min) while the CLI polls. Providers with no device endpoint (or no device authorization
for our client) fail closed with a clear message; the alternatives — loopback over an SSH port
forward, or acquire-on-laptop-then-vault-the-refresh-token — are documented, and device grant
is preferred over them because it decouples the consent device from the tool host cleanly.

### 3. Leg 3 (v2 — deferred) — remote-MCP token custody, not interception

> Deferred to v2 per §0 (decided 2026-07-30). The design is recorded here so v2 starts from a
> settled shape; nothing in this section ships in v1.

For a **remote** OAuth MCP server the client→server leg is the client's job, and the spec
forbids a middlebox relaying tokens (token passthrough). AVP's correct role is **custodian,
not interceptor**: hold the refresh token in the vault and hand the client a **fresh,
short-lived bearer per connection** through the client's own dynamic-header hook.

- **Claude Code:** `avp mcp headers <server>` is registered as the server's **`headersHelper`**
  (a command Claude Code runs fresh on each connection, ≤10 s, whose JSON output is merged as
  request headers). It mints an access token from the vaulted refresh token and returns it.
  **Honest bound:** the short-lived access token still transits the client process (the client
  must put it on the wire) — what changes is that **no token is persisted to disk** and the
  **durable refresh token never leaves the vault**. Refresh cadence is bounded by how often the
  client re-invokes the helper (per-connection, not per-request); the ADR does not claim
  per-request minting.
- **Codex:** native `codex mcp login` with `mcp_oauth_credentials_store = keyring` already
  stores in the OS keychain; AVP **defers** to it there and documents the `headersHelper`-style
  path only where a plaintext store would otherwise be used.
- **Client registration + client type:** the 2026-07-28 spec deprecates DCR verbatim —
  *"Dynamic Client Registration is deprecated. New implementations should use Client ID Metadata
  Documents instead"* — and the major providers never implemented RFC 7591 anyway. AVP uses a
  **pre-registered `client_id` held in the vault**, not DCR. **The loopback and device bootstrap
  flows are PUBLIC clients** (RFC 8252 — an installed CLI cannot keep a secret; PKCE is the proof
  of possession, no `client_secret`). A vaulted `client_secret` is held and used **only** where
  the provider issues a genuinely confidential registration (server-side / client-credentials
  custody), never treated as confidential for the native bootstrap. CIMD is a forward path, gated
  on provider support (near-zero today).
- **Not passthrough:** the custody path **mints a fresh token bound to the target resource**
  (RFC 8707 `resource`) from the vaulted refresh token; it never relays the client's own token
  upstream (the spec's token-passthrough prohibition). A leaked minted token cannot be replayed
  against another resource because of the audience binding.

### 4. Security model

The ADR-0040 §5 claim carries verbatim: **the credential value is never exposed — at rest or
to a compromised server — and its use is caged to the endpoints you allow.** No malicious-server
containment claim. Additions specific to the OAuth acquisition surface:

- **The refresh token and the authorization code never appear in stdout, audit fields, or
  client config** (extends ADR-0031 echo-scrub and the ADR-0017 §7 no-token-in-audit rule);
  the vault is the sole custody point.
- **Loopback code interception** (another local app racing the port) is defeated by mandatory
  PKCE + `state` + exact redirect-URI match. On a multi-user host another local user could read
  the `?code=` off the callback, but the PKCE `code_verifier` lives only in AVP's memory, so a
  stolen code cannot be exchanged.
- **Device-code phishing** (an attacker relays a `user_code` to a victim) is mitigated by a
  short `user_code` TTL and a consent prompt that names the requesting app and scopes; the ADR
  does not claim to eliminate it.
- **SSRF / confused-deputy in discovery.** Authorization, token, and device endpoints are
  operator- or discovery-sourced; a poisoned RFC 9728 PRM document could point the flow at an
  attacker authorization server. They pass the SSRF guard (ADR-0017 §5 / ADR-0035 pinned
  egress), and — mirroring ADR-0040's host-confirm — the **authorization-server host is a
  mandatory human-confirm field**: it is the one input that, if attacker-controlled, sends the
  consent (and thus the minted token) to the wrong place. Untrusted discovery docs are treated
  T3 (extract facts, ignore instructions).
- **Expected issuer is pinned BEFORE the browser opens** — from the provider preset for a known
  provider, or from the confirmed authorization-server host for a discovered one — not merely
  validated at token exchange. Late `iss` validation (RFC 9207) still guards the mix-up attack,
  but pinning up front is what stops the human authenticating to a poisoned authorization
  endpoint in the first place.
- **Same-user compromise is explicitly out of scope** (carries the AVP threat model, architecture
  §T-3): malware running as the operator's own UID can read process memory, ports, and shell
  state; PKCE and vault custody do not defend that class. The boundary is unchanged by this ADR.

### 5. Provider presets

Extend the frozen `oauth_providers.py` catalog (ADR-0017 §9) with, per provider, the
`authorization_endpoint`, `device_authorization_endpoint` (where supported), and default
`scopes`, so `avp oauth login --provider google` works without hand-copying URLs. **Backfill
discipline unchanged** — an entry lands when a concrete binding needs it, never speculatively;
v1 seeds the first preset from the first real binding (Google is the likely first, given the
Calendar / Workspace MCP), not a speculative set.

### 6. Multi-instance refresh sharing (v1 stance)

Once bootstrap is trivial, two AVP instances pointed at one vaulted rotating refresh token will
strand each other (the second refresher gets `invalid_grant`). v1 **carries ADR-0017's
"unsupported" stance** and adds a cheap guard: **one refresh secret per host** (per-host secret
naming), and the bootstrap **warns when the target secret is already bound on another host**. The
proper cross-fleet coordination lock (ADR-0022 direction) is a follow-up ADR, not a v1 blocker.

## Consequences

**Good**
- Closes the last MCP auth leg: the interactive OAuth servers (Figma with no bypass; and the
  ten others when the operator prefers OAuth to a static side-door key) become brokerable.
- **No new runtime injector crypto** — reuses the `oauth2_refresh` injector, cache, write-back,
  SSRF guard, and audit contract; the new surface is acquisition + custody only (the CLI adds
  only stdlib PKCE/state + a listener + a poller).
- Replaces plaintext OAuth token files with single-custody, revocable, short-lived,
  audience-bound injection — the OAuth analogue of AVP's core value.
- Headless-first: the device grant makes AVP usable on the exact SSH-reached fleet AVP runs on.
- Spec-aligned: stdio-from-env and remote-custody-not-passthrough are what the standard asks for.

**Bad**
- Interactivity is irreducible — the first token still needs one human consent per binding
  (minimised to one command, not removed).
- One more outbound surface (authorization / device endpoints) to SSRF-guard and to keep
  provider presets current against.
- The `headersHelper` path depends on a per-client hook that can change across client upgrades
  (same maintenance shape as ADR-0040's two `mcp add` writers).
- Device-code phishing is mitigated, not eliminated.
- **Write dependency (resolved by design):** first-mint routes through the create/populate path,
  not the rotation `update()` (§1 step 6), so the bootstrap does not depend on the known
  refresh-token half-apply edge. The lightweight gate is only "confirm create/populate lands a
  value"; rotation stays on the ADR-0017 §8 hardened path.

**Out of scope**
- DPoP / RFC 9449 sender-constraining (future ADR).
- Being the client→server injection point for keychain-storing clients that already do OAuth
  correctly — nothing to improve, and passthrough interception would fight the spec.
- Cursor / Claude Desktop; DB / non-HTTP wire protocols.

## Open questions

1. **Consent identity binding.** Should `avp oauth login` bind the completed flow to the
   operator identity that started it (beyond `state`), to harden against a relayed device code?
2. **CIMD adoption.** When do enough providers support Client ID Metadata Documents to make it
   worth implementing over pre-registered client credentials?
3. **Mid-session token expiry (Leg 3 / v2).** `headersHelper` runs per-connection; a long-lived
   connection can outlive the minted access token's TTL. Is 401-triggered reconnect the client's
   responsibility, or does the custody path need a shorter connection lease / forced re-invoke?

*Decided during acceptance (2026-07-30):* multi-instance refresh sharing → §6 (documented
one-secret-per-host + bootstrap warning; cross-fleet lock deferred). Write-back atomicity →
sidestepped by routing first-mint through the create path (§1 step 6); rotation atomicity remains
the ADR-0017 §8 concern, unchanged by this ADR.

## References

- MCP Authorization + Security Best Practices, revision 2026-07-28 (resource-server role, RFC
  9728 discovery, RFC 8707 audience, token-passthrough prohibition, stdio-from-env, DCR
  deprecation).
- RFC 8252 (native-app loopback), RFC 7636 (PKCE), RFC 8628 (device grant), RFC 8707 (resource
  indicators), RFC 9728 (PRM), RFC 9207 (`iss`), RFC 7591 (DCR — deprecated), RFC 6749 / 6750.
- Claude Code MCP docs (`headersHelper`, `--client-id/--client-secret/--callback-port`); Codex
  CLI MCP docs (`mcp login`, keyring credential store, callback port).

Security-status-quo evidence (threat-model motivation; all URLs verified to resolve 2026-07-30):
- **[A1]** Anthropic, "Use connectors to extend Claude's capabilities" — connectors run from
  Anthropic's cloud, not the local device.
  https://support.claude.com/en/articles/11176164-use-connectors-to-extend-claude-s-capabilities
- **[A2]** Claude Code MCP docs — documented secure-storage claim (keychain / credentials file,
  not config) and claude.ai connectors surfaced into Claude Code. https://code.claude.com/docs/en/mcp
- **[R1]** Mitiga, "MCP Token Theft in Claude Code: a MitM attack chain" — MCP bearer/refresh
  tokens found in plaintext in `~/.claude.json`; vendor classified out-of-scope / by-design,
  no patch (disclosed 2026-04-10). https://www.mitiga.io/blog/claude-code-mcp-token-theft-mitm
- **[R2]** Trail of Bits, "Insecure credential storage plagues MCP" (2025-04-30) — local stdio
  MCP config (`claude_desktop_config.json`) world-readable (`-rw-r--r--`) holding plaintext API
  keys. https://blog.trailofbits.com/2025/04/30/insecure-credential-storage-plagues-mcp/
- **[S1]** OWASP MCP Security Cheat Sheet — "Never store OAuth tokens in plaintext in MCP config
  files or application settings." https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html

- ADR-0040 (the broker this extends), ADR-0017 (`oauth2_refresh` + write-back), ADR-0030
  (client-credentials + github_app), ADR-0035 (pinned token egress), ADR-0029 (stored
  placeholders), ADR-0031 (echo scrubbing), ADR-0024 (host allowlist), ADR-0026 (TLS scoping).
