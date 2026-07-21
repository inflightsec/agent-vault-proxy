---
status: accepted
date: 2026-07-22
relates_to: ADR-0017 (oauth2_refresh — the token-exchange seam these reuse), ADR-0028 (jwt_bearer — reused to mint the github_app JWT), docs/architecture.md §4.2, docs/ROADMAP.md (Injector types)
references:
  - RFC 6749 §4.4 (OAuth 2.0 client-credentials grant)
  - RFC 7519 / 7515 (JWT / JWS — the GitHub App JWT)
  - GitHub REST API — "Authenticating as a GitHub App installation" (App JWT → installation access token)
---

# ADR-0030: `oauth2_client_credentials` and `github_app` injectors

> **Status: ACCEPTED (2026-07-22).** Implemented + tested end to end. **These were the last two
> reserved injector types — the taxonomy is now complete.**

## Context

Two reserved injector types remained, both *network-exchange* mechanisms that mint a short-lived
credential and inject it — the same shape as `oauth2_refresh`, resolved at `requestheaders` (not the
signing request-hook seam that sigv4/hmac/jwt use):

- **`oauth2_client_credentials`** (RFC 6749 §4.4) — the machine-to-machine OAuth grant: exchange a
  client id + secret for an access token.
- **`github_app`** — authenticate as a GitHub App: mint an App JWT (RS256) from the App's private
  key, then exchange it for a short-lived *installation* access token.

## Decision

Ship both, reusing the OAuth infrastructure and adding one shared piece.

**Shared token transport (`injectors/_token_transport.py`).** A small SSRF-guarded, no-redirect,
retry-on-5xx POST helper with a `TokenResult` and a `transport_open` egress seam the e2e tests patch.
The two new injectors POST through it; the pre-existing `oauth2_refresh` keeps its own equivalent
transport (not refactored — it is verified as-is).

**`oauth2_client_credentials`.** `exchange` builds the `grant_type=client_credentials` body (client
id/secret via `body_post` or HTTP Basic, optional `scope`), POSTs, and parses the RFC 6749 §5.1
success response (Bearer-only, per RFC 6750). The resolver mirrors `oauth2_refresh`'s
fetch → cache → dedup-exchange → `token_exchange` audit → inject → fail-closed flow, minus the refresh
token and its rotation/write-back. v1 takes an explicit `token_url` (provider presets are a later
slice).

**`github_app`.** `exchange` mints the App JWT via the ADR-0028 JWT signer (`iss = app_id`, `iat`
backdated 60 s for clock skew, `exp` ≤ 10 min), POSTs to
`{api_base_url}/app/installations/{installation_id}/access_tokens` with `Authorization: Bearer <jwt>`,
and parses `{"token", "expires_at": <ISO 8601>}` into the cache TTL. Injects
`Authorization: token {token}` by default.

Shared design:

1. **Reuse the token cache.** Both use `DerivedTokenCache` (single-flight, TTL). The cache key folds
   in every input that changes the minted token — the client secret (CC) / the private-key hash +
   app/installation ids (github_app) — so a rotated credential invalidates the cached token
   (Oracle C4 invariant). `KeyInputs`' generic slots are reused, no cache change.
2. **Placeholder = detection trigger** (as with oauth2_refresh); the value is exchanged, not
   substituted. `compose:` rejected.
3. **Audit reuses `token_exchange` + `inject_decision`** — already in the closed event set (ADR-0023),
   **no new event type**. Reused outcomes: `success`, `ssrf_blocked`, `token_endpoint_error:<code>`,
   `token_endpoint_unreachable`, `response_parse_failed`; github_app adds `app_jwt_error:<Err>`
   (a malformed / non-RSA key). Fail-closed: 503 + audited denial. No secret or minted token in any
   audit field.

## Consequences

**Good** — the two most common remaining auth mechanisms (M2M OAuth, GitHub App installations) are
brokered without the client secret / App private key ever entering the agent's process. **The
injector taxonomy is complete**: static header/body, `oauth2_refresh`, `oauth2_client_credentials`,
`github_app`, `sigv4`, `hmac`, `jwt_bearer`, `multi`. The "planned/not-yet-implemented" config guard
now has no live types but is retained for future additions (exercised in tests via a monkeypatched
planned entry).

**Cost / accepted** — some resolver structure is shared by copy between the CC and github_app
resolvers rather than a common base (kept independent to avoid refactoring the just-verified paths).
GitHub is the only App provider modelled; the endpoint shape is GitHub-specific by design.

## Test strategy

- **End to end through the addon** (mocked endpoint via `transport_open`): CC exchanges and injects a
  Bearer token, a cache hit skips the second exchange, a 4xx and a missing secret fail closed with
  503; github_app mints a real RS256 App JWT (generated key), exchanges + injects
  `token <installation>`, caches, and fails closed on exchange error and on a malformed private key
  (no egress attempted). In both, the client secret / private key and the minted token stay out of
  the audit log.
